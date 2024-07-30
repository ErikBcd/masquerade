use quiche;
use quiche::h3::NameValue;

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedSender};

use log::*;

use crate::common::*;

use crate::client::*;

async fn handle_socks5_stream(
    mut stream: TcpStream,
    http3_sender: UnboundedSender<ToSend>,
    connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
    connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
) {
    let peer_addr = stream.peer_addr().unwrap();
    let hs_req = match socks5_proto::HandshakeRequest::read_from(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            error!("socks5 handshake request read failed: {}", e);
            return;
        }
    };

    if hs_req
        .methods
        .contains(&socks5_proto::HandshakeMethod::None)
    {
        let hs_resp = socks5_proto::HandshakeResponse::new(socks5_proto::HandshakeMethod::None);
        match hs_resp.write_to(&mut stream).await {
            Ok(_) => {}
            Err(e) => {
                error!("socks5 handshake write response failed: {}", e);
                return;
            }
        };
    } else {
        error!("No available handshake method provided by client, currently only support no auth");
        let hs_resp =
            socks5_proto::HandshakeResponse::new(socks5_proto::HandshakeMethod::Unacceptable);
        match hs_resp.write_to(&mut stream).await {
            Ok(_) => {}
            Err(e) => {
                error!("socks5 handshake write response failed: {}", e);
                return;
            }
        };
        let _ = stream.shutdown().await;
        return;
    }

    let req = match socks5_proto::Request::read_from(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            error!("socks5 request parse failed: {}", e);
            let resp = socks5_proto::Response::new(
                socks5_proto::Reply::GeneralFailure,
                socks5_proto::Address::unspecified(),
            );
            match resp.write_to(&mut stream).await {
                Ok(_) => {}
                Err(e) => {
                    error!("socks5 write response failed: {}", e);
                    return;
                }
            };
            let _ = stream.shutdown().await;
            return;
        }
    };

    match req.command {
        socks5_proto::Command::Connect => {
            let path = socks5_addr_to_string(&req.address);
            let headers = vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", path.as_bytes()),
                quiche::h3::Header::new(b":authorization", b"dummy-authorization"),
            ];
            info!("sending HTTP3 request {:?}", headers);
            let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
            let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();
            http3_sender
                .send(ToSend {
                    content: Content::Request {
                        headers,
                        stream_id_sender,
                    },
                    finished: false,
                    stream_id: u64::MAX,
                })
                .unwrap_or_else(|e| error!("sending http3 request failed: {:?}", e));

            let stream_id = stream_id_receiver
                .recv()
                .await
                .expect("stream_id receiver error");
            {
                let mut connect_streams = connect_streams.lock().unwrap();
                connect_streams.insert(stream_id, response_sender);
                // TODO: potential race condition: the response could be received before connect_streams is even inserted and get dropped
            }

            let response = response_receiver
                .recv()
                .await
                .expect("http3 response receiver error");
            let mut succeeded = false;
            if let Content::Headers { headers } = response {
                info!("Got response {:?}", hdrs_to_strings(&headers));
                let mut status = None;
                for hdr in headers {
                    match hdr.name() {
                        b":status" => status = Some(hdr.value().to_owned()),
                        _ => (),
                    }
                }
                if let Some(status) = status {
                    if let Ok(status_str) = std::str::from_utf8(&status) {
                        if let Ok(status_code) = status_str.parse::<i32>() {
                            if status_code >= 200 && status_code < 300 {
                                info!("connection established, sending OK socks response");
                                let response = socks5_proto::Response::new(
                                    socks5_proto::Reply::Succeeded,
                                    socks5_proto::Address::unspecified(),
                                );
                                succeeded = true;
                                match response.write_to(&mut stream).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("socks5 response write error: {}", e);
                                        let _ = stream.shutdown().await;
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                error!("received others when expecting headers for connect");
            }
            if !succeeded {
                error!("http3 CONNECT failed");
                let response = socks5_proto::Response::new(
                    socks5_proto::Reply::GeneralFailure,
                    socks5_proto::Address::unspecified(),
                );
                let _ = response.write_to(&mut stream).await;
                let _ = stream.shutdown().await;
                return;
            }

            let (mut read_half, mut write_half) = stream.into_split();
            let http3_sender_clone = http3_sender.clone();
            let read_task = tokio::spawn(async move {
                let mut buf = [0; 65535];
                loop {
                    let read = match read_half.read(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error reading from TCP {}: {}", peer_addr, e);
                            break;
                        }
                    };
                    if read == 0 {
                        debug!("TCP connection closed from {}", peer_addr);
                        // TODO: Do we have to tell the server that the TCP connection is closed?
                        break;
                    }
                    debug!(
                        "read {} bytes from TCP from {} for stream {}",
                        read, peer_addr, stream_id
                    );
                    http3_sender_clone
                        .send(ToSend {
                            stream_id: stream_id,
                            content: Content::Data {
                                data: buf[..read].to_vec(),
                            },
                            finished: false,
                        })
                        .unwrap_or_else(|e| error!("sending bytes from TCP failed: {:?}", e));
                }
            });
            let write_task = tokio::spawn(async move {
                loop {
                    let data = match response_receiver.recv().await {
                        Some(v) => v,
                        None => {
                            debug!("TCP receiver channel closed for stream {}", stream_id);
                            break;
                        }
                    };
                    match data {
                        Content::Request { .. } => unreachable!(),
                        Content::Headers { .. } => unreachable!(),
                        Content::Data { data } => {
                            let mut pos = 0;
                            while pos < data.len() {
                                let bytes_written = match write_half.write(&data[pos..]).await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!(
                                            "Error writing to TCP {} on stream id {}: {}",
                                            peer_addr, stream_id, e
                                        );
                                        return;
                                    }
                                };
                                pos += bytes_written;
                            }
                            debug!(
                                "written {} bytes from TCP to {} for stream {}",
                                data.len(),
                                peer_addr,
                                stream_id
                            );
                        }
                        Content::Datagram { .. } => unreachable!(),
                        Content::Finished => {
                            debug!("shutting down stream in write task");
                            break;
                        }
                    };
                }
            });
            match tokio::join!(read_task, write_task) {
                (Err(e), Err(e2)) => {
                    debug!("Two errors occured when joining r/w tasks: {:?} | {:?}", e, e2);
                },
                (Err(e), _) => {
                    debug!("An error occured when joining r/w tasks: {:?}", e);
                },
                (_, Err(e)) => {
                    debug!("An error occured when joining r/w tasks: {:?}", e);
                },
                (_, _) => {}
            };


            {
                // TODO: check whether this can actually trigger
                debug!("stream {} terminated", stream_id);
                let mut connect_streams = connect_streams.lock().unwrap();
                connect_streams.remove(&stream_id);
            }
        }
        socks5_proto::Command::Associate => {
            // NOTE: Currently do not support fragmentation
            let mut local_addr = stream.local_addr().unwrap(); // bind on the same ip address of the tcp connection
            local_addr.set_port(0); // let the OS assign a port
            if let Ok(bind_socket) = UdpSocket::bind(local_addr).await {
                if let Ok(local_addr) = bind_socket.local_addr() {
                    let response = socks5_proto::Response::new(
                        socks5_proto::Reply::Succeeded,
                        socks5_proto::Address::SocketAddress(local_addr),
                    );
                    match response.write_to(&mut stream).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("socks5 response write error: {}", e);
                            let _ = stream.shutdown().await;
                            return;
                        }
                    }
                    let bind_socket = Arc::new(bind_socket);
                    let http3_sender_clone = http3_sender.clone();
                    let stream_ids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
                    let stream_ids_clone = stream_ids.clone();
                    let connect_streams_clone = connect_streams.clone();
                    let connect_sockets_clone = connect_sockets.clone();

                    let listen_task = tokio::spawn(async move {
                        let mut buf = [0; 65535];
                        let mut dest_to_flow: HashMap<socks5_proto::Address, u64> = HashMap::new();
                        loop {
                            match bind_socket.recv_from(&mut buf).await {
                                Ok((read, recv_addr)) => {
                                    debug!("read {} bytes from UDP from {}", read, recv_addr);
                                    let socks5_udp_header =
                                        match socks5_proto::UdpHeader::read_from(&mut &buf[..read])
                                            .await
                                        {
                                            Ok(v) => v,
                                            Err(e) => {
                                                error!("udp socks5 socket received packet cannot be parsed: {}", e);
                                                continue;
                                            }
                                        };
                                    let payload = &buf[socks5_udp_header.serialized_len()..read];
                                    let flow_id = match dest_to_flow.get(&socks5_udp_header.address)
                                    {
                                        Some(flow_id) => *flow_id,
                                        None => {
                                            // New destination address to proxy, set up connect-udp flow
                                            let path = socks5_addr_to_connect_udp_path(
                                                &socks5_udp_header.address,
                                            );
                                            let headers = vec![
                                                quiche::h3::Header::new(b":method", b"CONNECT"),
                                                quiche::h3::Header::new(b":path", path.as_bytes()),
                                                quiche::h3::Header::new(
                                                    b":protocol",
                                                    b"connect-udp",
                                                ),
                                                quiche::h3::Header::new(
                                                    b":scheme",
                                                    b"dummy-scheme",
                                                ),
                                                quiche::h3::Header::new(
                                                    b":authority",
                                                    b"dummy-authority",
                                                ),
                                                quiche::h3::Header::new(
                                                    b":authorization",
                                                    b"dummy-authorization",
                                                ),
                                            ];
                                            debug!("sending HTTP3 request {:?}", headers);
                                            let (stream_id_sender, mut stream_id_receiver) =
                                                mpsc::channel(1);
                                            let (
                                                stream_response_sender,
                                                mut stream_response_receiver,
                                            ) = mpsc::unbounded_channel::<Content>();
                                            let (flow_response_sender, mut flow_response_receiver) =
                                                mpsc::unbounded_channel::<Content>();
                                            http3_sender_clone
                                                .send(ToSend {
                                                    content: Content::Request {
                                                        headers,
                                                        stream_id_sender,
                                                    },
                                                    finished: false,
                                                    stream_id: u64::MAX,
                                                })
                                                .unwrap_or_else(|err| {
                                                    error!("Error: {}", err);
                                                });
                                            let stream_id = stream_id_receiver
                                                .recv()
                                                .await
                                                .expect("stream_id receiver error");
                                            let flow_id = stream_id / 4;
                                            {
                                                let mut connect_streams =
                                                    connect_streams.lock().unwrap();
                                                connect_streams
                                                    .insert(stream_id, stream_response_sender);
                                                // TODO: potential race condition: the response could be received before connect_streams is even inserted and get dropped
                                            }
                                            {
                                                let mut connect_sockets =
                                                    connect_sockets.lock().unwrap();
                                                connect_sockets
                                                    .insert(flow_id, flow_response_sender);
                                            }
                                            {
                                                let mut stream_ids =
                                                    stream_ids_clone.lock().unwrap();
                                                stream_ids.push(stream_id);
                                            }
                                            let mut succeeded = false;
                                            let response = stream_response_receiver
                                                .recv()
                                                .await
                                                .expect("http3 response receiver error");
                                            if let Content::Headers { headers } = response {
                                                debug!(
                                                    "Got response {:?}",
                                                    hdrs_to_strings(&headers)
                                                );
                                                let mut status = None;
                                                for hdr in headers {
                                                    match hdr.name() {
                                                        b":status" => {
                                                            status = Some(hdr.value().to_owned())
                                                        }
                                                        _ => (),
                                                    }
                                                }
                                                if let Some(status) = status {
                                                    if let Ok(status_str) =
                                                        std::str::from_utf8(&status)
                                                    {
                                                        if let Ok(status_code) =
                                                            status_str.parse::<i32>()
                                                        {
                                                            if status_code >= 200
                                                                && status_code < 300
                                                            {
                                                                succeeded = true;
                                                                debug!("UDP CONNECT connection established for flow {}", flow_id);
                                                                dest_to_flow.insert(
                                                                    socks5_udp_header
                                                                        .address
                                                                        .clone(),
                                                                    flow_id,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                error!("received others when expecting headers for connect");
                                            }
                                            if !succeeded {
                                                error!("http3 CONNECT UDP failed");
                                                continue;
                                            }
                                            let bind_socket_clone = bind_socket.clone();
                                            let dest_addr = socks5_udp_header.address.clone();
                                            let _write_task = tokio::spawn(async move {
                                                loop {
                                                    let data = match flow_response_receiver
                                                        .recv()
                                                        .await
                                                    {
                                                        Some(v) => v,
                                                        None => {
                                                            debug!("receiver channel closed for flow {}", flow_id);
                                                            break;
                                                        }
                                                    };
                                                    match data {
                                                        Content::Request { .. } => unreachable!(),
                                                        Content::Headers { .. } => unreachable!(),
                                                        Content::Data { .. } => unreachable!(),
                                                        Content::Datagram { payload } => {
                                                            trace!(
                                                                "raw UDP datagram is {} bytes long",
                                                                payload.len()
                                                            );
                                                            let (context_id, payload) =
                                                                decode_var_int(&payload);
                                                            trace!("UDP datagram payload without context id is {} bytes long", payload.len());
                                                            assert_eq!(context_id, 0, "received UDP Proxying Datagram with non-zero Context ID");

                                                            let udp_header =
                                                                socks5_proto::UdpHeader::new(
                                                                    0,
                                                                    dest_addr.clone(),
                                                                );
                                                            trace!("appending SOCKS5 UDP request header of length {}", udp_header.serialized_len());
                                                            let mut serialized_udp_header =
                                                                Vec::new();
                                                            udp_header.write_to_buf(
                                                                &mut serialized_udp_header,
                                                            );
                                                            trace!("SOCKS5 UDP request header: {:02x?}", serialized_udp_header);
                                                            let payload =
                                                                [&serialized_udp_header, payload]
                                                                    .concat();
                                                            trace!("start sending on UDP");
                                                            let bytes_written =
                                                                match bind_socket_clone
                                                                    .send_to(&payload, recv_addr)
                                                                    .await
                                                                {
                                                                    Ok(v) => v,
                                                                    Err(e) => {
                                                                        error!("Error writing to UDP {} on flow id {}: {}", recv_addr, flow_id, e);
                                                                        continue;
                                                                    }
                                                                };
                                                            if bytes_written < payload.len() {
                                                                debug!("Partially sent {} bytes of UDP packet of length {}", bytes_written, payload.len());
                                                            }
                                                            debug!("written {} bytes from UDP to {} for flow {}", payload.len(), recv_addr, flow_id);
                                                        }
                                                        Content::Finished => {
                                                            debug!("shutting down stream in write task");
                                                            break;
                                                        }
                                                    };
                                                }
                                            });
                                            flow_id
                                        }
                                    };
                                    debug!(
                                        "sending {} bytes of data to flow {}",
                                        payload.len(),
                                        flow_id
                                    );
                                    let data = wrap_udp_connect_payload(0, payload);
                                    http3_sender_clone
                                        .send(ToSend {
                                            stream_id: flow_id,
                                            content: Content::Datagram { payload: data },
                                            finished: false,
                                        })
                                        .unwrap_or_else(|e| {
                                            error!(
                                                "sending data to flow {} failed: {:?}",
                                                flow_id, e
                                            )
                                        });
                                }
                                Err(e) => {
                                    error!("udp socks5 socket recv failed: {}", e);
                                    break;
                                }
                            }
                        }
                    });

                    let http3_sender_clone_2 = http3_sender.clone();
                    let terminate_task = tokio::spawn(async move {
                        let mut buf = [0; 4];
                        match stream.read(&mut buf).await {
                            Ok(n) => {
                                if n > 0 {
                                    unreachable!()
                                }
                            }
                            Err(e) => {
                                error!("udp associate control stream read error: {}", e);
                            }
                        }
                        debug!(
                            "Socks5 TCP connection on {} associated with UDP sockets terminated",
                            local_addr
                        );
                        {
                            let stream_ids = stream_ids.lock().unwrap();
                            let mut connect_streams = connect_streams_clone.lock().unwrap();
                            let mut connect_sockets = connect_sockets_clone.lock().unwrap();
                            listen_task.abort();
                            for stream_id in stream_ids.iter() {
                                let stream_id = *stream_id;
                                let flow_id = stream_id / 4;
                                debug!("terminating stream {} and flow {}", stream_id, flow_id);
                                http3_sender_clone_2
                                    .send(ToSend {
                                        stream_id,
                                        content: Content::Finished,
                                        finished: true,
                                    })
                                    .unwrap_or_else(|e| {
                                        error!("Terminating stream failed: {:?}", e)
                                    });
                                connect_sockets.remove(&flow_id);
                                connect_streams.remove(&stream_id);
                            }
                        }
                    });
                    // TODO: Might wanna handle the return value
                    let _ = tokio::join!(terminate_task);
                }
            }
            // TODO: handle termination of UDP assoiciate correctly
        }
        socks5_proto::Command::Bind => unimplemented!(),
    }
}

pub struct Socks5Client {
    client: Client,
}

impl Socks5Client {
    pub fn new() -> Socks5Client {
        Socks5Client {
            client: Client::new(),
        }
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self.client.listen_addr();
    }

    pub async fn bind<T: tokio::net::ToSocketAddrs>(
        &mut self,
        bind_addr: T,
    ) -> Result<(), Box<dyn Error>> {
        self.client.bind(bind_addr).await
    }

    pub async fn run(&mut self, server_addr: &String) -> Result<(), Box<dyn Error>> {
        self.client.run(server_addr, handle_socks5_stream).await
    }
}

fn socks5_addr_to_string(addr: &socks5_proto::Address) -> String {
    match addr {
        socks5_proto::Address::SocketAddress(socket_addr) => socket_addr.to_string(),
        socks5_proto::Address::DomainAddress(domain, port) => format!("{}:{}", domain, port),
    }
}

/**
 * RFC9298 specify connect-udp path should be a template like /.well-known/masque/udp/192.0.2.6/443/
 */
fn socks5_addr_to_connect_udp_path(addr: &socks5_proto::Address) -> String {
    let (host, port) = match addr {
        socks5_proto::Address::SocketAddress(socket_addr) => {
            let ip_string = socket_addr.ip().to_string();
            let _ = ip_string.replace(":", "%3A"); // encode ':' in IPv6 address in URI
            (ip_string, socket_addr.port())
        }
        socks5_proto::Address::DomainAddress(domain, port) => (domain.to_owned(), port.to_owned()),
    };
    format!("/.well_known/masque/udp/{}/{}/", host, port)
}