use quiche;
use quiche::h3::NameValue;
use ring::rand::*;

use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time;

use log::*;

use socks5_proto::{
    handshake::{
        Method as HandshakeMethod, Request as HandshakeRequest, Response as HandshakeResponse,
    },
    Address, ProtocolError, Reply, Request, Response,
};

use crate::common::*;

#[derive(Debug)]
enum Content {
    Request {
        headers: Vec<quiche::h3::Header>,
        stream_id_sender: mpsc::Sender<u64>,
    },
    Headers {
        headers: Vec<quiche::h3::Header>,
    },
    Data {
        data: Vec<u8>,
    },
    Datagram {
        payload: Vec<u8>,
    },
    Finished,
}

#[derive(Debug)]
struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    content: Content,
    finished: bool,
}

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

struct Client {
    listener: Option<TcpListener>,
}

impl Client {
    pub fn new() -> Client {
        Client { listener: None }
    }

    /**
     * returns None if client is not bound to a socket yet
     */
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self
            .listener
            .as_ref()
            .map(|listener| listener.local_addr().unwrap());
    }

    /**
     * Bind the server to listen to an address
     */
    pub async fn bind<T: tokio::net::ToSocketAddrs>(
        &mut self,
        bind_addr: T,
    ) -> Result<(), Box<dyn Error>> {
        debug!("creating TCP listener");

        let listener = TcpListener::bind(bind_addr).await?;
        debug!("listening on {}", listener.local_addr().unwrap());

        self.listener = Some(listener);
        Ok(())
    }

    /**
     * Run client to receive TCP connections at the binded address, and handle
     * incoming streams with stream_handler (e.g. handshake, negotiation, proxying traffic)
     *
     * This enables any protocol that accepts TCP connection to start with, such as HTTP1.1
     * CONNECT and SOCKS5 as implemented below. Similarly, UDP listening can be easily
     * added if necessary.
     */
    pub async fn run<F, Fut>(
        &mut self,
        server_addr: &String,
        mut stream_handler: F,
    ) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(
            TcpStream,
            UnboundedSender<ToSend>,
            Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
            Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
        ) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if self.listener.is_none() {
            return Err(Box::new(RunBeforeBindError));
        }
        let listener = self.listener.as_mut().unwrap();

        let server_name = format!("https://{}", server_addr); // TODO: avoid duplicate https://

        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        debug!("creating socket");
        let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
        socket.connect(peer_addr.clone()).await?;
        let socket = Arc::new(socket);
        debug!("connecting to {} at {}", server_name, peer_addr);

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        // TODO: *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        config.set_max_idle_timeout(1000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000);

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Client connection.
        let local_addr = socket.local_addr().unwrap();
        let mut conn = quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
            .expect("quic connection failed");
        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
        while let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send_to() would block");
                continue;
            }
            panic!("UDP socket send_to() failed: {:?}", e);
        }
        debug!("written {}", write);

        let mut http3_conn: Option<quiche::h3::Connection> = None;
        let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
        let connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut http3_retry_send: Option<ToSend> = None;
        let mut interval = time::interval(Duration::from_millis(20));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }
            // Process datagram-related events.
            while let Ok(len) = conn.dgram_recv(&mut buf) {
                let mut b = octets::Octets::with_slice(&mut buf);
                if let Ok(flow_id) = b.get_varint() {
                    info!(
                        "Received DATAGRAM flow_id={} len={} buf={:02x?}",
                        flow_id,
                        len,
                        buf[0..len].to_vec()
                    );

                    // TODO: Check if this is actually a good way to check for the
                    // length of the flow_id
                    // So far it's confirmed to work for a flow id of 0
                    let flow_id_len: usize = (flow_id.checked_ilog10().unwrap_or(0) + 1)
                        .try_into()
                        .unwrap();
                    info!("flow_id_len={}", flow_id_len);
                    let connect_sockets = connect_sockets.lock().unwrap();
                    if let Some(sender) = connect_sockets.get(&flow_id) {
                        sender
                            .send(Content::Datagram {
                                payload: buf[flow_id_len..len].to_vec(),
                            })
                            .unwrap_or_else(|e| error!("Could not send dgram payload {:?}", e));
                    }
                } else {
                    error!("Could not get varint from dgram!");
                }
            }

            tokio::select! {
                // handle QUIC received data
                recvd = socket.recv_from(&mut buf) => {
                    let (read, from) = match recvd {
                        Ok(v) => v,
                        Err(e) => {
                            error!("error when reading from UDP socket: {:?}", e);
                            continue
                        },
                    };
                    debug!("received {} bytes", read);
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };

                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..read], recv_info) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("QUIC recv failed: {:?}", e);
                            continue
                        },
                    };
                    debug!("processed {} bytes", read);

                    if let Some(http3_conn) = &mut http3_conn {
                        // Process HTTP/3 events.
                        loop {
                            debug!("polling on http3 connection");
                            match http3_conn.poll(&mut conn) {
                                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                    info!("got response headers {:?} on stream id {}", hdrs_to_strings(&list), stream_id);
                                    let connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Headers { headers: list })
                                            .unwrap_or_else(|e| error!("Could not send headers: {:?}", e));
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    debug!("received stream data");
                                    let connect_streams = connect_streams.lock().unwrap();
                                    while let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                                        if let Some(sender) = connect_streams.get(&stream_id) {
                                            debug!("got {} bytes of response data on stream {}", read, stream_id);
                                            trace!("{}", unsafe {std::str::from_utf8_unchecked(&buf[..read])});
                                            sender.send(Content::Data { data: buf[..read].to_vec() })
                                                .unwrap_or_else(|e| error!("Could not send data: {:?}", e));
                                        } else {
                                            debug!("received {} bytes of stream data on unknown stream {}", read, stream_id);
                                        }
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Finished)) => {
                                    info!("finished received, stream id: {} closing", stream_id);
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {})
                                            .unwrap_or_else(|e| error!("Could not send finish stream data: {:?}", e));
                                        connect_streams.remove(&stream_id);
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                    error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {})
                                            .unwrap_or_else(|e| error!("Could not send finish stream data: {:?}", e));
                                        connect_streams.remove(&stream_id);
                                    }
                                },
                                Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                                    info!("GOAWAY id={}", goaway_id);
                                },

                                Err(quiche::h3::Error::Done) => {
                                    debug!("poll done");
                                    break;
                                },

                                Err(e) => {
                                    error!("HTTP/3 processing failed: {:?}", e);
                                    break;
                                },
                            };
                        }
                    }
                },
                // Send pending HTTP3 data in channel to HTTP3 connection on QUIC
                http3_to_send = http3_receiver.recv(), if http3_conn.is_some() && http3_retry_send.is_none() => {
                    if http3_to_send.is_none() {
                        unreachable!()
                    }
                    let mut to_send = http3_to_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    loop {
                        let result = match &to_send.content {
                            Content::Headers { .. } => unreachable!(),
                            Content::Request { headers, stream_id_sender } => {
                                debug!("sending http3 request {:?} to {:?}", hdrs_to_strings(&headers), http3_conn.peer_settings_raw());
                                match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                    Ok(stream_id) => {
                                        stream_id_sender.send(stream_id)
                                            .await
                                            .unwrap_or_else(|e| error!("http3 request send stream_id failed: {:?}", e));
                                        Ok(())
                                    },
                                    Err(e) => {
                                        error!("http3 request send failed");
                                        Err(e)
                                    },
                                }
                            },
                            Content::Data { data } => {
                                debug!("sending http3 data of {} bytes", data.len());
                                let mut written = 0;
                                loop {
                                    if written >= data.len() {
                                        break Ok(())
                                    }
                                    match http3_conn.send_body(&mut conn, to_send.stream_id, &data[written..], to_send.finished) {
                                        Ok(v) => written += v,
                                        Err(e) => {
                                            to_send = ToSend { stream_id: to_send.stream_id, content: Content::Data { data: data[written..].to_vec() }, finished: to_send.finished };
                                            break Err(e)
                                        },
                                    }
                                    debug!("written http3 data {} of {} bytes", written, data.len());
                                }
                            },
                            Content::Datagram { payload } => {
                                debug!("sending http3 datagram of {} bytes to flow {}", payload.len(), to_send.stream_id);
                                match send_h3_dgram(&mut conn, to_send.stream_id, &payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed: {:?}", e);
                                            break;
                                        }
                                    }
                            },
                            Content::Finished => {
                                debug!("shutting down stream");
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0)
                                    .unwrap_or_else(|e| error!("A stream shutdown read failed: {:?}", e));
                                match conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0) {
                                    Ok(v) => Ok(v),
                                    Err(e) => {
                                        error!("stream shutdown failed: {}", e);
                                        Ok(()) // ignore the error
                                    }
                                }
                            },
                        };
                        match result {
                            Ok(_) => {},
                            Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                                debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                                http3_retry_send = Some(to_send);
                                break;
                            },
                            Err(e) => {
                                error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                                if !conn.stream_finished(to_send.stream_id) {
                                    conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0)
                                        .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                                    conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0)
                                        .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
                                }
                                {
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    connect_streams.remove(&to_send.stream_id);
                                }
                            }
                        };
                        to_send = match http3_receiver.try_recv() {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                    }
                },

                // Accept a new TCP connection
                tcp_accepted = listener.accept() => {
                    match tcp_accepted {
                        Ok((tcp_socket, addr)) => {
                            debug!("accepted connection from {}", addr);
                            tokio::spawn(stream_handler(tcp_socket, http3_sender.clone(), connect_streams.clone(), connect_sockets.clone()));
                        },
                        Err(_) => todo!(),
                    };
                },

                // Retry sending in case of stream blocking
                _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                    let mut to_send = http3_retry_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    let result = match &to_send.content {
                        Content::Headers { .. } => unreachable!(),
                        Content::Request { headers, stream_id_sender } => {
                            debug!("retry sending http3 request {:?}", hdrs_to_strings(&headers));
                            match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                Ok(stream_id) => {
                                    stream_id_sender.send(stream_id).await
                                        .unwrap_or_else(|e| error!("http3 request send stream_id failed: {:?}", e));
                                    Ok(())
                                },
                                Err(e) => {
                                    error!("http3 request send failed");
                                    Err(e)
                                },
                            }
                        },
                        Content::Data { data } => {
                            debug!("retry sending http3 data of {} bytes", data.len());
                            let mut written = 0;
                            loop {
                                if written >= data.len() {
                                    break Ok(())
                                }
                                match http3_conn.send_body(&mut conn, to_send.stream_id, &data[written..], to_send.finished) {
                                    Ok(v) => written += v,
                                    Err(e) => {
                                        to_send = ToSend { stream_id: to_send.stream_id, content: Content::Data { data: data[written..].to_vec() }, finished: to_send.finished };
                                        break Err(e)
                                    },
                                }
                                debug!("written http3 data {} of {} bytes", written, data.len());
                            }
                        },
                        Content::Datagram { payload } => {
                            debug!("retry sending http3 datagram of {} bytes", payload.len());
                            //http3_conn.send_dgram(&mut conn, to_send.stream_id, &payload)
                            match send_h3_dgram(&mut conn, to_send.stream_id, &payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed: {:?}", e);
                                            break;
                                        }
                                    }
                        },
                        Content::Finished => unreachable!(),
                    };
                    match result {
                        Ok(_) => {
                            http3_retry_send = None;
                        },
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
                        },
                        Err(e) => {
                            error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                            conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0)
                                .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
                            {
                                let mut connect_streams = connect_streams.lock().unwrap();
                                connect_streams.remove(&to_send.stream_id);
                            }
                            http3_retry_send = None;
                        }
                    };
                },

                else => break,
            }

            // Create a new HTTP/3 connection once the QUIC connection is established.
            if conn.is_established() && http3_conn.is_none() {
                let h3_config = quiche::h3::Config::new().unwrap();
                http3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }
            // Send pending QUIC packets
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("QUIC connection {} done writing", conn.trace_id());
                        break;
                    }

                    Err(e) => {
                        error!("QUIC connection {} send failed: {:?}", conn.trace_id(), e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                match socket.send_to(&out[..write], send_info.to).await {
                    Ok(written) => debug!(
                        "{} written {} bytes out of {}",
                        conn.trace_id(),
                        written,
                        write
                    ),
                    Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
                }
            }
        }

        Ok(())
    }
}

async fn handle_http1_stream(
    mut stream: TcpStream,
    http3_sender: UnboundedSender<ToSend>,
    connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
    _connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
) {
    let mut buf = [0; 65535];
    let mut pos = match stream.read(&mut buf).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error reading from TCP stream: {}", e);
            return;
        }
    };
    loop {
        match stream.try_read(&mut buf[pos..]) {
            Ok(read) => pos += read,
            Err(ref e) if would_block(e) => break,
            Err(ref e) if interrupted(e) => continue,
            Err(e) => {
                error!("Error reading from TCP stream: {}", e);
                return;
            }
        };
    }
    let peer_addr = stream.peer_addr().unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    //let res = req.parse(&buf[..pos]).unwrap();
    req.parse(&buf[..pos]).unwrap();
    if let Some(method) = req.method {
        if let Some(path) = req.path {
            if method.eq_ignore_ascii_case("CONNECT") {
                // TODO: Check Host?
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
                    .unwrap_or_else(|e| error!("sending HTTP3 request failed: {:?}", e));
                info!("Sent HTTP3 request");

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
                                    info!("connection established, sending 200 OK");
                                    match stream.write(&b"HTTP/1.1 200 OK\r\n\r\n".to_vec()).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!("Sending 200 OK failed: {:?}", e);
                                        }
                                    };
                                }
                            }
                        }
                    }
                } else {
                    error!("received others when expecting headers for connect");
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
                            http3_sender_clone
                                .send(ToSend {
                                    stream_id: stream_id,
                                    content: Content::Finished,
                                    finished: false,
                                })
                                .unwrap_or_else(|e| error!("tcp finish message not sent: {:?}", e));
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
                            .unwrap_or_else(|e| error!("tcp finish message not sent: {:?}", e));
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

                // {
                //     let mut connect_streams = connect_streams.lock().unwrap();
                //     connect_streams.remove(&stream_id);
                // }
                return;
            }
        }
    }
    match stream
        .write(&b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec())
        .await {
            Ok(_) => {},
            Err(e) => {
                error!("Error when writing 400 to tcp stream: {:?}", e);
            }
        };
}

pub struct Http1Client {
    client: Client,
}

impl Http1Client {
    pub fn new() -> Http1Client {
        Http1Client {
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
        self.client.run(server_addr, handle_http1_stream).await
    }
}

async fn handle_socks5_stream(
    mut stream: TcpStream,
    http3_sender: UnboundedSender<ToSend>,
    connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
    connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
) {
    let peer_addr = stream.peer_addr().unwrap();
    let hs_req = match HandshakeRequest::read_from(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            error!("socks5 handshake request read failed: {}", e);
            return;
        }
    };

    if hs_req
        .methods
        .contains(&HandshakeMethod::NONE)
    {
        let hs_resp = HandshakeResponse::new(HandshakeMethod::NONE);
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
            HandshakeResponse::new(HandshakeMethod::UNACCEPTABLE);
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
        socks5_proto::Address::DomainAddress(domain, port) => format!("{:?}:{}", domain, port),
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
        socks5_proto::Address::DomainAddress(domain, port) => { 
            let domain_string = format!("{:?}", domain);
            let _ = domain_string.replace("\"", "");
            (domain_string, port.to_owned())},
    };
    format!("/.well_known/masque/udp/{}/{}/", host, port)
}
