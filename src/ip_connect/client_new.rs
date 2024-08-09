use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use log::*;
use octets::varint_len;
use packet::{ip, AsPacket, AsPacketMut, Packet, PacketMut};
use quiche::h3::NameValue;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tun2::platform::posix::{Reader, Writer};
use tun2::platform::Device;

use crate::common::*;
use crate::ip_connect::capsules::{AddressRequest, Capsule, IpLength, RequestedAddress};
use crate::ip_connect::util::*;

/**
 * Information about packets, wether they are
 * to be sent to the server or to the client.
 */
pub enum Direction {
    ToServer,
    ToClient,
}
pub struct QuicStream {
    pub stream_sender: UnboundedSender<Content>,
    pub stream_receiver: UnboundedReceiver<Content>,
    pub stream_id: u64,
    pub flow_id: u64,
}

/**
 * Infos about the CONNECT-IP session
 * Includes converters for local ip's to destination ip's (and the other way around)
 */
pub struct ConnectIpInfo {
    pub http_sender: UnboundedSender<ToSend>,
    pub stream_id: u64,
    pub flow_id: u64,
    pub local_ip: Ipv4Addr,
    pub assigned_ip: Ipv4Addr,
}

pub struct IpMessage {
    pub message: Vec<u8>,
    pub dir: Direction,
}

/**
 * Receives raw IP messages from a TUN.
 * Will send received messages to the ip_handler_t
 */
pub async fn ip_receiver_t(tx: UnboundedSender<Vec<u8>>, mut reader: Reader) {
    let mut buf = [0; 4096];
    loop {
        let size = reader.read(&mut buf).expect("Could not read from reader");
        let pkt = &buf[..size];
        use std::io::{Error, ErrorKind::Other};
        match tx.send(pkt.to_vec()).map_err(|e| Error::new(Other, e)) {
            Ok(_) => {}
            Err(e) => {
                debug!("tx send error: {}", e);
            }
        }
    }
}

/**
 * Receives IP Packets from rx.
 * Will then handle these packets accordingly and send messages to quic_dispatcher_t
 */
pub async fn ip_handler_t(
    ip_recv: &mut UnboundedReceiver<IpMessage>,
    conn_info_recv: &mut UnboundedReceiver<ConnectIpInfo>,
    quic_dispatch: UnboundedSender<ToSend>,
    ip_dispatch: UnboundedSender<Vec<u8>>,
) {
    // Wait till the QUIC server sends us connection information
    let mut conn_info: Option<ConnectIpInfo> = None;
    while conn_info.is_none() {
        conn_info = conn_info_recv.recv().await;
    }
    let conn_info = conn_info.unwrap();
    loop {
        if let Some(mut pkt) = ip_recv.recv().await {
            let version = (pkt.message[0].reverse_bits()) & 0b00001111;
            if version == 4 {
                set_ipv4_pkt_source(&mut pkt.message, &conn_info.assigned_ip);
                match pkt.dir {
                    Direction::ToServer => {
                        match quic_dispatch.send(encapsulate_ipv4(pkt.message, &conn_info.flow_id))
                        {
                            Ok(()) => {}
                            Err(e) => {
                                error!("Error sending to quic dispatch: {}", e);
                            }
                        };
                    }
                    Direction::ToClient => {
                        // Send this to the ip dispatcher
                        match ip_dispatch.send(pkt.message) {
                            Ok(()) => {}
                            Err(e) => {
                                error!("Error sending to ip dispatch: {}", e);
                            }
                        }
                    }
                }
            } else if version == 6 {
                debug!("Received IPv6 messages at ip_handler_t, not supported!");
            } else {
                error!("Received message with unknown IP protocol.");
            }
        }
    }
}

pub fn encapsulate_ipv4(pkt: Vec<u8>, stream_id: &u64) -> ToSend {
    ToSend {
        stream_id: stream_id.clone(),
        content: Content::Datagram { payload: pkt },
        finished: false,
    }
}

/**
 * Receives ready-to-send ip packets and then sends them.
 */
pub async fn ip_dispatcher_t(rx: &mut UnboundedReceiver<Vec<u8>>, mut writer: Writer) {
    loop {
        if let Some(pkt) = rx.recv().await {
            writer.write(&pkt).expect("Could not write packet to TUN!");
        }
    }
}

/**
 * A general handler of a quic connection.
 * Will set up the connection and the connect_ip HTTP/3 connection.
 * Then receives ip address and route advertisement. Sends these infos to quic_dispatcher
 * and ip_handler
 *
 * After that goes into loop, waits for new messages and handles them accordingly.
 * Sends resulting messages to either ip_handler_t or quic_dispatch_t.
 */
pub async fn quic_conn_handler(
    ip_sender: UnboundedSender<Vec<u8>>,
    info_sender: UnboundedSender<ConnectIpInfo>,
    quic_dispatcher: UnboundedSender<Arc<Mutex<Option<quiche::h3::Connection>>>>,
    mut conn: Connection,
    udp_socket: UdpSocket,
) {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
    let mut http3_conn: Arc<Mutex<Option<quiche::h3::Connection>>> = Arc::new(Mutex::new(None));
    let mut stream: Option<QuicStream> = None;
    let mut assigned_addr: Option<Ipv4Addr> = None;
    let mut got_h3_conn = false;

    loop {
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process datagram related events
        // We only expect datagrams that contain ip payloads
        while let Ok(len) = conn.dgram_recv(&mut buf) {
            let mut b = octets::Octets::with_slice(&mut buf);
            if let Ok(flow_id) = b.get_varint() {
                let context_id = match b.get_varint() {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("DATAGRAM without context ID: {}", e);
                        continue;
                    }
                };
                // TODO: Handle context IDs, for now we only accept 0
                if context_id != 0 {
                    continue;
                }
                let header_len = varint_len(flow_id) + varint_len(context_id);
                match ip::Packet::new(buf[header_len..len].to_vec().as_slice()) {
                    Ok(ip::Packet::V4(_)) => {
                        debug!("Received IPv4 packet via http3");
                        // TODO: Send packet to TUN interface
                        //       Do we have to do anything else before that?
                        //       Might need to change the IP depending on the servers answer
                        //       to our address request
                        match ip_sender.send(buf[header_len..len].to_vec()) {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("Couldn't send ip packet to ip sender: {}", e);
                            }
                        }
                    }
                    Ok(ip::Packet::V6(_)) => {
                        debug!("Received IPv6 packet via http3 (not implemented yet)");
                        continue;
                    }
                    Err(err) => {
                        debug!("Received an invalid packet: {:?}", err)
                    }
                }
            }
        }

        // Check if the http3 connection has been established
        if conn.is_established() && !got_h3_conn {
            let h3_config = quiche::h3::Config::new().unwrap();
            http3_conn = Arc::new(Mutex::new(Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            )));
            got_h3_conn = true;

            stream = match establish_ip_connect(&http3_sender).await {
                Ok(v) => Some(v),
                Err(e) => {
                    error!("Could not establish ip_connect: {:?}", e);
                    return;
                }
            };

            // We can now notify the quic dispatcher that it can get to work
            quic_dispatcher
                .send(http3_conn.clone())
                .expect("Could not send http3 conn to quic dispatcher!");

            // Now we ask for an address
            let addr_request = RequestedAddress {
                request_id: 0,
                ip_version: 4,
                ip_address: IpLength::V4(Ipv4Addr::new(0, 0, 0, 0).into()),
                ip_prefix_len: 32,
            };

            let request_capsule = AddressRequest {
                length: 9,
                requested: vec![addr_request],
            };

            let cap = Capsule {
                capsule_id: 1,
                capsule_type: super::capsules::CapsuleType::AddressRequest(request_capsule),
            };

            let mut buf = [0; 9];
            cap.serialize(&mut buf);

            http3_sender
                .send(ToSend {
                    stream_id: stream.unwrap().stream_id,
                    content: Content::Data { data: buf.to_vec() },
                    finished: false,
                })
                .unwrap_or_else(|e| error!("sending http3 data capsule failed: {:?}", e));
        }
        // Handle received QUIC data
        let (read, from) = match udp_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!("error when reading from UDP socket: {:?}", e);
                continue;
            }
        };

        debug!("received {} bytes", read);
        let recv_info = quiche::RecvInfo {
            to: udp_socket.local_addr().unwrap(),
            from,
        };

        // Process potentially coalesced packets.
        let read = match conn.recv(&mut buf[..read], recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("QUIC recv failed: {:?}", e);
                continue;
            }
        };
        debug!("processed {} bytes", read);
        //if let Some(http3_conn) = &mut http3_conn {
        if got_h3_conn {
            //let http3_conn_clone = http3_conn.clone().as_ref().unwrap();
            loop {
                debug!("polling on http3 connection");
                let http3_incoming = http3_conn.lock().await.as_mut().unwrap().poll(&mut conn);
                match http3_incoming {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            hdrs_to_strings(&list),
                            stream_id
                        );
                        // TODO: Can we just ignore headers that occur now?
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        debug!("received stream data");
                        while let Ok(read) = http3_conn
                            .lock()
                            .await
                            .as_mut()
                            .unwrap()
                            .recv_body(&mut conn, stream_id, &mut buf)
                        {
                            // we only receive capsules via data, so parse this capsule
                            match Capsule::new(&buf) {
                                Ok(v) => {
                                    // TODO: handle the capsule
                                    todo!()
                                }
                                Err(e) => {
                                    debug!("Couldn't parse capsule: {}", e);
                                }
                            }
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        info!("finished received, stream id: {} closing", stream_id);
                        // Shut down the stream
                        // TODO: If this stream is the main connect-ip stream, we have to exit or
                        //       create a new one
                        if conn.stream_finished(stream_id) {
                            debug!("stream {} finished", stream_id);
                        } else {
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                                .unwrap_or_else(|e| {
                                    error!("stream shutdown write failed: {:?}", e)
                                });
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                        error!(
                            "request was reset by peer with {}, stream id: {} closed",
                            e, stream_id
                        );
                        // Shut down the stream
                        // TODO: If this stream is the main connect-ip stream, we have to exit or
                        //       create a new one
                        if conn.stream_finished(stream_id) {
                            debug!("stream {} finished", stream_id);
                        } else {
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                                .unwrap_or_else(|e| {
                                    error!("stream shutdown write failed: {:?}", e)
                                });
                        }
                    }
                    Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        info!("GOAWAY id={}", goaway_id);
                    }

                    Err(quiche::h3::Error::Done) => {
                        debug!("poll done");
                        break;
                    }

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);
                        break;
                    }
                };
            }
        }
    }
}

/**
 * Establishes the CONNECT-IP connection.
 * Sends the necessary requests to the server and awaits the response
 * Returns a QuicStream struct if the connection succeeded, or an HandleIPError if it failed.
 */
pub async fn establish_ip_connect(
    http3_sender: &UnboundedSender<ToSend>,
) -> Result<QuicStream, HandleIPError> {
    let headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"), // TODO: Should always be https?
        quiche::h3::Header::new(b":authority", b""),   // TODO
        quiche::h3::Header::new(b"path", b"/.well-known/masque/ip/*/*/"),
        quiche::h3::Header::new(b"connect-ip-version", b"3"),
    ];

    // Now send content via http3_sender
    let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
    let (response_sender, response_receiver) = mpsc::unbounded_channel::<Content>();

    http3_sender
        .send(ToSend {
            stream_id: u64::MAX,
            content: Content::Request {
                headers: headers,
                stream_id_sender: stream_id_sender,
            },
            finished: false,
        })
        .unwrap_or_else(|e| error!("sending http3 request failed: {:?}", e));

    let stream_id = stream_id_receiver
        .recv()
        .await
        .expect("stream_id receiver error");
    let flow_id = stream_id / 4;

    // Save this stream we just created

    let mut stream = QuicStream {
        stream_sender: response_sender,
        stream_receiver: response_receiver,
        stream_id: stream_id,
        flow_id: flow_id,
    };

    let mut succeeded = false;

    let response = stream
        .stream_receiver
        .recv()
        .await
        .expect("http3 response receiver error");

    // Check if the response was positive
    // We expect the status code to be in 2xx range
    if let Content::Headers { headers } = response {
        debug!("Got response {:?}", hdrs_to_strings(&headers));

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
                        succeeded = true;
                        debug!("CONNECT-IP connection established for flow {}", flow_id);
                    }
                }
            }
        }
    } else {
        error!("received others when expecting headers for connect");
        return Err(HandleIPError {
            message: "http3 CONNECT UDP failed".to_string(),
        });
    }

    if !succeeded {
        error!("http3 CONNECT UDP failed");
        return Err(HandleIPError {
            message: "http3 CONNECT UDP failed".to_string(),
        });
    }
    todo!()
}

/**
 * Receives ready-to-send QUIC messages and sends them to
 * the QUIC Connection
 * Will try to resend DATA packets till either the connection breaks down or the packets are all sent.
 * Waits first for the QUIC connection to be established, including the http3 conn.
 *  - rx              : Receiver for any messages that shall be sent to the http3 conn
 *  - quic_sender_recv: Receives an http3_sender once the connection is ready
 *  - conn            : The quic connection, used for sending datagrams
 */
pub async fn quic_dispatcher_t(
    mut rx: UnboundedReceiver<ToSend>,
    mut quic_sender_recv: UnboundedReceiver<Arc<Mutex<Option<quiche::h3::Connection>>>>,
    conn: &mut Connection,
) {
    // First wait for the connection info the QUIC handler provides
    // With that you can exchange ip's and everything
    // Wait till the QUIC server sends us connection information
    let mut http3_conn: Option<Arc<Mutex<Option<quiche::h3::Connection>>>> = None;
    while http3_conn.is_none() {
        http3_conn = quic_sender_recv.recv().await;
    }
    let mut http3_conn = http3_conn.unwrap();
    let mut to_send_queue: VecDeque<ToSend> = VecDeque::new();
    loop {
        if let Some(pkt) = rx.recv().await {
            to_send_queue.push_back(pkt);
            // Send all packets in the deque
            // WARN: If a packet fails over and over this will loop forever and block everything.
            while !to_send_queue.is_empty() {
                let mut pkt = to_send_queue.pop_front().unwrap();
                let result = match &pkt.content {
                    Content::Headers { headers: _ } => {
                        unreachable!("We should not be getting headers!")
                    }
                    Content::Request {
                        headers,
                        stream_id_sender,
                    } => {
                        debug!("Sending http3 request..");
                        match http3_conn.lock().await.as_mut().unwrap().send_request(
                            conn,
                            &headers,
                            pkt.finished,
                        ) {
                            Ok(stream_id) => {
                                stream_id_sender.send(stream_id).await.unwrap_or_else(|e| {
                                    error!("could not send stream_id back to receiver: {}", e)
                                });
                                Ok(())
                            }
                            Err(e) => {
                                error!("sending h3 request failed: {}", e);
                                Err(e)
                            }
                        }
                    }
                    Content::Data { data } => {
                        debug!("sending http3 data of {} bytes", data.len());
                        let mut written = 0;
                        loop {
                            if written >= data.len() {
                                break Ok(());
                            }
                            match http3_conn.lock().await.as_mut().unwrap().send_body(
                                conn,
                                pkt.stream_id,
                                &data[written..],
                                pkt.finished,
                            ) {
                                Ok(v) => written += v,
                                Err(e) => {
                                    // Failed to send the packet. If adequate, try resending later
                                    pkt = ToSend {
                                        stream_id: pkt.stream_id,
                                        content: Content::Data {
                                            data: data[written..].to_vec(),
                                        },
                                        finished: pkt.finished,
                                    };
                                    break Err(e);
                                }
                            }
                            debug!("written http3 data {} of {} bytes", written, data.len());
                        }
                    }
                    Content::Datagram { payload } => {
                        debug!("Sending HTTP/3 datagram of {} bytes!", payload.len());
                        match send_h3_dgram(conn, pkt.stream_id, &payload) {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.into()),
                        }
                    }
                    Content::Finished => {
                        debug!("Shutting down stream!");
                        match conn.stream_shutdown(pkt.stream_id, quiche::Shutdown::Read, 0) {
                            Ok(_) => {}
                            Err(quiche::Error::Done) => {}
                            Err(e) => {
                                error!("could not shutdown stream: {}", e);
                            }
                        }

                        match conn.stream_shutdown(pkt.stream_id, quiche::Shutdown::Write, 0) {
                            Ok(_) => {}
                            Err(quiche::Error::Done) => {}
                            Err(e) => {
                                error!("could not shutdown stream: {}", e);
                            }
                        }
                        Ok(())
                    }
                };
                match result {
                    Ok(_) => {}
                    Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                        debug!(
                            "Connection {} stream {} stream blocked, retry later",
                            conn.trace_id(),
                            pkt.stream_id
                        );
                        to_send_queue.push_front(pkt);
                        break;
                    }
                    Err(e) => {
                        error!(
                            "Connection {} stream {} send failed {:?}",
                            conn.trace_id(),
                            pkt.stream_id,
                            e
                        );
                        if !conn.stream_finished(pkt.stream_id) {
                            conn.stream_shutdown(pkt.stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                            conn.stream_shutdown(pkt.stream_id, quiche::Shutdown::Write, 0)
                                .unwrap_or_else(|e| {
                                    error!("stream shutdown write failed: {:?}", e)
                                });
                        }
                    }
                }
            }
        }
    }
}

pub struct ConnectIPClient;

impl ConnectIPClient {
    pub async fn run(&self, bind_addr: &String, server_addr: &String) {
        // 1) Create QUIC connection, connect to server
        let mut socket = match self.get_udp(bind_addr).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create udp socket: {}", e);
                return;
            }
        };

        let mut quic_conn = match self.create_quic_conn(&mut socket, server_addr).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create quic connection: {}", e);
                return;
            }
        };
        // 2) Setup Connect IP stream

        // 3) Create TUN
        let dev = match self.create_tun() {
            Ok(v) => v,
            Err(e) => {
                error!("could not create TUN: {}", e);
                return;
            }
        };

        let (mut reader, mut writer) = dev.split();

        // 4) Create receivers/senders and start threads
        /*

        // IP
        let (ip_sender, mut ip_recv) = tokio::sync::mpsc::unbounded_channel();
        let (to_quic_dispatch, quic_dispatch_reader) = tokio::sync::mpsc::unbounded_channel();
        //let (to_quic_handler, quic_handler_reader) = tokio::sync::mpsc::unbounded_channel();
        let (to_ip_dispatch, mut ip_dispatch_reader) = tokio::sync::mpsc::unbounded_channel();
        let (info_sender, info_retriever) = tokio::sync::mpsc::unbounded_channel();
        let to_ip_dispatch_clone = to_ip_dispatch.clone();

        // Spawn all threads. Stop once the first one finishes.
        tokio::select! {
            _ = ip_receiver_t(ip_sender, reader) => {},
            _ = ip_handler_t(&mut ip_recv, to_ip_dispatch_clone) => {},
            _ = ip_dispatcher_t(&mut ip_dispatch_reader, writer) => {},
           // _ = quic_receiver_t(to_quic_handler, quic_conn) => {},
          //  _ = quic_handler_t(quic_handler_reader, to_quic_dispatch, to_ip_dispatch) => {},
            _ = quic_conn_handler(to_quic_dispatch, info_sender, quic_conn, socket) => {},
            _ = quic_dispatcher_t(quic_dispatch_reader, info_retriever) => {},
        }
        */
    }

    async fn create_quic_conn(
        &self,
        udp_socket: &mut UdpSocket,
        server_addr: &String,
    ) -> Result<Connection, quiche::Error> {
        let mut http_start = "";
        if !server_addr.starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}", http_start, server_addr);

        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

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
        config.set_initial_max_streams_bidi(1000);
        config.set_initial_max_streams_uni(1000);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000);

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Client connection.
        let local_addr = udp_socket.local_addr().unwrap();
        let mut connection =
            quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
                .expect("quic connection failed");
        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            udp_socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let mut out = [0; MAX_DATAGRAM_SIZE];

        let (write, send_info) = connection.send(&mut out).expect("initial send failed");

        while let Err(e) = udp_socket.send_to(&out[..write], send_info.to).await {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send_to() would block");
                continue;
            }
            panic!("UDP socket send_to() failed: {:?}", e);
        }
        debug!("written {}", write);

        // TODO: Do we do more setup with the connection?
        Ok(connection)

        //todo!();
    }

    /**
     * Creates a TUN.
     * Currently config is hardcoded:
     *  - Address = 10.0.0.9
     *  - Netmaks = 255.255.255.0
     *  - Dest    = 10.0.0.1
     *
     * Warning: Needs root priviligies on linux!
     */
    fn create_tun(&self) -> Result<Device, tun2::Error> {
        let mut config = tun2::Configuration::default();

        config
            .address((10, 0, 0, 9))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 1))
            .up();

        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });

        tun2::create(&config)
    }

    /**
     * Creates and binds the UDP socket used for QUIC
     */
    async fn get_udp(&self, bind_addr: &String) -> Result<UdpSocket, UdpBindError> {
        let mut http_start = "";
        if !bind_addr.starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}", http_start, bind_addr);

        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        let socket = match UdpSocket::bind("0.0.0.0:0000").await {
            Ok(v) => v,
            Err(e) => {
                error!("Could not bind Udp socket: {:?}", e);
                return Err(UdpBindError);
            }
        };

        match socket.connect(peer_addr.clone()).await {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "Could not connect udp socket to peer address {}: {:?}",
                    peer_addr, e
                );
                return Err(UdpBindError);
            }
        }

        Ok(socket)
    }
}
