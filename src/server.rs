use futures::lock::Mutex;
use log::*;
use packet::ip;
use packet::ip::v4::Packet;
use quiche::h3::NameValue;
use tokio::task::JoinHandle;
use url::Url;

use std::collections::HashMap;
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{self, SocketAddr};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::{self, Duration};

use ring::rand::*;

use crate::common::*;
use crate::ip_connect::capsules::*;
use crate::ip_connect::client::encapsulate_ipv4;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

struct QuicReceived {
    recv_info: quiche::RecvInfo,
    data: Vec<u8>,
}

struct IpConnectSession {
    stream_id: u64,
    flow_id: u64,
    ip_h3_sender: UnboundedSender<Content>,
    handler_thread: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

/**
 * Client for each QUIC connection
 */
struct Client {
    conn: quiche::Connection,
    quic_receiver: mpsc::UnboundedReceiver<QuicReceived>,
    socket: Arc<UdpSocket>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, mpsc::UnboundedSender<QuicReceived>>;

pub struct Server {
    socket: Option<Arc<UdpSocket>>,
}

impl Server {
    pub fn new() -> Server {
        Server { socket: None }
    }

    /**
     * Get the socket address the server is bound to. Returns None if server is not bound to a socket yet
     */
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self
            .socket
            .clone()
            .map(|socket| socket.local_addr().unwrap());
    }

    /**
     * Bind the server to listen to an address
     */
    pub async fn bind<T: tokio::net::ToSocketAddrs>(
        &mut self,
        listen_addr: T,
    ) -> Result<(), Box<dyn Error>> {
        debug!("creating UDP socket");

        // Create the UDP listening socket, and register it with the event loop.
        let socket = UdpSocket::bind(listen_addr).await?;
        debug!("listening on {}", socket.local_addr().unwrap());

        self.socket = Some(Arc::new(socket));
        Ok(())
    }

    pub async fn run(&self, tun_addr: String, tun_name: String) -> Result<(), Box<dyn Error>> {
        if self.socket.is_none() {
            return Err(Box::new(RunBeforeBindError));
        }
        let socket = self.socket.clone().unwrap();

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Create the configuration for the QUIC connections.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        config
            .load_cert_chain_from_pem_file("example_cert/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("example_cert/cert.key")
            .unwrap();

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        // TODO: allow custom configuration of the following parameters and also consider the defaults more carefully
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
        config.enable_early_data();

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut clients = ClientMap::new();

        // CONNECT-IP things
        // TODO: Un-hardcode this. Should just be the next free ip for the TUN interface.
        let mut current_ip = Ipv4Addr::new(10, 8, 0, 3);
        let ip_connect_clients: Arc<Mutex<HashMap<Ipv4Addr, UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tun_sender, tun_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        // Create TUN handler (creates device automatically)
        let ip_connect_clients_clone = ip_connect_clients.clone();
        let _tun_thread = tokio::spawn(async move {
            tun_socket_handler(ip_connect_clients_clone, tun_receiver, tun_addr, tun_name).await;
        });

        let local_addr = socket.local_addr().unwrap();
        'read: loop {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,

                Err(e) => {
                    panic!("recv_from() failed: {:?}", e);
                }
            };

            debug!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            debug!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let tx = if !clients.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id) {
                // TODO: move initialization to client task
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from).await {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send_to() would block");
                            break;
                        }

                        panic!("send_to() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from).await {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send_to() would block");
                            break;
                        }

                        panic!("send_to() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn =
                    quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                let (tx, rx) = mpsc::unbounded_channel();

                let client = Client {
                    conn,
                    quic_receiver: rx,
                    socket: socket.clone(),
                };

                clients.insert(scid.clone(), tx);
                let tun_sender_clone = tun_sender.clone();
                let ip_connect_clients_clone = ip_connect_clients.clone();
                tokio::spawn(async move {
                    handle_client(
                        client, 
                        current_ip.clone(), 
                        &tun_sender_clone,
                        ip_connect_clients_clone
                    ).await
                });
                current_ip = match get_next_ipv4(current_ip, 0xFFFF0000) {
                    Ok(v) => v,
                    Err(e) => {
                        panic!("Could not get a new IP: {e}");
                    }
                };

                clients.get(&scid).unwrap()
            } else {
                match clients.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            match tx.send(QuicReceived {
                recv_info,
                data: pkt_buf.to_vec(),
            }) {
                Ok(_) => {}
                _ => {
                    debug!("Error sending to {:?}", &hdr.dcid);
                    clients.remove(&hdr.dcid);
                }
            }
        }

        Ok(())
    }
}

/**
 * Client handler that handles the connection for a single client
 */
async fn handle_client(
    mut client: Client,
    client_ip: Ipv4Addr,
    tun_sender: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ip_connect_clients: Arc<Mutex<HashMap<Ipv4Addr, UnboundedSender<Vec<u8>>>>>,
) {
    let mut http3_conn: Option<quiche::h3::Connection> = None;
    let mut connect_streams: HashMap<u64, UnboundedSender<Vec<u8>>> = HashMap::new(); // for TCP CONNECT
    let mut connect_sockets: HashMap<u64, UnboundedSender<Vec<u8>>> = HashMap::new(); // for CONNECT UDP
    let mut connect_ip_session: Option<IpConnectSession> = None;

    let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();

    let mut out = [0; MAX_DATAGRAM_SIZE];

    let timeout = 5000; // milliseconds
    let sleep = tokio::time::sleep(Duration::from_millis(timeout));
    tokio::pin!(sleep);

    let mut http3_retry_send: Option<ToSend> = None;
    let mut interval = time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            // Send pending HTTP3 data in channel to HTTP3 connection on QUIC
            http3_to_send = http3_receiver.recv(),
                            if http3_conn.is_some() && http3_retry_send.is_none() => {
                if http3_to_send.is_none() {
                    unreachable!()
                }
                let mut to_send = http3_to_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                loop {
                    let result = match &to_send.content {
                        Content::Request { headers: _, stream_id_sender: _} => unreachable!(),
                        Content::Headers { headers } => {
                            debug!("sending http3 response {:?}", hdrs_to_strings(&headers));
                            http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                        },
                        Content::Data { data } => {
                            debug!("sending http3 data of {} bytes to steam {}", data.len(), to_send.stream_id);
                            let mut written = 0;
                            loop {
                                if written >= data.len() {
                                    break Ok(())
                                }
                                match http3_conn.send_body(&mut client.conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                            //http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                            match send_h3_dgram(&mut client.conn, to_send.stream_id, &payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed! {:?}", e);
                                            break;
                                        }
                                    }
                        },
                        Content::Finished => {
                            remove_stream(&mut connect_streams, to_send.stream_id, &mut client.conn);
                            Ok(())
                        },
                    };
                    match result {
                        Ok(_) => {},
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            if client.conn.stream_finished(to_send.stream_id) {
                                remove_stream(&mut connect_streams, to_send.stream_id, &mut client.conn);
                                break;
                            }

                            debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
                            break;
                        },
                        Err(e) => {
                            error!("A Connection {} stream {} send failed {:?}", client.conn.trace_id(), to_send.stream_id, e);
                            remove_stream(&mut connect_streams, to_send.stream_id, &mut client.conn);
                        }
                    };
                    to_send = match http3_receiver.try_recv() {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                }
            },

            // handle QUIC received data
            recvd = client.quic_receiver.recv() => {
                match recvd {
                    Some(mut quic_received) => {
                        let read = match client.conn.recv(&mut quic_received.data, quic_received.recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Error when quic recv(): {}", e);
                                break
                            }
                        };
                        debug!("{} processed {} bytes", client.conn.trace_id(), read);

                    },
                    None => {
                        break // channel closed on the other side. Should not happen?
                    },
                }
                // Create a new HTTP/3 connection as soon as the QUIC connection
                // is established.
                if (client.conn.is_in_early_data() || client.conn.is_established()) &&
                    http3_conn.is_none()
                {
                    http3_conn = match create_http3_conn(&mut client) {
                        Some(v) => Some(v),
                        None => {continue}
                    }
                }

                if http3_conn.is_some() {
                    // Process HTTP/3 events.
                    let http3_conn = http3_conn.as_mut().unwrap();
                    loop {
                        match handle_http3_event(
                            http3_conn,
                            &mut client,
                            http3_sender.clone(),
                            &mut connect_sockets,
                            &mut connect_streams,
                            &mut connect_ip_session,
                            &tun_sender,
                            &client_ip,
                            &ip_connect_clients).await {
                                Ok(_) => {},
                                Err(_) => {
                                    break;
                                }
                            };
                    }
                }
            },

            // Retry sending in case of stream blocking
            _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                let mut to_send = http3_retry_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                let result = match &to_send.content {
                    Content::Request { headers: _, stream_id_sender: _ } => unreachable!(),
                    Content::Headers { headers } => {
                        debug!("retry sending http3 response {:?}", hdrs_to_strings(&headers));
                        http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                    },
                    Content::Data { data } => {
                        debug!("retry sending http3 data of {} bytes", data.len());
                        let mut written = 0;
                        loop {
                            if written >= data.len() {
                                break Ok(())
                            }
                            match http3_conn.send_body(&mut client.conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                       // http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                        match send_h3_dgram(&mut client.conn, to_send.stream_id, &payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed: {:?}", e);
                                            break;
                                        }
                                    }
                    },
                    Content::Finished => todo!(),
                };
                match result {
                    Ok(_) => {
                        http3_retry_send = None;
                    },
                    Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                        debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                        http3_retry_send = Some(to_send);
                    },
                    Err(e) => {
                        error!("B Connection {} stream {} send failed {:?}",
                            client.conn.trace_id(),
                            to_send.stream_id, e);
                        remove_stream(&mut connect_streams, to_send.stream_id, &mut client.conn);
                        http3_retry_send = None;
                    }
                };
            },

            () = &mut sleep => {
                trace!("timeout elapsed");
                sleep.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout));

                if client.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        client.conn.trace_id(),
                        client.conn.stats()
                    );
                }
            },
            else => break,
        }
        // Send pending QUIC packets
        loop {
            let (write, send_info) = match client.conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("QUIC connection {} done writing", client.conn.trace_id());
                    break;
                }

                Err(e) => {
                    error!(
                        "QUIC connection {} send failed: {:?}",
                        client.conn.trace_id(),
                        e
                    );

                    client.conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            match client.socket.send_to(&out[..write], send_info.to).await {
                Ok(written) => debug!(
                    "{} written {} bytes out of {}",
                    client.conn.trace_id(),
                    written,
                    write
                ),
                Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
            }
        }
    }
}

/**
 * Parse pseudo-header path for CONNECT UDP to SocketAddr
 */
fn path_to_socketaddr(path: &[u8]) -> Option<net::SocketAddr> {
    // for now, let's assume path pattern is "/something.../target-host/target-port/"
    let mut split_iter = std::io::BufRead::split(path, b'/');
    let mut second_last = None;
    let mut last = None;
    while let Some(curr) = split_iter.next() {
        if let Ok(curr) = curr {
            second_last = last;
            last = Some(curr);
        } else {
            return None;
        }
    }
    if second_last.is_some() && last.is_some() {
        let second_last = second_last.unwrap();
        let last = last.unwrap();
        let second_last = std::str::from_utf8(&second_last);
        let last = std::str::from_utf8(&last);
        if second_last.is_ok() && last.is_ok() {
            let url_str = format!("scheme://{}:{}/", second_last.unwrap(), last.unwrap());
            let url = url::Url::parse(&url_str);
            if let Ok(url) = url {
                let socket_addrs = url.to_socket_addrs();
                if let Ok(mut socket_addrs) = socket_addrs {
                    return socket_addrs.next();
                }
            }
        }
    }

    None
}

/**
 * Creates a new HTTP/3 connection for an existing & established QUIC connection
 */
fn create_http3_conn(client: &mut Client) -> Option<quiche::h3::Connection> {
    debug!(
        "{} QUIC handshake completed, now trying HTTP/3",
        client.conn.trace_id()
    );

    let h3_config = quiche::h3::Config::new().unwrap();
    let h3_conn = match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
        Ok(v) => v,

        Err(e) => {
            error!("failed to create HTTP/3 connection: {}", e);
            return None;
        }
    };

    // TODO: sanity check h3 connection before adding to map
    Some(h3_conn)
}

// TODO: Declutter this!
/**
 * Processes an HTTP/3 event
 */
async fn handle_http3_event(
    http3_conn: &mut quiche::h3::Connection,
    client: &mut Client,
    http3_sender: UnboundedSender<ToSend>,
    connect_sockets: &mut HashMap<u64, UnboundedSender<Vec<u8>>>,
    connect_streams: &mut HashMap<u64, UnboundedSender<Vec<u8>>>,
    connect_ip_session: &mut Option<IpConnectSession>,
    tun_sender: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    next_free_ip: &Ipv4Addr,
    connect_ip_clients: &Arc<Mutex<HashMap<Ipv4Addr, UnboundedSender<Vec<u8>>>>>,
) -> Result<(), ClientError> {
    let mut buf = [0; 65535];
    // Process datagram-related events.
    while let Ok(len) = client.conn.dgram_recv(&mut buf) {
        let mut b = octets::Octets::with_slice(&buf);
        if let Ok(flow_id) = b.get_varint() {
            info!(
                "Received DATAGRAM flow_id={} len={} buf={:02x?}",
                flow_id,
                len,
                buf[0..len].to_vec()
            );

            // TODO: Check if this is actually a good way to check for the
            // length of the flow_id
            let flow_id_len: usize = (flow_id.checked_ilog10().unwrap_or(0) + 1)
                .try_into()
                .unwrap();
            info!("flow_id_len={}", flow_id_len);
            if connect_sockets.contains_key(&flow_id) {
                let data = &buf[flow_id_len..len];
                connect_sockets
                    .get(&flow_id)
                    .unwrap()
                    .send(data.to_vec())
                    .expect("Send to udp connect handler failed.");
            } else if connect_ip_session.is_some() {
                {
                    let ip_session = connect_ip_session.as_ref().unwrap();
                    if ip_session.flow_id == flow_id {
                        let data = &buf[flow_id_len..len];
                        ip_session
                            .ip_h3_sender
                            .send(Content::Datagram {
                                payload: data.to_vec(),
                            })
                            .expect("Could not send datagram to ip handler.");
                    }
                }
            } else {
                debug!("received datagram on unknown flow: {}", flow_id)
            }
        }
    }
    match http3_conn.poll(&mut client.conn) {
        Ok((stream_id, quiche::h3::Event::Headers { list: headers, .. })) => {
            info!(
                "{} got request {:?} on stream id {}",
                client.conn.trace_id(),
                hdrs_to_strings(&headers),
                stream_id
            );

            let mut method = None;
            let mut authority = None;
            let mut protocol = None;
            let mut scheme = None;
            let mut path = None;

            // Look for the request's path and method.
            for hdr in headers.iter() {
                match hdr.name() {
                    b":method" => method = Some(hdr.value()),
                    b":authority" => authority = Some(std::str::from_utf8(hdr.value()).unwrap()),
                    b":protocol" => protocol = Some(hdr.value()),
                    b":scheme" => scheme = Some(hdr.value()),
                    b":path" => path = Some(hdr.value()),
                    _ => (),
                }
            }

            match method {
                Some(b"CONNECT") => {
                    if let Some(authority) = authority {
                        if protocol == Some(b"connect-udp") && scheme.is_some() && path.is_some() {
                            let path = path.unwrap();
                            if let Some(peer_addr) = path_to_socketaddr(path) {
                                debug!(
                                    "connecting udp to {} at {} from authority {}",
                                    std::str::from_utf8(&path).unwrap(),
                                    peer_addr,
                                    authority
                                );
                                let http3_sender_clone_1 = http3_sender.clone();
                                let http3_sender_clone_2 = http3_sender.clone();
                                let (udp_sender, udp_receiver) =
                                    mpsc::unbounded_channel::<Vec<u8>>();
                                let flow_id = stream_id / 4;
                                connect_sockets.insert(flow_id, udp_sender);

                                tokio::spawn(async move {
                                    udp_connect_handler(
                                        peer_addr,
                                        stream_id,
                                        flow_id,
                                        http3_sender_clone_1,
                                        http3_sender_clone_2,
                                        udp_receiver,
                                    )
                                    .await;
                                });
                            }
                        } else if protocol == Some(b"connect-ip")
                            && scheme.is_some()
                            && path.is_some()
                           // && !authority.is_empty()
                        {
                            debug!("Got request for connect-ip!");
                            // Check the path
                            let path = path.unwrap();
                            
                            debug!(
                                "connecting ip to {} from authority {}",
                                std::str::from_utf8(&path).unwrap(),
                                //peer_addr,
                                authority
                            );
                            // acquire http3 and TUN sender clones

                            // For sending messages from the ip handler to the http3 sender
                            let http3_sender_clone = http3_sender.clone();

                            // These are for receiving messages from the TUN device
                            let (tun_sender_from, from_tun_receiver) =
                                mpsc::unbounded_channel::<Vec<u8>>();
                                connect_ip_clients.lock().await.insert(next_free_ip.clone(), tun_sender_from);

                            // For sending received http3 messages to the ip connect handler
                            let (ip_http3_sender, ip_http3_receiver) =
                                mpsc::unbounded_channel::<Content>();
                            let flow_id = stream_id / 4;

                            if connect_ip_session.is_some() {
                                debug!("Replacing old IpConnectSession!");
                                {
                                    let ip_session = connect_ip_session.as_ref().unwrap();
                                    if !ip_session
                                        .handler_thread
                                        .as_ref()
                                        .unwrap()
                                        .is_finished()
                                    {
                                        ip_session.handler_thread.as_ref().unwrap().abort();
                                    }
                                }
                            }
                            let _ = std::mem::replace(
                                connect_ip_session,
                                Some(IpConnectSession {
                                    flow_id: flow_id,
                                    stream_id: stream_id,
                                    ip_h3_sender: ip_http3_sender,
                                    handler_thread: None,
                                }),
                            );

                            // spawn handler thread for this one
                            let assigned_ip = next_free_ip.clone();

                            // For sending messages to the TUN device
                            let tun_sender_clone = tun_sender.clone();
                            connect_ip_session.as_mut().unwrap().handler_thread =
                                Some(tokio::spawn(async move {
                                    connect_ip_handler(
                                        stream_id,
                                        flow_id,
                                        http3_sender_clone,
                                        from_tun_receiver,
                                        tun_sender_clone,
                                        ip_http3_receiver,
                                        assigned_ip,
                                    )
                                    .await;
                                }));
                            
                        } else if let Ok(target_url) = if authority.contains("://") {
                            url::Url::parse(authority)
                        } else {
                            url::Url::parse(format!("scheme://{}", authority).as_str())
                        } {
                            debug!(
                                "connecting to url {} from authority {}",
                                target_url, authority
                            );
                            if let Ok(mut socket_addrs) = target_url.to_socket_addrs() {
                                let peer_addr = socket_addrs.next().unwrap();
                                let http3_sender_clone_1 = http3_sender.clone();
                                let http3_sender_clone_2 = http3_sender.clone();
                                let (tcp_sender, tcp_receiver) =
                                    mpsc::unbounded_channel::<Vec<u8>>();
                                connect_streams.insert(stream_id, tcp_sender);

                                tokio::spawn(async move {
                                    tcp_stream_handler(
                                        peer_addr,
                                        target_url,
                                        stream_id,
                                        http3_sender_clone_1,
                                        http3_sender_clone_2,
                                        tcp_receiver,
                                    )
                                    .await;
                                });
                            } else {
                                // TODO: send error
                            }
                        } else {
                            // TODO: send error
                        }
                    } else {
                        // TODO: send error
                    }
                }

                _ => {}
            };
        }

        Ok((stream_id, quiche::h3::Event::Data)) => {
            info!(
                "{} got data on stream id {}",
                client.conn.trace_id(),
                stream_id
            );
            while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                if connect_streams.contains_key(&stream_id) {
                    debug!("got {} bytes of data on stream {}", read, stream_id);
                    trace!("{}", unsafe { std::str::from_utf8_unchecked(&buf[..read]) });
                    let data = &buf[..read];
                    connect_streams
                        .get(&stream_id)
                        .unwrap()
                        .send(data.to_vec())
                        .expect("channel send failed");
                } else if connect_ip_session.is_some() {
                    {
                        let ip_session = connect_ip_session.as_ref().unwrap();
                        if ip_session.stream_id == stream_id {
                            // connect-ip data, must be a capsule
                            debug!(
                                "got {} bytes of data on ip connect stream {}",
                                read, stream_id
                            );
                            let data = &buf[..read];
                            ip_session
                                .ip_h3_sender
                                .send(Content::Data {
                                    data: data.to_vec(),
                                })
                                .expect("channel send failed");
                        }
                    }
                } else {
                    debug!(
                        "received {} bytes of stream data on unknown stream {}",
                        read, stream_id
                    );
                }
            }
        }

        Ok((stream_id, quiche::h3::Event::Finished)) => {
            info!("finished received, stream id: {} closing", stream_id);
            // TODO: do we need to shutdown the stream on our side?
            while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                if connect_streams.contains_key(&stream_id) {
                    debug!("got {} bytes of data on stream {}", read, stream_id);
                    trace!("{}", unsafe { std::str::from_utf8_unchecked(&buf[..read]) });
                    let data = &buf[..read];
                    connect_streams
                        .get(&stream_id)
                        .unwrap()
                        .send(data.to_vec())
                        .expect("channel send failed");
                } else {
                    debug!(
                        "received {} bytes of stream data on unknown stream {}",
                        read, stream_id
                    );
                }
            }
            if connect_ip_clients.lock().await.contains_key(&next_free_ip) {
                // stop the connect_ip_connection
                {
                    let ip_session = connect_ip_session.as_ref().unwrap();
                    ip_session.handler_thread.as_ref().unwrap().abort();
                }
                connect_ip_session.take();
                connect_ip_clients.lock().await.remove(&next_free_ip);
            }
            remove_stream(connect_streams, stream_id, &mut client.conn);
        }

        Ok((stream_id, quiche::h3::Event::Reset(e))) => {
            error!(
                "request was reset by peer with {}, stream id: {} closed",
                e, stream_id
            );
            // TODO: do we need to shutdown the stream on our side?
            while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                if connect_streams.contains_key(&stream_id) {
                    debug!("got {} bytes of data on stream {}", read, stream_id);
                    trace!("{}", unsafe { std::str::from_utf8_unchecked(&buf[..read]) });
                    let data = &buf[..read];
                    connect_streams
                        .get(&stream_id)
                        .unwrap()
                        .send(data.to_vec())
                        .expect("channel send failed");
                } else {
                    debug!(
                        "received {} bytes of stream data on unknown stream {}",
                        read, stream_id
                    );
                }
            }
            if connect_ip_clients.lock().await.contains_key(&next_free_ip) {
                // stop the connect_ip_connection
                {
                    let ip_session = connect_ip_session.as_ref().unwrap();
                    ip_session.handler_thread.as_ref().unwrap().abort();
                }
                connect_ip_session.take();
                connect_ip_clients.lock().await.remove(&next_free_ip);
            }
            remove_stream(connect_streams, stream_id, &mut client.conn);
        }
        Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

        Ok((_goaway_id, quiche::h3::Event::GoAway)) => unreachable!(),

        Err(quiche::h3::Error::Done) => {
            return Err(ClientError::Other(format!("quiche error: Done")));
        }

        Err(e) => {
            error!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);
            return Err(ClientError::Other(format!("HTTP/3 error")));
        }
    }
    Ok(())
}

fn remove_stream(
    connect_streams: &mut HashMap<u64, UnboundedSender<Vec<u8>>>,
    stream_id: u64,
    conn: &mut quiche::Connection,
) {
    debug!("terminating stream {}", stream_id);
    if conn.stream_finished(stream_id) {
        debug!("stream {} finished", stream_id);
    } else {
        conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
            .expect("Couldn't shutdown stream!");
        conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
            .expect("Couldn't shutdown stream!");
    }
    // TODO: Shutting stream down on our side as well?
    /*
    if let Some(sender) = connect_streams.get(&stream_id) {

    }*/
    connect_streams.remove(&stream_id);
    //Ok(())
}

async fn tcp_stream_handler(
    peer_addr: SocketAddr,
    target_url: Url,
    stream_id: u64,
    http3_sender_clone_1: UnboundedSender<ToSend>,
    http3_sender_clone_2: UnboundedSender<ToSend>,
    mut tcp_receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let stream = match TcpStream::connect(peer_addr).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error connecting TCP to {}: {}", peer_addr, e);
            return;
        }
    };
    debug!(
        "connecting to url {} {}",
        target_url,
        target_url.to_socket_addrs().unwrap().next().unwrap()
    );
    let (mut read_half, mut write_half) = stream.into_split();
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
                // TODO: Do we have to tell the client about this?
                break;
            }
            debug!(
                "read {} bytes from TCP from {} for stream {}",
                read, peer_addr, stream_id
            );
            http3_sender_clone_1
                .send(ToSend {
                    stream_id: stream_id,
                    content: Content::Data {
                        data: buf[..read].to_vec(),
                    },
                    finished: false,
                })
                .unwrap_or_else(|e| debug!("Error sending http3 data: {:?}", e));
        }
        http3_sender_clone_1
            .send(ToSend {
                stream_id: stream_id,
                content: Content::Finished,
                finished: true,
            })
            .unwrap_or_else(|e| debug!("Error sending http3 data: {:?}", e));
    });
    let write_task = tokio::spawn(async move {
        loop {
            let data = match tcp_receiver.recv().await {
                Some(v) => v,
                None => {
                    debug!("TCP receiver channel closed for stream {}", stream_id);
                    break;
                }
            };
            trace!("start sending on TCP");
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
    });
    let headers = vec![
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"content-length", b"0"), // NOTE: is this needed?
    ];
    http3_sender_clone_2
        .send(ToSend {
            stream_id,
            content: Content::Headers { headers },
            finished: false,
        })
        .expect("channel send failed");
    match tokio::join!(read_task, write_task) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    };
}

fn set_ip_settings(tun_addr: &String, tun_name: &String) -> Result<(), Box<dyn Error>> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg("dev")
        .arg(tun_name)
        .arg("up")
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to bring up tun0: {:?}", String::from_utf8(output.stderr)).into());
    }

    let output = Command::new("sudo")
        .arg("ip")
        .arg("addr")
        .arg("add")
        .arg(tun_addr)
        .arg("dev")
        .arg(tun_name)
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to assign IP to tun0: {:?}", String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(())
}

fn destroy_tun_interface() {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("delete")
        .arg("tun0")
        .output()
        .expect("Failed to execute command to delete TUN interface");

    if !output.status.success() {
        eprintln!("Failed to delete TUN interface: {}", String::from_utf8_lossy(&output.stderr));
    }
}

/**
 * Creates a TUN socket and sets it up in the system.
 * Will then create a writer and a reader thread which are connected to channels.
 */
async fn tun_socket_handler(
    ip_handlers: Arc<Mutex<HashMap<Ipv4Addr, UnboundedSender<Vec<u8>>>>>,
    mut tun_sender: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    tun_addr: String, tun_name: String
) {
    // first create tun socket
    let mut config = tun2::Configuration::default();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    config.tun_name(&tun_name);

    let dev = tun2::create(&config);
    set_ip_settings(&tun_addr, &tun_name)
        .unwrap_or_else(|e| panic!("Error setting up TUN: {e}"));
    

    let (mut reader, mut writer) = dev.unwrap().split();
    // create reader thread
    // Reads from the TUN device and sends messages to connect_ip handler(s)
    let read_t = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let size = reader.read(&mut buf).expect("Could not read from reader");
            let pkt = &buf[..size];
            // parse packet to get destination ip
            // then send it to handler for dest ip
            if let Ok(ip_pkt) = Packet::new(&pkt[..size]) {
                if let Some(ip_handler_) = ip_handlers.lock().await.get(&ip_pkt.destination()) {
                    ip_handler_
                        .send(pkt.to_vec())
                        .expect("Could not send a message to ip handler channel!");
                }
            }
        }
    });

    // create writer thread
    // Waits for messages from the connect_ip handler(s) and sends them via TUN device
    let write_t = tokio::spawn(async move {
        loop {
            if let Some(pkt) = tun_sender.recv().await {
                // TODO: For now we make sure to only send ipv4 packets
                // Get the version by looking at the first nibble
                let version = pkt[0].reverse_bits() & 0b00001111;
                if version == 4 {
                    // All is okay, send the packet to the TUN interface
                    // call write as long as needed to send the entire packet
                    let mut pos = 0;
                    while pos <= pkt.len() {
                        let written = match writer.write(&pkt[pos..]) {
                            Ok(n) => n,
                            Err(e) => {
                                if e.kind() == ErrorKind::Interrupted {
                                    0
                                } else {
                                    panic!("Could not write to TUN device: {e}");
                                }
                            }
                        };
                        pos += written;
                    }
                } else if version == 6 {
                    debug!("TUN Writer Received ipv6 packet, ignoring for now...");
                } else {
                    error!(
                        "TUN Writer received ip packet of unknown version: {}",
                        version
                    );
                }
            }
        }
    });
    match tokio::join!(read_t, write_t) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    }
    let _ = destroy_tun_interface();
}

async fn connect_ip_handler(
    stream_id: u64,
    flow_id: u64,
    http3_sender: UnboundedSender<ToSend>,
    mut tun_receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    tun_sender: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    mut http3_receiver: tokio::sync::mpsc::UnboundedReceiver<Content>,
    assigned_ip: Ipv4Addr,
) {
    debug!("Creating new IP connect handler!");
    let http3_sender_clone_1 = http3_sender.clone();
    let http3_sender_clone_2 = http3_sender.clone();
    let http3_sender_clone_3 = http3_sender.clone();

    let read_task = tokio::spawn(async move {
        loop {
            // Check for packets in the tun receiver
            // This receiver gets packets from the TUN interface that are supposed to be tunnelled
            // to the proxy client.
            // The packets are confirmed to be ipv4 packets so we don't need to worry about anything.
            // Just create the http3 datagram and send the packet.
            if let Some(pkt) = tun_receiver.recv().await {
                let to_send = encapsulate_ipv4(pkt, &flow_id);

                http3_sender_clone_1
                    .send(to_send)
                    .expect("Could not send datagram to http3 sender!");
            }
        }
    });

    let write_task = tokio::spawn(async move {
        loop {
            // Check for packets in the http3 receiver
            // This receiver gets datagram bodies (which are just ip packets) from the client proxy
            // and handles them (sends them to the TUN interface)
            if let Some(pkt) = http3_receiver.recv().await {
                match pkt {
                    Content::Request { headers: _, stream_id_sender: _ } => unreachable!(),
                    Content::Headers { headers: _ } => unreachable!(),
                    Content::Data { data } => {
                        // Parse and handle received capsule
                        let cap = match Capsule::new(&data) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Ignoring invalid capsule: {e}");
                                continue;
                            }
                        };
                        match cap.capsule_type {
                            CapsuleType::AddressAssign(_) => {
                                debug!("Got ADDRESS_ASSIGN capsule, ignoring...");
                            }
                            CapsuleType::AddressRequest(c) => {
                                // TODO: Very basic capsule handling, can be improved in the future
                                //       This_works_for_now.txt
                                debug!("Got ADDRESS_REQUEST capsule, sending ADDRESS_ASSIGN...");
                                let addr = AssignedAddress {
                                    request_id: c.requested[0].request_id,
                                    ip_version: 4,
                                    ip_address: IpLength::V4(assigned_ip.into()),
                                    ip_prefix_len: 16,
                                };
                                let req_inner_cap = AddressAssign {
                                    length: 9,
                                    assigned_address: vec![addr],
                                };
                                let req_cap = Capsule {
                                    capsule_id: ADDRESS_ASSIGN_ID,
                                    capsule_type: CapsuleType::AddressAssign(req_inner_cap),
                                };
                                let mut cap_buf = [0; 9];
                                req_cap.serialize(&mut cap_buf);
                                http3_sender_clone_2
                                    .send(ToSend {
                                        stream_id: stream_id,
                                        content: Content::Data {
                                            data: cap_buf.to_vec(),
                                        },
                                        finished: false,
                                    })
                                    .expect("Could not send to http3 channel..");
                            }
                            CapsuleType::RouteAdvertisement(_) => todo!(),
                        }
                    }
                    Content::Datagram { payload } => {
                        // just send the datagram
                        let test_pkt = payload.clone();
                        match ip::Packet::new(test_pkt) {
                            Ok(ip::Packet::V4(v)) => {
                                debug!("Received IPv4 packet via http3");
                                if !v.is_valid() {
                                    debug!("Received invalid ipv4 packet, discarding..");
                                    continue;
                                }
                                tun_sender
                                    .send(payload)
                                    .expect("Wasn't able to send ip packet to tun handler");
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
                    Content::Finished => unreachable!(), //TODO: Maybe we can actually use this to terminate connections?
                }
            }
        }
    });

    debug!("Sending back ok to the client!");
    let headers = vec![quiche::h3::Header::new(b":status", b"200")];
    http3_sender_clone_3
        .send(ToSend {
            stream_id,
            content: Content::Headers { headers },
            finished: false,
        })
        .expect("channel send failed");
    match tokio::join!(read_task, write_task) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    };
}

async fn udp_connect_handler(
    peer_addr: SocketAddr,
    stream_id: u64,
    flow_id: u64,
    http3_sender_clone_1: UnboundedSender<ToSend>,
    http3_sender_clone_2: UnboundedSender<ToSend>,
    mut udp_receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(v) => v,
        Err(e) => {
            error!("Error binding UDP socket: {:?}", e);
            return;
        }
    };
    if socket.connect(peer_addr).await.is_err() {
        error!("Error connecting to UDP {}", peer_addr);
        return;
    };
    let peer_addr_clone = peer_addr.clone();
    let socket = Arc::new(socket);
    let socket_clone = socket.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = [0; 65527]; // max length of UDP Proxying Payload, ref: https://www.rfc-editor.org/rfc/rfc9298.html#name-http-datagram-payload-forma
        loop {
            let read = match socket_clone.recv(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Error reading from UDP {} on stream id {}: {}",
                        peer_addr_clone, stream_id, e
                    );
                    break;
                }
            };
            if read == 0 {
                debug!("UDP connection closed from {}", peer_addr_clone); // do we need this check?
                break;
            }
            debug!(
                "read {} bytes from UDP from {} for flow {}",
                read, peer_addr_clone, flow_id
            );
            let data = wrap_udp_connect_payload(0, &buf[..read]);
            http3_sender_clone_1
                .send(ToSend {
                    stream_id: flow_id,
                    content: Content::Datagram { payload: data },
                    finished: false,
                })
                .unwrap_or_else(|e| debug!("Sending udp connect payload to clone failed: {:?}", e));
        }
    });

    let peer_addr_clone_2 = peer_addr.clone();
    let write_task = tokio::spawn(async move {
        loop {
            let data = match udp_receiver.recv().await {
                Some(v) => v,
                None => {
                    debug!("UDP receiver channel closed for flow {}", flow_id);
                    break;
                }
            };
            let (context_id, payload) = decode_var_int(&data);
            assert_eq!(
                context_id, 0,
                "received UDP Proxying Datagram with non-zero Context ID"
            );

            trace!("start sending on UDP");
            let bytes_written = match socket.send(payload).await {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Error writing to UDP {} on flow id {}: {}",
                        peer_addr_clone_2, flow_id, e
                    );
                    return;
                }
            };
            if bytes_written < payload.len() {
                debug!(
                    "Partially sent {} bytes of UDP packet of length {}",
                    bytes_written,
                    payload.len()
                );
            }
            debug!(
                "written {} bytes from UDP to {} for flow {}",
                payload.len(),
                peer_addr_clone_2,
                flow_id
            );
        }
    });
    let headers = vec![quiche::h3::Header::new(b":status", b"200")];
    http3_sender_clone_2
        .send(ToSend {
            stream_id,
            content: Content::Headers { headers },
            finished: false,
        })
        .expect("channel send failed");
    match tokio::join!(read_task, write_task) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    };
}
