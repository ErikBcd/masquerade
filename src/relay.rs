// Base notes:
//  * Relay has one incoming and one outgoing connection
//  * Takes packets from incoming conn and sends to outgoing
//  * (also vice-versa, bidirectional)
//  * First connects to the specified server on a specified port,
//  * and then waits for a client connection on a specified port
//  * -> Client can be another relay

use log::*;

use std::collections::HashMap;
use std::error::Error;
use std::net::ToSocketAddrs;
use std::net::{self, SocketAddr};

use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::{self, Duration};

use ring::rand::*;

use crate::common::*;

// TODO: Copied code from client, if this works out we can put it in common
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

struct QuicReceived {
    recv_info: quiche::RecvInfo,
    data: Vec<u8>,
}

/**
 * Client for each QUIC connection
 */
struct Client {
    conn: quiche::Connection,
    quic_receiver: mpsc::UnboundedReceiver<QuicReceived>,
    socket: Arc<UdpSocket>,
}

#[derive(Debug)]
pub struct Relay {
    socket: Option<Arc<UdpSocket>>,
}

impl Relay {
    pub fn new() -> Relay {
        Relay { socket: None }
    }
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

    /**
     *  Runs this server relay.
     *  
     *  What a relay does: It acts as an intermediary between a sender and a server, e.g.
     *  a masquerade client and a masquerade (endpoint) server.
     *  As such it will only receive QUIC messages, unpack them and then create a new QUIC message
     *  and send it forth.
     *  This way the sender will never know the next server in the chain.
     *
     *  WARN: This is very much experimental.
     */
    pub async fn run(&mut self, server_addr: &String) -> Result<(), Box<dyn Error>> {
        // connect to predefined outgoing clients first, then
        // start accepting new clients & send messages back and forth
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

        // Connect to next server
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

        // Now get ready for an incoming connection
        let mut client: Option<Client> = None;

        loop {
            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }

            if client.is_none() {
                todo!("");
                // TODO: implement behaviour if no client is connected
                // Wait for new connection
            } else if client.unwrap_or_else("").conn.is_closed() {
                todo!("");
                // TODO: implement behaviour if no client is connected
                // Wait for new connection
            }
            tokio::select! {
                // handle QUIC received data
                recvd = socket.recv_from(&mut buf) => {
                    let (read, from) = match recvd {
                        Ok(v) => v,
                        Err(e) => {
                            error!("error when reading from UDP socket");
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
                                        sender.send(Content::Headers { headers: list });
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    debug!("received stream data");
                                    let connect_streams = connect_streams.lock().unwrap();
                                    while let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                                        if let Some(sender) = connect_streams.get(&stream_id) {
                                            debug!("got {} bytes of response data on stream {}", read, stream_id);
                                            trace!("{}", unsafe {std::str::from_utf8_unchecked(&buf[..read])});
                                            sender.send(Content::Data { data: buf[..read].to_vec() });
                                        } else {
                                            debug!("received {} bytes of stream data on unknown stream {}", read, stream_id);
                                        }
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Finished)) => {
                                    info!("finished received, stream id: {} closing", stream_id);
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {});
                                        connect_streams.remove(&stream_id);
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                    error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {});
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
                            }
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
                                debug!("sending http3 request {:?}", hdrs_to_strings(&headers));
                                match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                    Ok(stream_id) => {
                                        stream_id_sender.send(stream_id).await;
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
                                            error!("sending http3 datagram failed!");
                                            break;
                                        }
                                    }
                                //http3_conn.send_dgram(&mut conn, to_send.stream_id, &payload)
                            },
                            Content::Finished => {
                                debug!("shutting down stream");
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0);
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
                                error!("OH NO! Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                                panic!("TEMPORARY PANIC");
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0);
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                                {
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    connect_streams.remove(&to_send.stream_id);
                                }
                            }
                        };
                        to_send = match http3_receiver.try_recv() {
                            Ok(v) => v,
                            Err(e) => break,
                        };
                    }
                },
                // Accept a new QUIC connection

            }
        }

        Ok(())
    }

    async fn wait_for_client(&self, &local_addr: &SocketAddr) -> Option<Client> {
        let socket = self.socket.clone().unwrap();

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let mut client: Option<Client> = None;

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
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000); 
        config.enable_early_data();
    
        let rng = SystemRandom::new();
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
        
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
            let conn_id: [u8] = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let tx = {
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

                client = Some(Client {
                    conn,
                    quic_receiver: rx,
                    socket: socket.clone(),
                });
                //clients.insert(scid.clone(), tx);

                //tokio::spawn(async move { handle_client(client).await });

                //clients.get(&scid).unwrap()
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
                    client = None;
                }
            }
        }

        None
    }
}
