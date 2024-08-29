use quiche;
use ring::rand::*;

use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time;

use log::*;

use crate::common::*;

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

pub struct Client {
    pub listener: Option<TcpListener>,
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
        config.set_initial_max_streams_bidi(1000);
        config.set_initial_max_streams_uni(1000);
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
                                        if conn.stream_finished(stream_id) {
                                            debug!("stream {} finished", stream_id);
                                        } else {
                                            conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                                                .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
                                        }
                                        connect_streams.remove(&stream_id);
                                    }
                                },

                                Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                    error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {})
                                            .unwrap_or_else(|e| error!("Could not send finish stream data: {:?}", e));
                                        
                                        if conn.stream_finished(stream_id) {
                                            debug!("stream {} finished", stream_id);
                                        } else {
                                            conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                                                .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
                                        }
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
                                if conn.stream_finished(to_send.stream_id) {
                                    debug!("stream {} finished", to_send.stream_id);
                                    Ok(())
                                } else {
                                    conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0)
                                        .unwrap_or_else(|e| error!("A stream shutdown read failed: {:?}", e));
                                    match conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("stream shutdown failed: {}", e);
                                            Ok(()) // ignore the error
                                        }
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
                                let mut connect_streams = connect_streams.lock().unwrap();
                                connect_streams.remove(&to_send.stream_id);
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
                            conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
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
