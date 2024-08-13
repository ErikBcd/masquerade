use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;
use std::u64;

use log::*;
use octets::varint_len;
use packet::ip;
use quiche::h3::NameValue;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time::{self, sleep};
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
    pub stream_sender: Option<UnboundedSender<Content>>,
    pub stream_id: Option<u64>,
    pub flow_id: Option<u64>,
}

/**
 * Infos about the CONNECT-IP session
 * Includes converters for local ip's to destination ip's (and the other way around)
 */
pub struct ConnectIpInfo {
    pub stream_id: u64,
    pub flow_id: u64,
    pub assigned_ip: Ipv4Addr,
}

pub struct IpMessage {
    pub message: Vec<u8>,
    pub dir: Direction,
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

/**
 * Receives raw IP messages from a TUN.
 * Will send received messages to the ip_handler_t
 * Arguments:
 *  - ip_handler: Channel that handles received ip messages
 *  - reader: Receiver for raw ip messages
 */
pub async fn ip_receiver_t(
    ip_handler: UnboundedSender<IpMessage>,
    mut reader: Reader, //
) {
    debug!("Started ip_receiver thread!");
    let mut buf = [0; 4096];
    loop {
        let size = reader.read(&mut buf).expect("Could not read from reader");
        //debug!("Read TUN message size {size}");
        let pkt = &buf[..size];
        use std::io::{Error, ErrorKind::Other};
        match ip_handler
            .send(IpMessage {
                message: pkt.to_vec(),
                dir: Direction::ToServer,
            })
            .map_err(|e| Error::new(Other, e))
        {
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
    mut ip_recv: UnboundedReceiver<IpMessage>, // Other side is ip_receiver_t
    mut conn_info_recv: UnboundedReceiver<ConnectIpInfo>, // Other side is quic_handler_t
    quic_dispatch: UnboundedSender<ToSend>,    // other side is quic_dispatcher_t
    ip_dispatch: UnboundedSender<Vec<u8>>,     // other side is ip_dispatcher_t
) {
    debug!("Started ip_handler thread!");
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

/**
 * Creates a ToSend struct for sending IP from a given IP packet and stream_id
 */
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
pub async fn ip_dispatcher_t(mut rx: UnboundedReceiver<Vec<u8>>, mut writer: Writer) {
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
// TODO: Handle incoming capsules, send ip information out once we have it (Address Assign etc)
pub async fn quic_conn_handler(
    ip_sender: UnboundedSender<IpMessage>, // other side is ip_dispatcher_t
    info_sender: UnboundedSender<ConnectIpInfo>, // other side is the ip_handler_t
    http3_sender: UnboundedSender<ToSend>, // Other side is the quic_dispatcher_t
    http3_receiver: &mut UnboundedReceiver<ToSend>,
    mut conn: Connection,
    udp_socket: UdpSocket,
) {
    debug!("quic_conn_handler active!");
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let http3_conn_temp: Arc<Mutex<Option<quiche::h3::Connection>>> =
        Arc::new(Mutex::new(None));
    let mut http3_conn: Option<quiche::h3::Connection> = None;

    let stream: Arc<Mutex<QuicStream>> = Arc::new(Mutex::new(
        QuicStream { stream_sender: None, stream_id: None, flow_id: None }
    ));

    let mut assigned_addr: Option<Ipv4Addr> = None;
    let mut got_ip_addr = false;

    //let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
    let mut http3_retry_send: Option<ToSend> = None;

    let mut interval = time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        debug!("Loop start!");
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
                // If this is a valid ipv4 packet
                let header_len = varint_len(flow_id) + varint_len(context_id);
                match ip::Packet::new(buf[header_len..len].to_vec().as_slice()) {
                    Ok(ip::Packet::V4(v)) => {
                        debug!("Received IPv4 packet via http3");
                        // Check if the ip packet was valid first, if not we discard of it
                        if !v.is_valid() {
                            debug!("Received invalid ipv4 packet, discarding..");
                            continue;
                        }
                        match ip_sender.send(IpMessage {
                            message: buf[header_len..len].to_vec(),
                            dir: Direction::ToClient,
                        }) {
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

        tokio::select! {
            // handle QUIC received data
            recvd = udp_socket.recv_from(&mut buf) => {
                let (read, from) = match recvd {
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
                debug!("a processed {} bytes", read);
                if let Some(http3_conn) = &mut http3_conn {
                    loop {
                        debug!("polling on http3 connection");
                        match http3_conn.poll(&mut conn) {
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
                                let mut incoming: Vec<u8> = Vec::new();
                                let mut pos = 0;
                                while let Ok(read) = http3_conn_temp
                                    .lock()
                                    .await
                                    .as_mut()
                                    .unwrap()
                                    .recv_body(&mut conn, stream_id, &mut buf)
                                {
                                    incoming.extend_from_slice(&buf[0..read]);
                                    pos += read;
                                }
                                // Finished reading data
                                if pos == incoming.len() {
                                    // we only receive capsules via data, so parse this capsule
                                    let parsed = match Capsule::new(&incoming) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            debug!("Couldn't parse capsule: {}", e);
                                            break;
                                        }
                                    };
                                    match parsed.capsule_type {
                                        crate::ip_connect::capsules::CapsuleType::AddressAssign(c) => {
                                            // TODO: Check if this packet is correctly structured
                                            //       Potentially we also want to make sure that we can
                                            //       change our own IP later and notify clients about it?
                                            //       Also: See if we can use the other values like the prefix
                                            //       This should not be used like this in prod
                                            if let IpLength::V4(ipv4) = c.assigned_address[0].ip_address {
                                                assigned_addr = Some(Ipv4Addr::from(ipv4));
                                                if !got_ip_addr {
                                                    // Send assigned ip to ip handler
                                                    let ci = ConnectIpInfo {
                                                        assigned_ip: assigned_addr.unwrap(),
                                                        flow_id: stream.as_ref().lock().await.flow_id.unwrap(),
                                                        stream_id: stream.as_ref().lock().await.stream_id.unwrap(),
                                                    };
                                                    info_sender.send(ci)
                                                        .expect("Could not send connect ip info to ip handler.");
                                                    got_ip_addr = true;
                                                }
                                            } else {
                                                panic!("Received an ipv6 address even tho we only allow ipv4");
                                            }
                                        },
                                        crate::ip_connect::capsules::CapsuleType::AddressRequest(_) => {
                                            // We should not be receiving this one.
                                        },
                                        crate::ip_connect::capsules::CapsuleType::RouteAdvertisement(_) => {

                                        },
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
                                todo!();
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
                    };
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
                            // TODO: Signal that stream is lost
                            todo!();
                        }
                    };
                    to_send = match http3_receiver.try_recv() {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                }

            },
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
                        // TODO: Signal that stream is ended
                        http3_retry_send = None;
                        todo!()
                    }
                };
            }
        }

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            debug!("Establishing h3 conn!");
            let h3_config = quiche::h3::Config::new().unwrap();
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );

            // now we can create the ip connect stream 
            let stream_clone = stream.clone();
            let http3_sender_clone = http3_sender.clone();
            let _ip_connect_thread = tokio::spawn(
                async move {
                    handle_ip_connect_stream(http3_sender_clone, stream_clone).await;
                }
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
            match udp_socket.send_to(&out[..write], send_info.to).await {
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
    debug!("quic conn handler exiting.")
}

/**
 * Initiates the CONNECT-IP request.
 */
async fn handle_ip_connect_stream(
    http3_sender: UnboundedSender<ToSend>,
    stream: Arc<Mutex<QuicStream>>,
) {
    // We only need to establish the connect-ip thing first
    debug!("Trying to establish connect-ip!");
    let headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"), // TODO: Should always be https?
        quiche::h3::Header::new(b":authority", b""),   // TODO
        quiche::h3::Header::new(b"path", b"/.well-known/masque/ip/*/*/"),
        quiche::h3::Header::new(b"connect-ip-version", b"3"),
    ];
    let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
    let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();

    http3_sender.send(ToSend {
        stream_id: u64::MAX,
        content: Content::Request {
            headers: headers,
            stream_id_sender,
        },
        finished: false,
    }).unwrap_or_else(|e| error!("Could not send http3 request to http3_receiver in QUIC handler: {e}"));

    let stream_id = stream_id_receiver
        .recv()
        .await
        .expect("Stream id receiver failed us all.");
    {
        let mut stream = stream.lock().await;
        stream.stream_id = Some(stream_id);
        stream.flow_id = Some(stream_id / 4);
        stream.stream_sender = Some(response_sender);
    }

    // Now wait for response

    let response = response_receiver
        .recv()
        .await
        .expect("http3 response receiver error");

    let mut succeeded = false;
    if let Content::Headers { headers } = response {
        info!("Got response for connect-ip request: {:?}", hdrs_to_strings(&headers));
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
                        info!("connect-ip established, sending ip request!");

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
                                stream_id: stream.lock().await.stream_id.unwrap(),
                                content: Content::Data { data: buf.to_vec() },
                                finished: false,
                            })
                            .unwrap_or_else(|e| error!("sending http3 data capsule failed: {:?}", e));
                        // the quic handler should do the rest
                        succeeded = true;
                    }
                }
            }
        }
    } else {
        error!("Didn't receive a header when waiting for response!");
    }

    if !succeeded {
        // TODO: We should inform the quic thread about this
        todo!()
    }
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
    conn: Arc<Mutex<Connection>>,
) {
    // First wait for the connection info the QUIC handler provides
    // With that you can exchange ip's and everything
    // Wait till the QUIC server sends us connection information
    let mut http3_conn: Option<Arc<Mutex<Option<quiche::h3::Connection>>>> = None;
    while http3_conn.is_none() {
        http3_conn = quic_sender_recv.recv().await;
    }
    let http3_conn = http3_conn.unwrap();
    let mut to_send_queue: VecDeque<ToSend> = VecDeque::new();
    loop {
        if let Some(pkt) = rx.recv().await {
            debug!("Received message to send to QUIC!");
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
                        let conn_clone = conn.clone();
                        let mut conn_clone = conn_clone.lock().await;
                        match http3_conn.lock().await.as_mut().unwrap().send_request(
                            conn_clone.deref_mut(),
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
                            let conn_clone = conn.clone();
                            let mut conn_clone = conn_clone.lock().await;
                            match http3_conn.lock().await.as_mut().unwrap().send_body(
                                conn_clone.deref_mut(),
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
                        let conn_clone = conn.clone();
                        let mut conn_clone = conn_clone.lock().await;
                        match send_h3_dgram(conn_clone.deref_mut(), pkt.stream_id, &payload) {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.into()),
                        }
                    }
                    Content::Finished => {
                        debug!("Shutting down stream!");
                        match conn.lock().await.stream_shutdown(
                            pkt.stream_id,
                            quiche::Shutdown::Read,
                            0,
                        ) {
                            Ok(_) => {}
                            Err(quiche::Error::Done) => {}
                            Err(e) => {
                                error!("could not shutdown stream: {}", e);
                            }
                        }

                        match conn.lock().await.stream_shutdown(
                            pkt.stream_id,
                            quiche::Shutdown::Write,
                            0,
                        ) {
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
                            conn.lock().await.trace_id(),
                            pkt.stream_id
                        );
                        to_send_queue.push_front(pkt);
                        break;
                    }
                    Err(e) => {
                        error!(
                            "Connection {} stream {} send failed {:?}",
                            conn.lock().await.trace_id(),
                            pkt.stream_id,
                            e
                        );
                        if !conn.lock().await.stream_finished(pkt.stream_id) {
                            conn.lock()
                                .await
                                .stream_shutdown(pkt.stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                            conn.lock()
                                .await
                                .stream_shutdown(pkt.stream_id, quiche::Shutdown::Write, 0)
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
    pub async fn run(&self, server_addr: &String) {
        // 1) Create QUIC connection, connect to server
        let mut socket = match self.get_udp(server_addr).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create udp socket: {}", e);
                return;
            }
        };
        debug!("Created UDP socket");
        let quic_conn = match self.create_quic_conn(&mut socket, server_addr).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create quic connection: {}", e);
                return;
            }
        };
        debug!("Created QUIC connection");

        // We need two connections in different threads, so we put it in a Arc<Mutex<>>
        //let quic_conn = Arc::new(Mutex::new(quic_conn));
        // 2) Setup Connect IP stream

        // 3) Create TUN
        let dev = match self.create_tun() {
            Ok(v) => v,
            Err(e) => {
                error!("could not create TUN: {}", e);
                return;
            }
        };

        let (reader, writer) = dev.split();

        // 4) Create receivers/senders

        // ip_sender for ip_receiver_t, ip_recv for ip_handler_t
        let (ip_sender, ip_recv) = tokio::sync::mpsc::unbounded_channel();
        let (quic_dispatch, mut quic_dispatch_reader) = tokio::sync::mpsc::unbounded_channel();
        let (ip_dispatch, ip_dispatch_reader) = tokio::sync::mpsc::unbounded_channel();
        let (conn_info_sender, conn_info_recv) = tokio::sync::mpsc::unbounded_channel();

        // Copies of senders
        let ip_from_quic_sender = ip_sender.clone();
        let http3_sender = quic_dispatch.clone();

        debug!("Starting threads!");

        let ip_recv_t = tokio::spawn(async move {
            ip_receiver_t(ip_sender, reader).await;
        });

        let ip_h_t = tokio::spawn(async move {
            ip_handler_t(ip_recv, conn_info_recv, quic_dispatch, ip_dispatch).await;
        });

        let ip_disp_t = tokio::spawn(async move {
            ip_dispatcher_t(ip_dispatch_reader, writer).await;
        });

        let quic_h_t = tokio::spawn(async move {
            quic_conn_handler(
                ip_from_quic_sender,
                conn_info_sender,
                http3_sender,
                &mut quic_dispatch_reader,
                quic_conn,
                socket,
            )
            .await;
        });

        while !ip_recv_t.is_finished()
            && !ip_h_t.is_finished()
            && !ip_disp_t.is_finished()
            && !quic_h_t.is_finished()
        //&& !quic_disp_t.is_finished()
        {
            sleep(Duration::from_millis(10)).await;
        }
        // gracefully exit
        if !ip_recv_t.is_finished() {
            ip_recv_t.abort();
        }

        if !ip_h_t.is_finished() {
            ip_h_t.abort();
        }

        if !ip_disp_t.is_finished() {
            ip_disp_t.abort();
        }

        if !quic_h_t.is_finished() {
            quic_h_t.abort();
        }
        debug!("ConnectIPClient exiting..");
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
                trace!(
                    "{} -> {}: send() would block",
                    udp_socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }

            panic!("send() failed: {e:?}");
        }
        debug!("written {}", write);

        loop {
            let (write, send_info) = match connection.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("QUIC connection {} done writing", connection.trace_id());
                    break;
                }

                Err(e) => {
                    error!(
                        "QUIC connection {} send failed: {:?}",
                        connection.trace_id(),
                        e
                    );

                    connection.close(false, 0x1, b"fail").ok();
                    break;
                }
            };
            debug!("!!!!");
            match udp_socket.send_to(&out[..write], send_info.to).await {
                Ok(written) => debug!(
                    "{} written {} bytes out of {}",
                    connection.trace_id(),
                    written,
                    write
                ),
                Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
            }
        }

        while connection.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if connection.new_scid(&scid, reset_token, false).is_err() {
                break;
            }
        }

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
