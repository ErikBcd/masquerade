use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::*;
use octets::varint_len;
use quiche::h3::NameValue;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time::{self};
use tun2::AsyncDevice;

use crate::common::*;
use crate::ip_connect::capsules::{
    AddressRequest, Capsule, CapsuleType, IpLength, RequestedAddress, ADDRESS_REQUEST_ID
};
use crate::ip_connect::util::*;

const MAX_CHANNEL_MSG: usize = 50;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub server_name: Option<String>,
    pub tun_addr: Option<String>,
    pub tun_name: Option<String>,
    pub tun_gateway: Option<String>,
}

impl std::fmt::Display for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "server_name  = {:?}\n
            tun_addr     = {:?}\n
            tun_name     = {:?}\n
            tun_gateway  = {:?}\n
            ",
            self.server_name, self.tun_addr, self.tun_name, self.tun_gateway
        )
    }
}

/// 
/// Information about packets, wether they are
/// to be sent to the server or to the client.
/// Generally, packets that were received from the server (from the QUIC connection)
/// are labeled as ToClient, and packets from the TUN device as ToServer
/// 
#[derive(Debug)]
pub enum Direction {
    ToServer,
    ToClient,
}

///
/// Useful for holding some basic data for a HTTP3 Stream
/// 
pub struct QuicStream {
    pub stream_sender: Option<UnboundedSender<Content>>,
    pub stream_id: Option<u64>,
    pub flow_id: Option<u64>,
}

/// 
/// Infos about the CONNECT-IP session
/// Includes converters for local ip's to destination ip's (and the other way around)
/// 
#[derive(Clone, Copy)]
pub struct ConnectIpInfo {
    pub stream_id: u64,
    pub flow_id: u64,
    pub assigned_ip: Ipv4Addr,
}

///
/// Holds an ip packet and its direction
/// 
struct IpMessage {
    message: Vec<u8>,
    dir: Direction,
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

/// Basic commands for setting up the TUN interface
/// Should in the end take all traffic on the device and tunnel it.
fn set_client_ip_and_route(dev_addr: &String, tun_gateway: &String, tun_name: &String) {
    let ip_output = Command::new("ip")
        .args(["addr", "add", dev_addr, "dev", tun_name])
        .output()
        .expect("Failed to execute IP command");

    if !ip_output.status.success() {
        error!(
            "Failed to set IP: {}",
            String::from_utf8_lossy(&ip_output.stderr)
        );
        return;
    }

    let link_output = Command::new("ip")
        .args(["link", "set", "up", "dev", tun_name])
        .output()
        .expect("Failed to execute IP LINK command");

    if !link_output.status.success() {
        eprintln!(
            "Failed to set link up: {}",
            String::from_utf8_lossy(&link_output.stderr)
        );
        return;
    }

    let route_output = Command::new("ip")
        .args(["route", "add", "0.0.0.0/0", "via", tun_gateway, "dev", tun_name])
        .output()
        .expect("Failed to execute first IP ROUTE command");

    if !route_output.status.success() {
        eprintln!(
            "Failed to set route 0.0.0.0 to tun device: {}",
            String::from_utf8_lossy(&route_output.stderr)
        );
    }

    // sudo iptables -t nat -A POSTROUTING -o tunMC -j MASQUERADE
    let iptables = Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", tun_name, "-j", "MASQUERADE"])
        .output()
        .expect("Failed to execute ip tables cmd");
    if !iptables.status.success() {
        error!("Failed to set up iptables: {}", String::from_utf8_lossy(&iptables.stderr));
    }

    // Allow ipv4 proxying
    // sudo sysctl -w net.ipv4.conf.all.forwarding=1
    let sysctl_cmd = Command::new("sysctl")
        .args(["-w", "net.ipv4.conf.all.forwarding=1"])
        .output()
        .expect("Failed to execute sysctl command!");
    if !sysctl_cmd.status.success() {
        error!("Failed to allow ipv4 forwarding: {}", String::from_utf8_lossy(&sysctl_cmd.stderr));
    }
}

/// 
/// Receives raw IP messages from a TUN.the
/// Will send received messages to the ip_handler_t
/// Arguments:
///  * ip_handler: Channel that handles received ip messages
///  * reader: Receiver for raw ip messages
/// 
async fn ip_receiver_t(
    ip_handler: Sender<IpMessage>,
    mut reader: ReadHalf<AsyncDevice>, 
) {
    debug!("[ip_receiver_t] Started ip_receiver thread!");
    let mut buf = [0; 4096];
    loop {
        let size = reader
            .read(&mut buf)
            .await
            .expect("[ip_receiver_t] Could not read from reader");
        debug!("[ip_receiver_t] Read TUN message size {size}");
        let pkt = &buf[..size];
        use std::io::{Error, ErrorKind::Other};
        match ip_handler
            .send(IpMessage {
                message: pkt.to_vec(),
                dir: Direction::ToServer,
            })
            .await
            .map_err(|e| Error::new(Other, e))
        {
            Ok(()) => {
                debug!("[ip_receiver_t] Sent packet to receiver.")
            }
            Err(e) => {
                debug!("[ip_receiver_t] tx send error: {}", e);
            }
        }
    }
}

/// 
/// Receives IP Packets from rx.
/// Will then handle these packets accordingly and send messages to quic_dispatcher_t
/// 
async fn ip_handler_t(
    mut ip_recv: Receiver<IpMessage>, // Other side is ip_receiver_t
    mut conn_info_recv: Receiver<ConnectIpInfo>, // Other side is quic_handler_t
    http3_dispatch: Sender<ToSend>,   // other side is quic_dispatcher_t
    ip_dispatch: Sender<Vec<u8>>,     // other side is ip_dispatcher_t
    device_addr: Ipv4Addr,
) {
    debug!("[ip_handler_t] Started ip_handler thread!");
    // Wait till the QUIC server sends us connection information
    let mut conn_info: Option<ConnectIpInfo> = None;
    if let Some(info) = conn_info_recv.recv().await {
        conn_info = Some(info);
    }
    let conn_info = conn_info.unwrap();
    debug!("[ip_handler_t] Received connection info!");
    println!("Connected to server! Assigned IP: {}", conn_info.assigned_ip);
    loop {
        debug!("[ip_handler_t] Waiting for new packet..");
        debug!(
            "[ip_handler_t] Currently {} packets in queue",
            ip_recv.len()
        );

        if let Some(pkt) = ip_recv.recv().await {
            debug!(
                "[ip_handler_t] Received a packet in direction: {:?}",
                pkt.dir
            );
            let http3_dispatch_clone = http3_dispatch.clone();
            let ip_disp_clone = ip_dispatch.clone();
            let ip_addr_clone = device_addr;
            ip_message_handler(
                pkt,
                http3_dispatch_clone,
                ip_disp_clone,
                conn_info,
                ip_addr_clone,
            )
            .await;
            
        }
        debug!("[ip_handler_t] Handled a packet!");
    }
}

///
/// Handles ip messages received by either the QUIC connection
/// or the TUN device.
/// 
/// Arguments:
///     - pkt: The IP Message
///     - http3_dispatch: Channel that is connected to the quic connection handler
///     - ip_dispatch: Channel that is connected to the ip dispatcher
///     - conn_info: Information about the connection, 
///                  used for setting the ToServer IP and the flow ID for the h3 datagram
///     - device_addr: The local device address, used for correcting the IP for ToClient packets
async fn ip_message_handler(
    mut pkt: IpMessage,
    http3_dispatch: Sender<ToSend>,
    ip_dispatch: Sender<Vec<u8>>,
    conn_info: ConnectIpInfo,
    device_addr: Ipv4Addr,
) {
    debug!("[ip_message_handler] got message! ip version={} | header len={}", 
        get_ip_version(&pkt.message),
        get_ip_header_length(&pkt.message));
    match get_ip_version(&pkt.message) {
        4 => {
            match pkt.dir {
                Direction::ToServer => {
                    set_ipv4_pkt_source(&mut pkt.message, &conn_info.assigned_ip);
                    // Recalculate checksum after ipv4 change
                    recalculate_checksum(&mut pkt.message);
                    info!("[ip_handler_t] Sending ipv4 packet to server");
                    match http3_dispatch
                        .send(encapsulate_ipv4(pkt.message, &conn_info.flow_id, &0))
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            error!("[ip_handler_t] Error sending to quic dispatch: {}", e);
                        }
                    };
                }
                Direction::ToClient => {
                    // Send this to the ip dispatcher
                    set_ipv4_pkt_destination(&mut pkt.message, &device_addr);
                    // Recalculate checksum after ipv4 change
                    recalculate_checksum(&mut pkt.message);
    
                    debug!(
                        "[ip_handler_t] Sending IPv4 packet towards client (tun): {:?}",
                        pkt.message
                    );
                    match ip_dispatch.send(pkt.message).await {
                        Ok(()) => {}
                        Err(e) => {
                            error!("[ip_handler_t] Error sending to ip dispatch: {}", e);
                        }
                    }
                }
            }
        },
        6 => {
            debug!("[ip_handler_t] Received IPv6 messages at ip_handler_t, not supported!");
        },
        _ => {
            error!("[ip_handler_t] Received message with unknown IP protocol.");
        }
    };
}

/// 
/// Creates a ToSend struct for sending IP
/// 
pub fn encapsulate_ipv4(pkt: Vec<u8>, flow_id: &u64, context_id: &u64) -> ToSend {
    let context_id_enc = encode_var_int(*context_id);
    let payload = [&context_id_enc, pkt.as_slice()].concat();
    ToSend {
        stream_id: *flow_id,
        content: Content::Datagram { payload },
        finished: false,
    }
}

/// 
/// Receives ready-to-send ip packets and then sends them
/// to the TUN device.
/// 
async fn ip_dispatcher_t(
    mut ip_dispatch_reader: Receiver<Vec<u8>>,
    mut writer: WriteHalf<AsyncDevice>,
) {
    loop {
        if let Some(pkt) = ip_dispatch_reader.recv().await {
            writer
                .write_all(&pkt)
                .await
                .expect("Could not write packet to TUN!");
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
async fn quic_conn_handler(
    ip_handler: Sender<IpMessage>,      // other side is ip_dispatcher_t
    info_sender: Sender<ConnectIpInfo>, // other side is the ip_handler_t
    http3_sender: Sender<ToSend>,
    mut http3_receiver: Receiver<ToSend>,
    peer_addr: String,
    mut conn: Connection,
    udp_socket: UdpSocket,
) {
    debug!("quic_conn_handler active!");
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut http3_conn: Option<quiche::h3::Connection> = None;

    let stream: Arc<Mutex<QuicStream>> = Arc::new(Mutex::new(QuicStream {
        stream_sender: None,
        stream_id: None,
        flow_id: None,
    }));

    let mut got_ip_addr = false;

    let mut main_stream_id: Option<u64> = None;
    let mut flow_id: Option<u64> = None;

    //let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
    let mut http3_retry_send: Option<ToSend> = None;

    let mut interval = time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Process datagram related events
        // We only expect datagrams that contain ip payloads
        while let Ok(len) = conn.dgram_recv(&mut buf) {
            let mut b = octets::Octets::with_slice(&buf);
            if let Ok(flow_id) = b.get_varint() {
                let context_id = match b.get_varint() {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("DATAGRAM without context ID: {}", e);
                        continue;
                    }
                };
                info!("Received datagram with context id={context_id}");
                if context_id != 0 {
                    continue;
                }
                
                let header_len = varint_len(flow_id) + varint_len(context_id);
                match get_ip_version(&buf[header_len..len]) {
                    4 => {
                        // Check if packet is valid (checksum check)
                        match check_ipv4_packet(&buf[header_len..len], 
                                (len - header_len) as u16) {
                            Ok(_) => {},
                            Err(Ipv4CheckError::WrongChecksumError) => {
                                debug!("Received IPv4 packet with invalid checksum, discarding..");
                                continue;
                            },
                            Err(Ipv4CheckError::WrongSizeError) => {
                                debug!("Received IPv4 packet with invalid size, discarding...");
                                continue;
                            },
                        }
                        match ip_handler
                            .send(IpMessage {
                                message: buf[header_len..len].to_vec(),
                                dir: Direction::ToClient,
                            })
                            .await
                        {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("Couldn't send ip packet to ip sender: {}", e);
                            }
                        }

                    },
                    6 => {
                        debug!("Received IPv6 packet via http3 (not implemented yet)");
                        continue;
                    },
                    v => {
                        error!("Received packet with invalid version: {v}");
                    }
                };
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
                        debug!("IP connect client polling on http3 connection");
                        match http3_conn.poll(&mut conn) {
                            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                info!(
                                    "got response headers {:?} on stream id {}",
                                    hdrs_to_strings(&list),
                                    stream_id
                                );
                                if stream.lock().await.stream_id.is_some() 
                                    && stream.lock().await.stream_id.unwrap() == stream_id {
                                    let binding = stream.as_ref().lock().await;
                                    let sender = binding.stream_sender.as_ref().unwrap();
                                    sender.send(Content::Headers { headers: list })
                                        .expect("Couldn't send headers through channel!");
                                }
                            }

                            Ok((stream_id, quiche::h3::Event::Data)) => {
                                debug!("received stream data");
                                let mut incoming: Vec<u8> = Vec::new();
                                let mut pos = 0;
                                while let Ok(read) = http3_conn
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
                                        CapsuleType::AddressAssign(c) => {
                                            debug!("Received a AddressAssign capsule from the server!");
                                            // TODO: Check if this packet is correctly structured
                                            //       Potentially we also want to make sure that we can
                                            //       change our own IP later and notify clients about it?
                                            //       Also: See if we can use the other values like the prefix
                                            //       This should not be used like this in prod
                                            if let IpLength::V4(ipv4) = c.assigned_address[0].ip_address {
                                                let assigned_addr = Ipv4Addr::from(ipv4);
                                                debug!("Got address: {:?}", assigned_addr);
                                                if !got_ip_addr {
                                                    // Send assigned ip to ip handler
                                                    debug!("Sending connection info to ip_handler");
                                                    let ci = ConnectIpInfo {
                                                        assigned_ip: assigned_addr,
                                                        flow_id: flow_id.unwrap(),
                                                        stream_id: main_stream_id.unwrap(),
                                                    };
                                                    info_sender.send(ci).await
                                                        .expect("Could not send connect ip info to ip handler.");
                                                    got_ip_addr = true;
                                                    debug!("Sent info to ip_handler!");
                                                }
                                            } else {
                                                panic!("Received an ipv6 address even tho we only allow ipv4");
                                            }
                                        },
                                        CapsuleType::AddressRequest(_) => {
                                            // We should not be receiving this one.
                                            error!("Received a AddressRequest capsule from the server!");
                                        },
                                        CapsuleType::RouteAdvertisement(_) => {
                                            error!("Received a RouteAdvertisement capsule from the server! Not implemented yet.");
                                        },
                                        CapsuleType::ClientIdentify(_) => {
                                            todo!()
                                        },
                                        CapsuleType::ClientRegister(_) => {
                                            todo!()
                                        },
                                        CapsuleType::ClientHello(_) => {
                                            error!("Received ClientHello from server?");
                                        }
                                    }
                                }
                            }

                            Ok((stream_id, quiche::h3::Event::Finished)) => {
                                info!("finished received, stream id: {} closing", stream_id);
                                // Shut down the stream
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
                                debug!("Connection with server ended, finishing up!");
                                return;
                            }

                            Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                error!(
                                    "request was reset by peer with {}, stream id: {} closed",
                                    e, stream_id
                                );
                                // Shut down the stream
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
                                debug!("Connection with server ended, finishing up!");
                                return;
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
                            info!("sending http3 request {:?} to {:?}", hdrs_to_strings(headers), http3_conn.peer_settings_raw());
                            match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                Ok(stream_id) => {
                                    stream_id_sender.send(stream_id)
                                        .await
                                        .unwrap_or_else(|e| error!("http3 request send stream_id failed: {:?}", e));
                                    main_stream_id = Some(stream_id);
                                    flow_id = Some(stream_id / 4);
                                    Ok(())
                                },
                                Err(e) => {
                                    error!("http3 request send failed");
                                    Err(e)
                                },
                            }
                        },
                        Content::Data { data } => {
                            info!("sending http3 data of {} bytes", data.len());
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
                            info!("sending http3 datagram of {} bytes to flow {}", payload.len(), to_send.stream_id);
                            match send_h3_dgram(&mut conn, to_send.stream_id, payload) {
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
                            return;
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
                        debug!("retry sending http3 request {:?}", hdrs_to_strings(headers));
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
                        match send_h3_dgram(&mut conn, to_send.stream_id, payload) {
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
                        error!("Connection ended! Stopping quic_conn_handler...");
                        return;
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
            let peer_addr_clone = peer_addr.clone(); //rust is stupid
            let _ip_connect_thread = tokio::spawn(async move {
                handle_ip_connect_stream(http3_sender_clone, stream_clone, peer_addr_clone).await;
            });
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

/// 
/// Initiates the CONNECT-IP request.
/// 
async fn handle_ip_connect_stream(
    http3_sender: Sender<ToSend>,
    stream: Arc<Mutex<QuicStream>>,
    peer_addr: String,
) {
    // We only need to establish the connect-ip thing first
    // TODO: Check if this packet structure is correct.
    //       For now it's fine
    debug!("connect-ip builder: Trying to establish connect-ip!");
    let headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"), 
        quiche::h3::Header::new(b":authority", peer_addr.as_bytes()), 
        quiche::h3::Header::new(b":path", b"/.well-known/masque/ip/*/*/"),
        quiche::h3::Header::new(b"connect-ip-version", b"3"),
    ];
    let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
    let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();

    http3_sender
        .send(ToSend {
            stream_id: u64::MAX,
            content: Content::Request {
                headers,
                stream_id_sender,
            },
            finished: false,
        })
        .await
        .unwrap_or_else(|e| {
            error!("Could not send http3 request to http3_receiver in QUIC handler: {e}")
        });

    debug!("connect-ip builder: Sent connect-ip request");

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

    debug!("connect-ip builder: Got a stream_id: {}", stream_id);
    // Now wait for response

    let response = response_receiver
        .recv()
        .await
        .expect("http3 response receiver error");
    debug!("connect-ip builder: Got response from server");
    let mut succeeded = false;
    if let Content::Headers { headers } = response {
        info!(
            "Got response for connect-ip request: {:?}",
            hdrs_to_strings(&headers)
        );
        let mut status = None;
        for hdr in headers {
            if hdr.name() == b":status" {
                status = Some(hdr.value().to_owned());
                break;
            }
        }
        if let Some(status) = status {
            if let Ok(status_str) = std::str::from_utf8(&status) {
                if let Ok(status_code) = status_str.parse::<i32>() {
                    if (200..300).contains(&status_code) {
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
                            capsule_id: ADDRESS_REQUEST_ID,
                            capsule_type: super::capsules::CapsuleType::AddressRequest(
                                request_capsule,
                            ),
                        };

                        let mut buf = [0; 9];
                        cap.serialize(&mut buf);

                        http3_sender
                            .send(ToSend {
                                stream_id: stream.lock().await.stream_id.unwrap(),
                                content: Content::Data { data: buf.to_vec() },
                                finished: false,
                            })
                            .await
                            .unwrap_or_else(|e| {
                                error!("sending http3 data capsule failed: {:?}", e)
                            });
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
    info!("connect-ip established!")
}

pub struct ConnectIPClient;

impl ConnectIPClient {
    pub async fn run(
        &self,
        config: ClientConfig,
    ) {
        // 1) Create QUIC connection, connect to server
        let mut socket = match self.get_udp(config.server_name.as_ref().unwrap()).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create udp socket: {}", e);
                return;
            }
        };
        debug!("Created UDP socket");
        let quic_conn = match self.create_quic_conn(&mut socket, 
                config.server_name.as_ref().unwrap()).await {
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
        let dev = match self.create_tun(
            config.tun_addr.as_ref().unwrap(), 
            config.tun_gateway.as_ref().unwrap(), 
            config.tun_name.as_ref().unwrap()) {
            Ok(v) => v,
            Err(e) => {
                error!("could not create TUN: {}", e);
                return;
            }
        };
        let prefix_index = config.tun_addr.as_ref().unwrap().find("/");
        if prefix_index.is_none() {
            error!("Malformed IP address!");
            return;
        }
        let addr = String::from_str(
            &config.tun_addr.as_ref().unwrap()[..(prefix_index.unwrap())])
            .unwrap();
        let ipaddr = Ipv4Addr::from_str(&addr).unwrap();
        info!("Local address for packets: {}", ipaddr);
        let (reader, writer) = tokio::io::split(dev);

        // 4) Create receivers/senders

        // ip_sender for ip_receiver_t, ip_recv for ip_handler_t
        let (ip_sender, ip_recv) = tokio::sync::mpsc::channel(MAX_CHANNEL_MSG); 
        let (http3_dispatch, http3_dispatch_reader) = tokio::sync::mpsc::channel(MAX_CHANNEL_MSG);
        let (ip_dispatch, ip_dispatch_reader) = tokio::sync::mpsc::channel(MAX_CHANNEL_MSG);
        let (conn_info_sender, conn_info_recv) = tokio::sync::mpsc::channel(MAX_CHANNEL_MSG);

        // Copies of senders
        let ip_from_quic_sender = ip_sender.clone();
        let http3_dispatch_clone = http3_dispatch.clone();

        debug!("Starting threads!");
        let ip_recv_t = tokio::task::spawn(ip_receiver_t(ip_sender, reader));

        let ip_h_t = tokio::task::spawn(ip_handler_t(
            ip_recv,
            conn_info_recv,
            http3_dispatch,
            ip_dispatch,
            ipaddr,
        ));

        let ip_disp_t = tokio::task::spawn(ip_dispatcher_t(ip_dispatch_reader, writer));

        let peer_addr = config.server_name.unwrap().clone();
        let quic_h_t = tokio::task::spawn(quic_conn_handler(
            ip_from_quic_sender,
            conn_info_sender,
            http3_dispatch_clone,
            http3_dispatch_reader,
            peer_addr,
            quic_conn,
            socket,
        ));

        tokio::select! {
            _ = ip_recv_t => { error!("ip_recv_t stopped!"); },
            _ = ip_h_t => { error!("ip_h_t stopped!"); },
            _ = ip_disp_t => { error!("ip_disp_t stopped!"); },
            _ = quic_h_t => { error!("quic_h_t stopped!"); },
        };
        debug!("ConnectIPClient exiting..");
    }

    ///
    /// Creates a basic QUIC connection to the given server address.
    /// Connection will be in early data after this.
    /// 
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

        Ok(connection)
    }

    ///
    /// Creates a async TUN device
    /// Given arguments will be used for the configuration of the device.
    ///
    fn create_tun(
        &self,
        dev_addr: &String,
        tun_gateway: &String,
        tun_name: &String,
    ) -> Result<AsyncDevice, tun2::Error> {
        let mut config = tun2::Configuration::default();

        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });
        config.tun_name(tun_name);
        let dev = tun2::create_as_async(&config);
        set_client_ip_and_route(dev_addr, tun_gateway, tun_name);
        dev
    }

    /// 
    /// Creates and binds the UDP socket used for QUIC
    /// 
    async fn get_udp(&self, server_addr: &String) -> Result<UdpSocket, UdpBindError> {
        let mut http_start = "";
        if !server_addr.starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}", http_start, server_addr);

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

        match socket.connect(peer_addr).await {
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
