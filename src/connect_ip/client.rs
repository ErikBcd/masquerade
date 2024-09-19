use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use log::*;
use octets::varint_len;
use quiche::h3::NameValue;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, channel, Receiver, Sender};
use tokio::time::{self};
use tun2::AsyncDevice;

use crate::common::*;
use crate::connect_ip::capsules::*;
use crate::connect_ip::util::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub server_address: Option<String>,
    pub interface_address: Option<String>,
    pub interface_name: Option<String>,
    pub interface_gateway: Option<String>,
    pub allowed_ips: Option<String>,
    pub use_static_address: Option<bool>,
    pub static_address: Option<String>,
    pub client_name: Option<String>,
    pub thread_channel_max: Option<usize>,
    pub create_qlog_file: Option<bool>,
    pub qlog_file_path: Option<String>,
    pub mtu: Option<String>,
    pub congestion_algorithm: Option<String>,
    pub max_pacing_rate: Option<u64>,
    pub disable_active_migration: Option<bool>,
    pub enable_hystart: Option<bool>,
    pub discover_pmtu: Option<bool>,
    pub ack_delay_exponent: Option<u64>,
    pub max_ack_delay: Option<u64>,    
    pub max_idle_timeout: Option<u64>,
}

impl std::fmt::Display for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\
            server_address           = {:?}\n\
            interface_address        = {:?}\n\
            interface_name           = {:?}\n\
            interface_gateway        = {:?}\n\
            use_static_ip            = {:?}\n\
            static_address           = {:?}\n\
            client_name              = {:?}\n\
            thread_channel_max       = {:?}\n\
            create_qlog_file         = {:?}\n\
            qlog_file_path           = {:?}\n\
            mtu                      = {:?}\n\
            congestion_algorithm     = {:?}\n\
            max_pacing_rate          = {:?}\n\
            disable_active_migration = {:?}\n\
            enable_hystart           = {:?}\n\
            discover_pmtu            = {:?}\n\
            ack_delay_exponent       = {:?}\n\
            max_ack_delay            = {:?}\n\
            max_idle_timeout         = {:?}\n\
            ",
            self.server_address,
            self.interface_address,
            self.interface_name,
            self.interface_gateway,
            self.use_static_address,
            self.static_address,
            self.client_name,
            self.thread_channel_max,
            self.create_qlog_file.as_ref().unwrap(),
            self.qlog_file_path.as_ref().unwrap(),
            self.mtu,
            self.congestion_algorithm,
            self.max_pacing_rate,
            self.disable_active_migration,
            self.enable_hystart,
            self.discover_pmtu,
            self.ack_delay_exponent,
            self.max_ack_delay,
            self.max_idle_timeout,
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
    pub stream_sender: Option<Sender<Content>>,
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
fn set_client_ip_and_route(
    dev_addr: &String, 
    tun_gateway: &String, 
    tun_name: &String, 
    allowed_ips: &String, 
    mtu: &String) {
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
        .args([
            "route",
            "add",
            allowed_ips,
            "via",
            tun_gateway,
            "dev",
            tun_name,
        ])
        .output()
        .expect("Failed to execute first IP ROUTE command");

    if !route_output.status.success() {
        eprintln!(
            "Failed to set route 0.0.0.0 to tun device: {}",
            String::from_utf8_lossy(&route_output.stderr)
        );
    }

    // ip link set dev eth0 mtu 1400
    let mtu_output = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            tun_name,
            "mtu",
            mtu,
        ])
        .output()
        .expect("Failed to execute MTU size command");

    if !mtu_output.status.success() {
        eprintln!(
            "Failed to set MTU to tun device: {}",
            String::from_utf8_lossy(&mtu_output.stderr)
        );
    }

    // sudo iptables -t nat -A POSTROUTING -o tunMC -j MASQUERADE
    let iptables = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            tun_name,
            "-j",
            "MASQUERADE",
        ])
        .output()
        .expect("Failed to execute ip tables cmd");
    if !iptables.status.success() {
        error!(
            "Failed to set up iptables: {}",
            String::from_utf8_lossy(&iptables.stderr)
        );
    }

    // Allow ipv4 proxying
    // sudo sysctl -w net.ipv4.conf.all.forwarding=1
    let sysctl_cmd = Command::new("sysctl")
        .args(["-w", "net.ipv4.conf.all.forwarding=1"])
        .output()
        .expect("Failed to execute sysctl command!");
    if !sysctl_cmd.status.success() {
        error!(
            "Failed to allow ipv4 forwarding: {}",
            String::from_utf8_lossy(&sysctl_cmd.stderr)
        );
    }
}

///
/// Receives raw IP messages from a TUN.the
/// Will send received messages to the ip_handler_t
/// Arguments:
///  * ip_handler: Channel that handles received ip messages
///  * reader: Receiver for raw ip messages
///
async fn ip_receiver_t(ip_handler: Sender<IpMessage>, mut reader: ReadHalf<AsyncDevice>) {
    let mut buf = [0; 4096];
    loop {
        let size = reader
            .read(&mut buf)
            .await
            .expect("[ip_receiver_t] Could not read from reader");
        let pkt = &buf[..size];
        use std::io::{Error, ErrorKind::Other};
        if ip_handler.capacity() == 0 {
            error!("[ip_receiver_t] ip_handler capacity 0, dropping packet!");
            continue;
        }
        match ip_handler
            .send(IpMessage {
                message: pkt.to_vec(),
                dir: Direction::ToServer,
            })
            .await
            .map_err(|e| Error::new(Other, e))
        {
            Ok(()) => {
            }
            Err(e) => {
                error!("[ip_receiver_t] tx send error: {}", e);
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
    // Wait till the QUIC server sends us connection information
    let mut conn_info: Option<ConnectIpInfo> = None;
    if let Some(info) = conn_info_recv.recv().await {
        conn_info = Some(info);
    }
    let conn_info = conn_info.unwrap();
    println!(
        "Connected to server! Assigned IP: {}",
        conn_info.assigned_ip
    );
    loop {
        if let Some(mut pkt) = ip_recv.recv().await {
            match get_ip_version(&pkt.message) {
                4 => {
                    match pkt.dir {
                        Direction::ToServer => {
                            set_ipv4_pkt_source(&mut pkt.message, &conn_info.assigned_ip);
                            // Recalculate checksum after ipv4 change
                            recalculate_checksum(&mut pkt.message);
                            if http3_dispatch.capacity() > 0 {
                                match http3_dispatch
                                    .send(encapsulate_ipv4(pkt.message, &conn_info.flow_id, &0))
                                    .await
                                {
                                    Ok(()) => {}
                                    Err(e) => {
                                        error!("[ip_handler_t] Error sending to quic dispatch: {}", e);
                                    }
                                };
                            } else {
                                error!("Http3 dispatcher capacity was full!");
                            }
                        }
                        Direction::ToClient => {
                            // Send this to the ip dispatcher
                            set_ipv4_pkt_destination(&mut pkt.message, &device_addr);
                            // Recalculate checksum after ipv4 change
                            recalculate_checksum(&mut pkt.message);

                            if ip_dispatch.capacity() > 0 {
                                match ip_dispatch.send(pkt.message).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        error!("[ip_handler_t] Error sending to ip dispatch: {}", e);
                                    }
                                }
                            } else {
                                error!("Dropping packet, ip_dispatch is full!");
                            }
                        }
                    }
                }
                6 => {
                    debug!("[ip_handler_t] Received IPv6 messages at ip_handler_t, not supported!");
                }
                _ => {
                    error!("[ip_handler_t] Received message with unknown IP protocol.");
                }
            };
        }
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
    mut conn: Connection,
    udp_socket: UdpSocket,
    config: ClientConfig,
) {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut http3_conn: Option<quiche::h3::Connection> = None;

    let mut got_ip_addr = false;

    let mut flow_id: Option<u64> = None;

    //let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
    let mut http3_retry_send: Option<ToSend> = None;

    let mut interval = time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    let mut stream: QuicStream = QuicStream {
        stream_sender: None,
        stream_id: None,
        flow_id: None,
    };

    loop {
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
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

                let recv_info = quiche::RecvInfo {
                    to: udp_socket.local_addr().unwrap(),
                    from,
                };

                // Process potentially coalesced packets.
                let _ = match conn.recv(&mut buf[..read], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("QUIC recv failed: {:?}", e);
                        break;
                    }
                };
                
                if let Some(http3_conn) = &mut http3_conn {
                    loop {
                        match http3_conn.poll(&mut conn) {
                            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                if stream.stream_id.is_some()
                                    && stream.stream_id.unwrap() == stream_id {
                                    stream.stream_sender.as_ref().unwrap()
                                        .send(Content::Headers { headers: list }).await
                                        .expect("Couldn't send headers through channel!");
                                }
                            }

                            Ok((stream_id, quiche::h3::Event::Data)) => {
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
                                            error!("Couldn't parse capsule: {}", e);
                                            break;
                                        }
                                    };

                                    match parsed.capsule_type {
                                        CapsuleType::AddressAssign(c) => {
                                            if let IpLength::V4(ipv4) = c.assigned_address[0].ip_address {
                                                let assigned_addr = Ipv4Addr::from(ipv4);
                                                // If we get 0.0.0.0/32 as an address we quit
                                                // TODO: Implement some sort of renegotiation
                                                if assigned_addr == Ipv4Addr::new(0, 0, 0, 0) {
                                                    error!("Server sent assigned 0.0.0.0 as our address, giving up!");
                                                    return;
                                                }
                                                let (addr, prefix) = split_ip_prefix(
                                                    config.static_address.as_ref().unwrap().clone()
                                                );
                                                let requested_addr = Ipv4Addr::from_str(&addr).unwrap();
                                                if assigned_addr != requested_addr && requested_addr != Ipv4Addr::UNSPECIFIED {
                                                    // send another address request
                                                    let buf = AddressRequest::create_sendable(
                                                        requested_addr, prefix, None);
                                                    http3_sender
                                                        .send(ToSend {
                                                            stream_id: stream.stream_id.unwrap(),
                                                            content: Content::Data { data: buf.to_vec() },
                                                            finished: false,
                                                        })
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            error!("sending http3 data capsule failed: {:?}", e)
                                                        });
                                                    continue;
                                                }

                                                if !got_ip_addr {
                                                    // Send assigned ip to ip handler
                                                    let ci = ConnectIpInfo {
                                                        assigned_ip: assigned_addr,
                                                        flow_id: flow_id.unwrap(),
                                                        stream_id: stream.stream_id.unwrap(),
                                                    };
                                                    info_sender.send(ci).await
                                                        .expect("Could not send connect ip info to ip handler.");
                                                    got_ip_addr = true;
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
                                        CapsuleType::ClientHello(_) => {
                                            // CLIENT_HELLO from server means that the server doesn't
                                            // know us yet, so we need to ask for an IP
                                            // We don't need to parse this message
                                            // If we get this message we should also be
                                            // configured to only take static addresses
                                            let (addr, prefix) = split_ip_prefix(
                                                config.static_address.as_ref().unwrap().clone()
                                            );

                                            let requested_addr = Ipv4Addr::from_str(&addr)
                                                .expect("Couldn't parse given static address!");

                                            let buf = AddressRequest::create_sendable(requested_addr, prefix, None);

                                            http3_sender
                                                .send(ToSend {
                                                    stream_id: stream.stream_id.unwrap(),
                                                    content: Content::Data { data: buf.to_vec() },
                                                    finished: false,
                                                })
                                                .await
                                                .unwrap_or_else(|e| {
                                                    error!("sending http3 data capsule failed: {:?}", e)
                                                });
                                        }
                                    }
                                }
                            }

                            Ok((stream_id, quiche::h3::Event::Finished)) => {
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
                                return;
                            }
                            Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                            Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                                info!("GOAWAY id={}", goaway_id);
                            }

                            Err(quiche::h3::Error::Done) => {
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
                            match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                Ok(stream_id) => {
                                    stream_id_sender.send(stream_id)
                                        .await
                                        .unwrap_or_else(|e| error!("http3 request send stream_id failed: {:?}", e));
                                    stream.stream_id = Some(stream_id);
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
                            }
                        },
                        Content::Datagram { payload } => {
                            match send_h3_dgram(&mut conn, to_send.stream_id, payload) {
                                    Ok(v) => Ok(v),
                                    Err(e) => {
                                        error!("sending http3 datagram failed: {:?}", e);
                                        break;
                                    }
                                }
                        },
                        Content::Finished => {
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

        // Process datagram related events
        // We only expect datagrams that contain ip payloads
        while let Ok(len) = conn.dgram_recv(&mut buf) {
            let mut b = octets::Octets::with_slice(&buf);
            if let Ok(flow_id) = b.get_varint() {
                let context_id = match b.get_varint() {
                    Ok(v) => v,
                    Err(_) => {
                        continue;
                    }
                };
                if context_id != 0 {
                    continue;
                }

                let header_len = varint_len(flow_id) + varint_len(context_id);
                match get_ip_version(&buf[header_len..len]) {
                    4 => {
                        // Check if packet is valid (checksum check)
                        match check_ipv4_packet(&buf[header_len..len], (len - header_len) as u16) {
                            Ok(_) => {}
                            Err(Ipv4CheckError::WrongChecksumError) => {
                                debug!("Received IPv4 packet with invalid checksum, discarding..");
                                continue;
                            }
                            Err(Ipv4CheckError::WrongSizeError) => {
                                debug!("Received IPv4 packet with invalid size, discarding...");
                                continue;
                            }
                        }
                        if ip_handler.capacity() > 0 {
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
                        } else {
                            error!("Dropping packet, ip_handler capacity at 0!");
                        }
                    }
                    6 => {
                        debug!("Received IPv6 packet via http3 (not implemented yet)");
                        continue;
                    }
                    v => {
                        error!("Received packet with invalid version: {v}");
                    }
                };
            }
        }

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            let h3_config = quiche::h3::Config::new().unwrap();
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );

            // now we can create the ip connect stream
            let http3_sender_clone = http3_sender.clone();
            let config_clone = config.clone();
            let (response_sender, response_receiver) =
                    channel(config.thread_channel_max.unwrap());

            stream.stream_sender = Some(response_sender);

            let _ip_connect_thread = tokio::spawn(async move {
                handle_ip_connect_stream(http3_sender_clone, response_receiver, config_clone).await;
            });
        }

        // Send pending QUIC packets
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("QUIC connection {} send failed: {:?}", conn.trace_id(), e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };
            match udp_socket.send_to(&out[..write], send_info.to).await {
                Ok(_) => {},
                Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
            }
        }
    }
}

///
/// Initiates the CONNECT-IP request.
///
async fn handle_ip_connect_stream(
    http3_sender: Sender<ToSend>,
    mut response_receiver: Receiver<Content>,
    config: ClientConfig,
) {
    // We only need to establish the connect-ip thing first
    // TODO: Check if this packet structure is correct.
    //       For now it's fine
    let headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", config.server_address.unwrap().as_bytes()),
        quiche::h3::Header::new(b":path", b"/.well-known/masque/ip/*/*/"),
        quiche::h3::Header::new(b"connect-ip-version", b"3"),
    ];
    let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);

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

    let stream_id = stream_id_receiver
        .recv()
        .await
        .expect("Stream id receiver failed us all.");

    // Now wait for response

    let response = response_receiver
        .recv()
        .await
        .expect("http3 response receiver error");
    let mut succeeded = false;
    if let Content::Headers { headers } = response {
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
                        // If we want a static IP we only have to send the client hello for now
                        let buf = if config.use_static_address.unwrap() {
                            ClientHello::create_sendable(config.client_name.unwrap())
                                .unwrap_or_else(|e| {
                                    panic!("Could not create client_hello: {:?}", e)
                                })
                        } else {
                            AddressRequest::create_sendable(
                                Ipv4Addr::new(0, 0, 0, 0),
                                None,
                                None,
                            )
                        };

                        http3_sender
                            .send(ToSend {
                                stream_id,
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
}

pub struct ConnectIPClient;

impl ConnectIPClient {
    pub async fn run(&self, config: ClientConfig) {
        // 1) Create QUIC connection, connect to server
        let mut socket = match self.get_udp(config.server_address.as_ref().unwrap()).await {
            Ok(v) => v,
            Err(e) => {
                error!("could not create udp socket: {}", e);
                return;
            }
        };
        debug!("Created UDP socket");
        let quic_conn = match self
            .create_quic_conn(
                &mut socket,
                &config,
            )
            .await
        {
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
            config.interface_address.as_ref().unwrap(),
            config.interface_gateway.as_ref().unwrap(),
            config.interface_name.as_ref().unwrap(),
            config.allowed_ips.as_ref().unwrap(),
            config.mtu.as_ref().unwrap(),
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("could not create TUN: {}", e);
                return;
            }
        };
        let (addr, _prefix) = split_ip_prefix(config.interface_address.as_ref().unwrap().clone());

        let ipaddr = Ipv4Addr::from_str(&addr).unwrap();
        info!("Local address for packets: {}", ipaddr);
        let (reader, writer) = tokio::io::split(dev);

        // 4) Create receivers/senders

        // ip_sender for ip_receiver_t, ip_recv for ip_handler_t
        let (ip_sender, ip_recv) = tokio::sync::mpsc::channel(config.thread_channel_max.unwrap());
        let (http3_dispatch, http3_dispatch_reader) =
            tokio::sync::mpsc::channel(config.thread_channel_max.unwrap());
        let (ip_dispatch, ip_dispatch_reader) =
            tokio::sync::mpsc::channel(config.thread_channel_max.unwrap());
        let (conn_info_sender, conn_info_recv) =
            tokio::sync::mpsc::channel(config.thread_channel_max.unwrap());

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

        let quic_h_t = tokio::task::spawn(quic_conn_handler(
            ip_from_quic_sender,
            conn_info_sender,
            http3_dispatch_clone,
            http3_dispatch_reader,
            quic_conn,
            socket,
            config,
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
        client_config: &ClientConfig,
    ) -> Result<Connection, quiche::Error> {
        let mut http_start = "";
        if !client_config.server_address.as_ref().unwrap().starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}", http_start, client_config.server_address.as_ref().unwrap());

        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        // TODO: *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        // Only set a maximum timeout if the value is something 
        // Will be none if user specified timeout of 0
        if client_config.max_idle_timeout.is_some() {
            config.set_max_idle_timeout(client_config.max_idle_timeout.unwrap());
        }
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(1000);
        config.set_initial_max_streams_uni(1000);
        config.enable_dgram(true, 1000, 1000);
        config.set_disable_active_migration(client_config.disable_active_migration.unwrap());
        config.enable_pacing(true);
        config.set_max_pacing_rate(client_config.max_pacing_rate.unwrap());
        config.set_ack_delay_exponent(client_config.ack_delay_exponent.unwrap());
        config.set_max_ack_delay(client_config.max_ack_delay.unwrap());
        match client_config.congestion_algorithm.as_ref().unwrap().as_str() {
            "bbr2" => {
                config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR2);
            },
            "bbr" => {
                config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR);
            },
            "reno" => {
                config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Reno);
            },
            "cubic" => {
                config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);
            },
            v => {
                error!("Congestion algorithm {:?} not available", v);
            }
        }
        config.enable_hystart(client_config.enable_hystart.unwrap());
        config.discover_pmtu(client_config.discover_pmtu.unwrap());

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

        // If the user wanted it, create a qlog file
        if client_config.create_qlog_file.unwrap() {
            let id = format!("{:?}", &scid);
            let writer = make_qlog_writer(client_config.qlog_file_path.as_ref().unwrap(), "connect-ip-client", &id);

            connection.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }

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
        allowed_ips: &String,
        mtu: &String,
    ) -> Result<AsyncDevice, tun2::Error> {
        let mut config = tun2::Configuration::default();

        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });
        config.tun_name(tun_name);
        let dev = tun2::create_as_async(&config);
        set_client_ip_and_route(dev_addr, tun_gateway, tun_name, allowed_ips, mtu);
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
