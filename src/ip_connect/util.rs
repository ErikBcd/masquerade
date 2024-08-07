use std::{
    error::Error, io::Read, sync::{Arc, Mutex}
};

use log::*;
use octets::varint_len;
use packet::ip;
use tun2::platform::posix::{Reader, Writer};
use tokio::sync::mpsc::{self};

use crate::{common::{hdrs_to_strings, MAX_DATAGRAM_SIZE}, ip_connect::{capsules::Capsule, client::IPConnectClient}};

#[derive(Debug)]
pub enum Content {
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
pub struct ToSend {
    pub stream_id: u64, // or flow_id for DATAGRAM
    pub content: Content,
    pub finished: bool,
}

#[derive(Debug, Clone)]
pub struct UdpBindError;

impl std::fmt::Display for UdpBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "get_udp(server_addr) has failed!")
    }
}
impl Error for UdpBindError {}

#[derive(Debug, Clone)]
pub struct HandleIPError {
    pub message: String,
}

impl std::fmt::Display for HandleIPError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Unable to handle IP message: {}", self.message)
    }
}
impl Error for HandleIPError {}

#[derive(Debug, Clone)]
pub struct IPError {
    pub message: String,
}

impl std::fmt::Display for IPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "get_udp(server_addr) has failed! Error: {}",
            self.message
        )
    }
}

#[derive(Debug, Clone)]
pub struct QUICStreamError {
    pub message: String,
}

impl std::fmt::Display for QUICStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Could not creat IP connect stream! Error: {}",
            self.message
        )
    }
}

/**
 * Tries to read anything from the reader and sends it to tx
 * Should be used as a thread, will block otherwise.
 */
// TODO: Do we even need to do this? Can't we directly parse this here?
pub fn receive_ip_t(
    tx: std::sync::mpsc::Sender<Vec<u8>>,
    mut reader: Reader,
) -> Result<(), IPError> {
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
 * Handles incoming IP packets from a receiver rx
 */
pub fn handle_ip_t(
    client: Arc<Mutex<IPConnectClient>>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    mut writer: Writer,
) -> Result<(), IPError> {
    loop {
        if let Ok(pkt) = rx.recv() {
            match ip::Packet::new(pkt.as_slice()) {
                Ok(ip::Packet::V4(mut pkt)) => {
                    debug!("Received IPv4 packet");
                    let response = client
                        .lock()
                        .unwrap()
                        .handle_ip_packet(&mut pkt)
                        .expect("Error handling ip packet");
                    // Send the response created by the handler
                    // TODO: Maybe we want to create a responder thread that checks a message queue 
                    //       and sends any messages that are in there.
                }
                Ok(ip::Packet::V6(mut pkt)) => {
                    debug!("Received IPv6 packet");
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
            }
        }
    }
}

/**
 * Handles incoming http3 messages and sends messages that have appeared.
 */
pub fn handle_http3(
    client: Arc<Mutex<IPConnectClient>>
) {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut binding = client.lock().unwrap();
    let mut conn = binding.connection.as_mut().unwrap();
    let mut binding = client.lock().unwrap();
    let udp_socket = binding.udp_socket.as_ref().unwrap();

    let mut http3_conn: Option<quiche::h3::Connection> = None;
    loop {
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        if conn.is_established() && http3_conn.is_none() {
            let h3_config = quiche::h3::Config::new().unwrap();
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }

        // First check for datagrams
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
                    Ok(ip::Packet::V4(mut pkt)) => {
                        debug!("Received IPv4 packet via http3");
                        // TODO: Send packet to TUN interface
                        //       Do we have to do anything else before that? 
                        //       Might need to change the IP depending on the servers answer
                        //       to our address request
                        {
                            let binding = client.lock().unwrap();
                            binding.send_ip_to_tun(&mut pkt);
                        }
                    }
                    Ok(ip::Packet::V6(_)) => {
                        debug!("Received IPv6 packet via http3 (not implemented yet)");
                        continue;
                    }
                    Err(err) => {
                        debug!("Received an invalid packet: {:?}", err)
                    },
                }
            }
        }

        // handle QUIC received data
        let recvd = futures::executor::block_on(udp_socket.recv_from(&mut buf));
        
        let (read, from) = match recvd {
            Ok(v) => v,
            Err(e) => {
                error!("error when reading from UDP socket: {:?}", e);
                continue
            },
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
                        // TODO: Can we just ignore headers that occur now?
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        debug!("received stream data");
                        while let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            // we only receive capsules via data, so parse this capsule
                            match Capsule::new(&buf) {
                                Ok(v) => {
                                    client.lock().unwrap().handle_capsule(v);
                                },
                                Err(e) => {
                                    debug!("Couldn't parse capsule: {}", e);
                                }
                            }

                        }
                    },

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
                                .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
                        }

                    },

                    Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                        // Shut down the stream
                        // TODO: If this stream is the main connect-ip stream, we have to exit or 
                        //       create a new one
                        if conn.stream_finished(stream_id) {
                            debug!("stream {} finished", stream_id);
                        } else {
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                                .unwrap_or_else(|e| error!("stream shutdown read failed: {:?}", e));
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                                .unwrap_or_else(|e| error!("stream shutdown write failed: {:?}", e));
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
        
        // TODO: Check if we have any messages to write back to the server
    }
}