use std::{
    collections::HashMap, error::Error, io::Read, sync::{Arc, Mutex}, time::Duration
};

use log::*;
use packet::ip;
use quiche::Connection;
use tun2::platform::posix::{Reader, Writer};
use tokio::{sync::mpsc::{self, unbounded_channel, UnboundedSender}, time};

use crate::ip_connect::client::IPConnectClient;

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
                    //writer.write(&response[..])
                    //    .expect("Error writing to writer!");
                }
                Ok(ip::Packet::V6(mut pkt)) => {
                    debug!("Received IPv6 packet");
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
            }
        }
    }
}

pub fn handle_http3(
    client: Arc<Mutex<IPConnectClient>>
) {
    // TODO: How long do we even allow this to be?
    let mut buf = [0; 65535];
    // create new http3 connection and then wait for events
    let mut http3_conn: Option<quiche::h3::Connection> = None;
    let (http3_sender, mut http3_receiver) = unbounded_channel::<ToSend>();
    let connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut http3_retry_send: Option<ToSend> = None;
    let mut interval = time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    if client.lock().unwrap().connection.is_none() {
        error!("Wanted to handle http3, but connection was none!");
    }

    // TODO: Does the connection stay locked this way?
    // Also: This isn't copied, right?
    let mut binding = client.lock().unwrap();
    let mut conn = binding.connection.as_mut().unwrap();

    loop {
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
        handle_h3_dgram(&mut buf, &connect_sockets, conn);

        // TODO: handle h3 connection data

    }
}

fn handle_h3_dgram(
    buf: &mut [u8], 
    connect_sockets: &Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>, 
    conn: &mut Connection) 
    {
    while let Ok(len) = conn.dgram_recv(buf) {
        let mut b = octets::Octets::with_slice(buf);
        if let Ok(flow_id) = b.get_varint() {
            info!(
                "Received DATAGRAM flow_id={} len={} buf={:02x?}",
                flow_id,
                len,
                buf[0..len].to_vec()
            );

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
}