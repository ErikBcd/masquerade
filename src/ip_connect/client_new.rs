use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::mpsc::{Receiver, Sender};

use log::*;
use packet::{ip, Packet};
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::unix::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tun2::platform::posix::{Reader, Writer};
use tun2::platform::Device;

use crate::common::*;
use crate::ip_connect::util::*;

/**
 * Receives raw IP messages from a TUN.
 * Will send received messages to the ip_handler_t
 */
pub async fn ip_receiver_t(tx: Sender<Vec<u8>>, mut reader: Reader) {
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
pub async fn ip_handler_t(ip_recv: Receiver<Vec<u8>>, dispatch_sender: Sender<Vec<u8>>) {
    loop {
        if let Ok(pkt) = ip_recv.recv() {
            match ip::Packet::new(pkt.as_slice()) {
                Ok(ip::Packet::V4(mut pkt)) => {
                    debug!("Received IPv4 packet");
                    // TODO: Send the parsed packet to the quic_dispatcher_t
                    match dispatch_sender.send(encapsulate_ipv4(pkt)) {
                        Ok(()) => {},
                        Err(e) => {
                            error!("Error sending to ip dispatch: {}", e);
                        }
                    };
                }
                Ok(ip::Packet::V6(mut pkt)) => {
                    debug!("Received IPv6 packet");
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
            }
        }
    }
}

pub fn encapsulate_ipv4(pkt: packet::ip::v4::Packet<&[u8]>) -> Vec<u8> {
    todo!();
}

/**
 * Receives QUIC messages from a connection.
 * Sends these messages to the handler.
 */
pub async fn quic_receiver_t(tx: Sender<Vec<u8>>, conn: Connection) {
    todo!()
}

/**
 * Receives QUIC messages from the quic receiver.
 * Handles these messages and then sends messages to the
 * TUN dispatcher or the QUIC dispatcher.
 */
pub async fn quic_handler_t(
    quic_receiver: Receiver<Vec<u8>>,
    quic_dispatcher: Sender<Vec<u8>>,
    ip_dispatcher: Sender<Vec<u8>>,
) {
    todo!()
}

/**
 * Receives ready-to-send ip packets and then sends them.
 */
pub async fn ip_dispatcher_t(rx: Receiver<Vec<u8>>, mut writer: Writer) {
    loop {
        if let Ok(pkt) = rx.recv() {
            writer.write(&pkt).expect("Could not write packet to TUN!");
        }
    }
}

/**
 * Receives ready-to-send QUIC messages and sends them to
 * the given udp socket
 * //TODO: Actually a udp socket? or maybe something else?
 */
pub async fn quic_dispatcher_t(rx: Receiver<Vec<u8>>) {
    todo!()
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

        let mut quic_conn = 
            match self.create_quic_conn(&mut socket, server_addr).await {
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

        // IP
        let (ip_sender, ip_recv) = std::sync::mpsc::channel();
        let (to_quic_dispatch, quic_dispatch_reader) = std::sync::mpsc::channel();
        let (to_quic_handler, quic_handler_reader) = std::sync::mpsc::channel();
        let (to_ip_dispatch, ip_dispatch_reader) = std::sync::mpsc::channel();
        let to_ip_dispatch_clone = to_ip_dispatch.clone();

        // Spawn all threads. Stop once the first one finishes.
        tokio::select! {
            _ = ip_receiver_t(ip_sender, reader) => {},
            _ = ip_handler_t(ip_recv, to_ip_dispatch_clone) => {},
            _ = ip_dispatcher_t(ip_dispatch_reader, writer) => {},
            _ = quic_receiver_t(to_quic_handler, quic_conn) => {},
            _ = quic_handler_t(quic_handler_reader, to_quic_dispatch, to_ip_dispatch) => {},
            _ = quic_dispatcher_t(quic_dispatch_reader) => {},
        }
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
