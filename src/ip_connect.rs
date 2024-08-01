use std::{error::Error, net::{SocketAddr, ToSocketAddrs}};

use log::*;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tun2::platform::Device;

use crate::common::*;

#[derive(Debug, Clone)]
struct UdpBindError;

impl std::fmt::Display for UdpBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "get_udp(server_addr) has failed!")
    }
}
impl Error for UdpBindError {}

struct IPConnectClient {
    tun_device: Option<Device>,
    connection: Option<Connection>,
    udp_socket: Option<UdpSocket>
}

impl IPConnectClient {
    pub fn new() -> IPConnectClient {
        IPConnectClient {
            tun_device: None,
            connection: None,
            udp_socket: None
        }
    }

    pub async fn init(&mut self, server_addr: &String) {
        self.get_udp(server_addr).await.expect("Could not create udp socket!");
        self.get_tun().await.expect("Could not create TUN!");
        self.connect_quic(server_addr).await.expect("Could not connect to QUIC masquerade server!");
    }

    async fn get_udp(&mut self, server_addr: &String) -> Result<(), UdpBindError> {
        let server_name = format!("https://{}", server_addr); // TODO: avoid duplicate https://

        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        let socket = match UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await {
            Ok(v) => v,
            Err(e) => {
                error!("Could not bind Udp socket: {:?}", e);
                return Err(UdpBindError);
            }
        };

        match socket.connect(peer_addr.clone()).await {
            Ok(()) => {},
            Err(e) => {
                error!("Could not connect udp socket to peer address {}: {:?}", peer_addr, e);
                return Err(UdpBindError);
            }
        }

        self.udp_socket = Some(socket);
        Ok(())
    }

    async fn get_tun(&mut self) -> Result<Device, tun2::Error> {
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

        self.tun_device = Some(tun2::create(&config)?);
        // TODO: More init stuff for TUN device
        todo!();
    }

    async fn connect_quic(&mut self, server_addr: &String) -> Result<Connection, quiche::Error> {
        let server_name = format!("https://{}", server_addr); // TODO: avoid duplicate https://

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
        let local_addr = self.udp_socket.as_mut().unwrap().local_addr().unwrap();
        self.connection = Some(quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
            .expect("quic connection failed"));
        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            self.udp_socket.as_mut().unwrap().local_addr().unwrap(),
            hex_dump(&scid)
        );

        // TODO: Establish and add http3 connection, see how client does it

        todo!();
    }
}

