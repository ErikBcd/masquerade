use std::{error::Error, io::Read, net::{SocketAddr, ToSocketAddrs}, sync::Arc, time::Duration};

use log::*;
use packet::ip;
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::{net::UdpSocket, sync::Mutex, time::sleep};
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

#[derive(Debug, Clone)]
struct HandleIPError;
impl std::fmt::Display for HandleIPError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "get_udp(server_addr) has failed!")
    }
}
impl Error for HandleIPError {}

pub struct IPConnectClientStarter {
    client: Arc<Mutex<IPConnectClient>>
}

impl IPConnectClientStarter {
    pub fn new() -> IPConnectClientStarter {
        IPConnectClientStarter {client: Arc::new(Mutex::new(IPConnectClient::new()))}
    }

    pub async fn init(&mut self, server_addr: &String, bind_addr: &String) {
        self.client.lock().await.init(server_addr, bind_addr).await;
    }

    pub async fn run(&mut self) {
        // TODO: Figure out how concurrency works in rust
        loop {
            sleep(Duration::from_secs(1)).await;
            println!("I'm still running smile");
        }
    }

    /**
     * Runs a TUN client.
     * Will spawn threads for receiving and handling incoming IP messages.
     * 
     * Currently only handles IPv4 packets!
     * 
     * Panics on errors with channels!
     */
    pub async fn run_tun(&mut self) {
        let local_client = self.client.clone();
        let dev = local_client.lock().await
            .create_tun().await.expect("Could not create TUN device!");

        let (mut reader, mut writer) = dev.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        
        // Thread for handling incoming raw ip messages
        // Sends packets to receiver
        tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let size = reader.read(&mut buf)?;
                let pkt = &buf[..size];
                if let Err(e) = tx.send(pkt.to_vec()).await {
                    debug!("Receiver dropped: {:?}", e);
                    break;
                };
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
        
        // Thread for handling received messages
        // Checks if the packet is an IPv4 packet
        // Lets the client handle these packets.
        tokio::spawn(async move {
            loop {
                println!("Test");
                if let Some(pkt) = rx.recv().await {
                    println!("Received.. something. ");
                    match ip::Packet::new(pkt.as_slice()) {
                        Ok(ip::Packet::V4(mut pkt)) => {
                            local_client.lock().await
                                .handle_ip_packet(&mut pkt).await.expect("Error handling ip packet");
                        },
                        Ok(_) => {
                            debug!("Received packet with unsupported protocol version.");
                        }
                        Err(err) => println!("Received an invalid packet: {:?}", err),
                    }
                }
            }
        });
        loop {
            sleep(Duration::from_secs(1)).await;
        }
    }
}
struct IPConnectClient {
    connection: Option<Connection>,
    udp_socket: Option<UdpSocket>
}

impl IPConnectClient {
    pub fn new() -> IPConnectClient {
        IPConnectClient {
            connection: None,
            udp_socket: None
        }
    }

    pub async fn init(&mut self, server_addr: &String, bind_addr: &String) {
        // TODO: Uncommented for testing!
        //self.get_udp(bind_addr).await.expect("Could not create udp socket!");
        //self.connect_quic(server_addr).await.expect("Could not connect to QUIC masquerade server!");
    }

    /**
     * Creates and binds the UDP socket used for QUIC
     */
    async fn get_udp(&mut self, bind_addr: &String) -> Result<(), UdpBindError> {
        let server_name = format!("https://{}", bind_addr); // TODO: avoid duplicate https://

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

    /**
     * Creates a TUN. 
     * Currently config is hardcoded:
     *  - Address = 10.0.0.9
     *  - Netmaks = 255.255.255.0
     *  - Dest    = 10.0.0.1
     * 
     * Warning: Needs root priviligies on linux!
     */
    pub async fn create_tun(&mut self) -> Result<Device, tun2::Error> {
        // TODO: Let user assign IP configuration if needed
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
     * Handles a ip packet
     * Will check if it is a valid packet,
     * Then it will check if the client that sent this packet is already known,
     * and if it has a tunnel established.
     * 
     * If not we accept that client and create a new CONNECT_IP HTTP/3 tunnel
     * 
     * If a tunnel exists just pack the packet and send it via HTTP/3.
     * 
     * If the packet is malformed we reject it.
     */
    async fn handle_ip_packet(
        &mut self, pkt: &mut packet::ip::v4::Packet<&[u8]>) -> Result<Vec<u8>, HandleIPError> {
        println!("Totally handling a packet rn");
        Ok(vec![0, 0, 0])
        //todo!();
    }

    /**
     * Creates a new QUIC connection and connects to the given server.
     */
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

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let (write, send_info) = self.connection.as_mut().unwrap()
            .send(&mut out).expect("initial send failed");

        while let Err(e) = self.udp_socket.as_mut().unwrap()
            .send_to(&out[..write], send_info.to).await {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send_to() would block");
                continue;
            }
            panic!("UDP socket send_to() failed: {:?}", e);
        }
        debug!("written {}", write);

        todo!();
    }
}

