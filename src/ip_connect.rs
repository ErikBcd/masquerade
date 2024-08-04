use std::{collections::HashMap, net::{Ipv4Addr, SocketAddr, ToSocketAddrs}, sync::{Arc, Mutex}, u64};

use log::*;
use packet::{builder::Builder, icmp, ip, tcp, udp, Packet};
use quiche::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::{net::UdpSocket, sync::mpsc::{self, UnboundedSender}};
use tun2::platform::Device;

use futures::executor;

use crate::common::*;
use crate::ip_connect_util::*;
pub struct IPConnectClientStarter {
    client: Arc<Mutex<IPConnectClient>>
}

impl IPConnectClientStarter {
    pub fn new() -> IPConnectClientStarter {
        IPConnectClientStarter {client: Arc::new(Mutex::new(IPConnectClient::new()))}
    }

    pub async fn init(&mut self, server_addr: &String, bind_addr: &String) {
        self.client.lock().unwrap().init(server_addr, bind_addr).await;
    }

    pub async fn run(&mut self) {
        let local_client = self.client.clone();
        let dev = local_client.lock().unwrap()
            .create_tun().await.expect("Could not create TUN device!");

        let (reader, writer) = dev.split();
        let (tx, rx) = std::sync::mpsc::channel();

        debug!("Spawning IP handlers");
        let _t1 = std::thread::spawn(
            move || receive_ip_t(tx, reader));
        let _t2 = std::thread::spawn(
            move || handle_ip_t(local_client, rx, writer));

        //debug!("Spawning HTTP/3 handler");
        //let local_client = self.client.clone();
        //let _t3 = std::thread::spawn(
        //    move || handle_http3(local_client)
        //);

        // TODO: Threads should inform us that they are finished, 
        //       while() loop might be unnecessarily CPU intensive
        //while !_t1.is_finished() && !_t2.is_finished() && !_t3.is_finished() {
            
        //}
        while !_t1.is_finished() && !_t2.is_finished() {
            
        }
    }
}

/**
 * A client that sent data via the TUN interface
 * It has a list of streams which correspond to a number of ports
 */
struct IPClient {
    streams: Arc<Mutex<HashMap<u16, u64>>>
}

pub struct IPConnectClient {
    pub connection: Option<Connection>,
    pub udp_socket: Option<UdpSocket>,
    streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
    clients: Arc<Mutex<HashMap<Ipv4Addr, IPClient>>>, // Maps clients to streams based on their ip addr
    http3_sender: Option<Arc<Mutex<UnboundedSender<ToSend>>>>,
}

impl IPConnectClient {
    pub fn new() -> IPConnectClient {
        IPConnectClient {
            connection: None,
            udp_socket: None,
            streams: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            http3_sender: None
        }
    }

    pub async fn init(&mut self, server_addr: &String, bind_addr: &String) {
        // TODO: Disabled for testing
        //self.get_udp(bind_addr).await.expect("Could not create udp socket!");
        //self.connect_quic(server_addr).await.expect("Could not connect to QUIC masquerade server!");
    }

    /**
     * Creates and binds the UDP socket used for QUIC
     */
    async fn get_udp(&mut self, bind_addr: &String) -> Result<(), UdpBindError> {
        let mut http_start = "";
        if !bind_addr.starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}",http_start, bind_addr); 

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
    pub fn handle_ip_packet(
        &mut self, pkt: &mut packet::ip::v4::Packet<&[u8]>) -> Result<Vec<u8>, HandleIPError> {
        //println!("Totally handling a packet rn");
        let sender = pkt.source();
        let dest = pkt.destination();
        
        debug!("Handling packet from {} to {}", sender, dest);

        let mut port: u16 = 0;

        // Not sure if we actually need to handle the packets depending on the protocol
        match pkt.protocol() {
            ip::Protocol::Icmp => {
                if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                    if let Ok(icmp) = icmp.echo() {
                        debug!(
                            "Received ICMP: Source={:?} | Dest={:?} | Seq={:?}", 
                            pkt.source(),
                            pkt.destination(),
                            icmp.sequence(), 
                        );

                        let reply = ip::v4::Builder::default()
                            .id(0x42).unwrap()
                            .ttl(64).unwrap()
                            .source(pkt.destination()).unwrap()
                            .destination(pkt.source()).unwrap()
                            .icmp().unwrap()
                            .echo().unwrap()
                            .reply().unwrap()
                            .identifier(icmp.identifier()).unwrap()
                            .sequence(icmp.sequence()).unwrap()
                            .payload(icmp.payload()).unwrap()
                            .build().unwrap();
                        return Ok(reply);
                    }
                }
            },
            ip::Protocol::Tcp => {
                if let Ok(tcp) = tcp::Packet::new(pkt.payload()) {
                    debug!(
                        "Received TCP: Source={:?} | Dest={:?} | Seq={:?} | Ack={:?}",
                        tcp.source(),
                        tcp.destination(),
                        tcp.sequence(),
                        tcp.acknowledgment()
                    );
                    port = tcp.destination();
                }
            },
            ip::Protocol::Udp => {
                if let Ok(udp) = udp::Packet::new(pkt.payload()) {
                    debug!(
                        "Received UDP: Source={} | Dest={}",
                        udp.source(),
                        udp.destination()
                    );
                    port = udp.destination();
                }
            }
            _ => {}
        }
        // Get a client IP Connect stream (create one of needed)
        if port == 0 {
            return Err(HandleIPError {message: "Protocol not implemented".to_owned()});
        }
        let streamID = match self.get_or_create_client_stream(port, pkt.source()) {
            Ok(v) => v,
            Err(e) => {
                return Err(HandleIPError {message: e.to_string()});
            }
        };

        // Got the correct stream, now we can finally send our content
        self.send_ip_to_quicstream(streamID, pkt);

        // TODO: Do we have to send anything back instantly?
        Ok(vec![0, 0, 0])
        //todo!();
    }

    fn send_ip_to_quicstream(&self, streamID: u64, pkt: &mut packet::ip::v4::Packet<&[u8]>) {
        // TODO
        todo!()
    }

    fn get_or_create_client_stream(&self, port: u16, source: Ipv4Addr) -> Result<u64, QUICStreamError> {
        // Check if given packet already has a stream
        let binding = self.clients.lock().unwrap();
        let c = match binding.get(&source) {
            Some(v) => v,
            None => {
                // create a new client 
                // TODO
                todo!()
            }
        };

        let binding = c.streams.lock().unwrap();
        match binding.get(&port) {
            Some(v) => Ok(v.clone()),
            None => {
                // Create a new stream and put into client
                executor::block_on(self.create_connect_ip_stream());
                
                // TODO
                todo!()
                // Err(QUICStreamError { message: "Could not get stream!".to_owned()})
            }
        }
    }

    /**
     * Creates a new CONNECT-IP stream and adds it to the existing streams
     * Returns the streams ID when successful.
     */
    async fn create_connect_ip_stream(&self) -> Result<u64, HandleIPError> {
        // create commect-ip message
        // TODO: Get authority (address of connect server)
        let headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"), // TODO: Should always be https?
            quiche::h3::Header::new(b":authority", b""), // TODO
            quiche::h3::Header::new(b"path", b"/.well-known/masque/ip/*/*/"), 
            quiche::h3::Header::new(b"connect-ip-version", b"3"),
        ];

        // Now send content via http3_sender
        let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
        let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();
        
        self.http3_sender.as_ref().unwrap().lock().unwrap().send(
            ToSend { 
                stream_id: u64::MAX, 
                content: Content::Request { headers: headers, stream_id_sender: stream_id_sender }, 
                finished: false }
        )
        .unwrap_or_else(|e| error!("sending http3 request failed: {:?}", e));

        let stream_id = stream_id_receiver
                .recv()
                .await.expect("stream_id receiver error");
        
        {
            let mut streams = self.streams.lock().unwrap();
            streams.insert(stream_id, response_sender);
            // TODO: potential race condition: the response could be received before connect_streams is even inserted and get dropped
        }

        // TODO: Await response from the server.

        Ok(stream_id)
        
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

