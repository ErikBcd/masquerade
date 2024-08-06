use std::{collections::HashMap, net::{Ipv4Addr, SocketAddr, ToSocketAddrs}, sync::{Arc, Mutex}, u64};

use log::*;
use packet::{builder::Builder, icmp, ip, tcp, udp, Packet};
use quiche::{h3::NameValue, Connection};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::{net::UdpSocket, sync::mpsc::{self, UnboundedSender}};
use tun2::platform::Device;

use futures::executor;

use crate::common::*;
use crate::ip_connect::util::*;

use super::capsules::{AddressAssign, AddressRequest, AssignedAddress, Capsule, IpLength, RequestedAddress};
pub struct IPConnectClientStarter {
    client: Arc<Mutex<IPConnectClient>>
}

impl IPConnectClientStarter {
    pub fn new() -> IPConnectClientStarter {
        IPConnectClientStarter {client: Arc::new(Mutex::new(IPConnectClient::new()))}
    }

    pub async fn run(&mut self, server_addr: &String, bind_addr: &String) {
        // This creates & connects the TUN interface, the QUIC connection and the http3 stream
        self.client.lock().unwrap().init(server_addr, bind_addr).await;

        // Immediately spawn the h3 handler
        // We expect the server to send ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT 
        // right after the init
        debug!("Spawning HTTP/3 handler");
        let local_client = self.client.clone();
        let _t3 = std::thread::spawn(
            move || handle_http3(local_client) 
        );

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

        // TODO: Threads should inform us that they are finished, 
        //       while() loop might be unnecessarily CPU intensive
        while !_t1.is_finished() && !_t2.is_finished() && !_t3.is_finished() {
            
        }
    }
}

pub struct QuicStream {
    pub stream: Arc<Mutex<UnboundedSender<Content>>>,
    pub stream_id: u64,
    pub flow_id: u64,
}

pub struct IPConnectClient {
    pub connection: Option<Connection>,
    pub udp_socket: Option<UdpSocket>,
    pub http3_sender: Option<Arc<Mutex<UnboundedSender<ToSend>>>>,
    pub stream: Option<QuicStream>,
}

impl IPConnectClient {
    pub fn new() -> IPConnectClient {
        IPConnectClient {
            connection: None,
            udp_socket: None,
            http3_sender: None,
            stream: None,
        }
    }

    pub async fn init(&mut self, server_addr: &String, bind_addr: &String) {
        self.get_udp(bind_addr)
            .await
            .expect("Could not create udp socket!");
        self.connect_quic(server_addr)
            .await
            .expect("Could not connect to QUIC masquerade server!");
        self.create_connect_ip_stream()
            .await
            .unwrap_or_else(|e| error!("Creating the connect-ip stream failed: {}", e));
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

        // TODO: Remove this, it's only for debugging 
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
                }
            },
            ip::Protocol::Udp => {
                if let Ok(udp) = udp::Packet::new(pkt.payload()) {
                    debug!(
                        "Received UDP: Source={} | Dest={}",
                        udp.source(),
                        udp.destination()
                    );
                }
            }
            _ => {}
        }
        
        todo!();
    }

    pub fn handle_capsule(&mut self, capsule: Capsule) {
        todo!()
    }

    /**
     * Sends a ipv4 packet to a stream.
     * Will encapsulate the packet into a DATAGRAM
     */
    fn send_ip_to_quicstream(&self, pkt: &mut packet::ip::v4::Packet<&[u8]>) {
        // TODO
        todo!()
    }

    /**
     * Creates a new CONNECT-IP stream and sets it as the currently active stream.
     * This will also spawn the http3 handler that will wait for new packets.
     */
    async fn create_connect_ip_stream(&mut self) -> Result<(), HandleIPError> {
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
        let flow_id = stream_id / 4;

        // Save this stream we just created
        {
            self.stream = Some(QuicStream {
                stream: Arc::new(Mutex::new(response_sender)),
                stream_id: stream_id,
                flow_id: flow_id
            });
        }
        
        let mut succeeded = false;

        let response = response_receiver
            .recv()
            .await
            .expect("http3 response receiver error");

        // Check if the response was positive
        // We expect the status code to be in 2xx range
        if let Content::Headers { headers } = response {
            debug!(
                "Got response {:?}",
                hdrs_to_strings(&headers)
            );

            let mut status = None;
            for hdr in headers {
                match hdr.name() {
                    b":status" => {
                        status = Some(hdr.value().to_owned())
                    }
                    _ => (),
                }
            }

            if let Some(status) = status {
                if let Ok(status_str) =
                    std::str::from_utf8(&status)
                {
                    if let Ok(status_code) =
                        status_str.parse::<i32>()
                    {
                        if status_code >= 200
                            && status_code < 300
                        {
                            succeeded = true;
                            debug!("CONNECT-IP connection established for flow {}", flow_id);
                        }
                    }
                }
            }
        } else {
            error!("received others when expecting headers for connect");
        }

        if !succeeded {
            error!("http3 CONNECT UDP failed");
            self.stream = None;
            return Err(HandleIPError { message: "http3 CONNECT UDP failed".to_string() });
        }
        // Now send address assign capsule via data stream

        let addr_request = RequestedAddress {
            request_id: 0,
            ip_version: 4,
            ip_address: IpLength::V4(
                Ipv4Addr::new(0, 0, 0, 0).into()
            ),
            ip_prefix_len: 32
        };

        let request_capsule = AddressRequest {
            length: 9,
            requested: vec![addr_request]
        };

        let cap = Capsule {
            capsule_id: 1,
            capsule_type: super::capsules::CapsuleType::AddressRequest(request_capsule)
        };

        let mut buf = [0; 9];
        cap.serialize(&mut buf);

        self.http3_sender.as_ref().unwrap().lock().unwrap().send(
            ToSend { 
                stream_id: stream_id, 
                content: Content::Data { data: buf.to_vec() }, 
                finished: false }
        ).unwrap_or_else(|e| error!("sending http3 data capsule failed: {:?}", e));

        todo!()
    }

    /**
     * Creates a new QUIC connection and connects to the given server.
     */
    async fn connect_quic(&mut self, server_addr: &String) -> Result<Connection, quiche::Error> {
        let mut http_start = "";
        if !server_addr.starts_with("https://") {
            http_start = "https://";
        }
        let server_name = format!("{}{}",http_start, server_addr); 

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

    pub fn get_pending_quic_messages(&self) -> Vec<Vec<u8>> {
        todo!()
    }
}

