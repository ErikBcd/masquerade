use log::*;
use octets::varint_len;
use quiche::h3::NameValue;
use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

use std::collections::HashMap;
use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};
use tokio::time::{self, Duration};

use ring::rand::*;

use crate::common::*;
use crate::connect_ip::capsules::*;
use crate::connect_ip::util::*;

const MAX_CHANNEL_MESSAGES: usize = 400;
const STANDARD_NETMASK: u32 = 0xFFFFFF00;

/////////////////////////////////////////////////////////////////////
///                             STRUCTS                           ///
/////////////////////////////////////////////////////////////////////
///
/// Used for requesting an IP from the ip register thread.
/// Contains information about the client
/// 
struct IpRegisterRequest {
    requested_address: Ipv4Addr,
    id: String,
    callback: Sender<Ipv4Addr>,
    former_ip: Ipv4Addr,
    static_addr: bool,
}

/// 
/// Base struct for a client that has connected to the server.
/// Mainly used to send messages to the client_handler thread started from the Server.run()
/// 
struct Client {
    conn: quiche::Connection,
    quic_receiver: mpsc::UnboundedReceiver<QuicReceived>,
    socket: Arc<UdpSocket>,
}

///
/// A client that connected to the server.
/// Once the CONNECT-IP session is established, `sender` contains a channel that the 
/// TUN handling can use to send messages towards the client.
/// 
#[derive(Clone)]
struct ConnectIpClient {
    assigned_addr: Ipv4Addr,
    id: String,
    static_addr: bool,
    sender: Option<Sender<Vec<u8>>>,
}

/// Map of known clients that operate via CONNECT-IP, identified by their assigned IPs
type ConnectIpClientList = Arc<Mutex<HashMap<Ipv4Addr, ConnectIpClient>>>;
/// Map of registered clients that use CONNECT-IP and want specific IPs
pub type StaticClientMap = Arc<Mutex<HashMap<String, Ipv4Addr>>>;
/// Map for known clients for the QUIC server, to find the recipient of received QUIC messages
type ClientMap = HashMap<quiche::ConnectionId<'static>, mpsc::UnboundedSender<QuicReceived>>;

/// Containes a received QUIC message
struct QuicReceived {
    recv_info: quiche::RecvInfo,
    data: Vec<u8>,
}

/// Session data for an established CONNECT-IP client
/// stream_id is used for the DATA messages (capsules),
/// flow_id is used for datagrams,
/// ip_h3_sender is used to send HTTP/3 messages to the CONNECT-IP session threads
/// handler_thread is the thread containing the connect_ip_handler handle
struct IpConnectSession {
    stream_id: u64,
    flow_id: u64,
    ip_h3_sender: Sender<Content>,
    handler_thread: Option<JoinHandle<()>>,
}

/// Data for a client
/// connect_ip_session: For when the CONNECT-IP session is started
/// client_ip: The assigned IP for the client on the server subnet
/// http3_sender: Used to send HTTP/3 messages towards the client
/// connect_ip_clients: Map for the clients that are currently connected to the server
/// static_clients: Map of IPs that are currently reserved on the server
/// register_handler: Channel for messages towards the IP register threads.
struct ClientHandler {
    connect_ip_session: Option<IpConnectSession>,
    client_ip: Ipv4Addr,
    http3_sender: mpsc::UnboundedSender<ToSend>,
    connect_ip_clients: ConnectIpClientList,
    static_clients: StaticClientMap,
    register_handler: tokio::sync::mpsc::Sender<IpRegisterRequest>,
}

///
/// Configuration aggregator for the server.
/// 
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub server_address: Option<String>,
    pub interface_address: Option<String>,
    pub interface_name: Option<String>,
    pub local_uplink_device_ip: Option<String>,
    pub local_uplink_device_name: Option<String>,
    pub client_config_path: Option<String>,
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

impl std::fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\
            server_address              = {:?}\n\
            interface_address           = {:?}\n\
            interface_name              = {:?}\n\
            local_uplink_device_ip      = {:?}\n\
            local_uplink_device_name    = {:?}\n\
            client_config_path          = {:?}\n\
            create_qlog_file            = {:?}\n\
            qlog_file_path              = {:?}\n\
            mtu                         = {:?}\n\
            congestion_algorithm        = {:?}\n\
            max_pacing_rate             = {:?}\n\
            disable_active_migration    = {:?}\n\
            enable_hystart              = {:?}\n\
            discover_pmtu               = {:?}\n\
            ack_delay_exponent          = {:?}\n\
            max_ack_delay               = {:?}\n\
            max_idle_timeout            = {:?}\n\
            ",
            self.server_address.as_ref().unwrap(),
            self.interface_address.as_ref().unwrap(),
            self.interface_name.as_ref().unwrap(),
            self.local_uplink_device_ip.as_ref().unwrap(),
            self.local_uplink_device_name.as_ref().unwrap(),
            self.client_config_path.as_ref().unwrap(),
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

/////////////////////////////////////////////////////////////////////
///                             ERRORS                            ///
/////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

/////////////////////////////////////////////////////////////////////
///                             SERVER                            ///
/////////////////////////////////////////////////////////////////////

#[derive(Default)]
pub struct Server {
    socket: Option<Arc<UdpSocket>>,
}

impl Server {
    /**
     * Get the socket address the server is bound to. Returns None if server is not bound to a socket yet
     */
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.socket
            .clone()
            .map(|socket| socket.local_addr().unwrap())
    }

    /**
     * Bind the server to listen to an address
     */
    pub async fn bind<T: tokio::net::ToSocketAddrs>(
        &mut self,
        listen_addr: T,
    ) -> Result<(), Box<dyn Error>> {
        debug!("creating UDP socket");

        // Create the UDP listening socket, and register it with the event loop.
        let socket = UdpSocket::bind(listen_addr).await?;
        debug!("listening on {}", socket.local_addr().unwrap());

        self.socket = Some(Arc::new(socket));
        Ok(())
    }

    pub async fn run(&self, server_config: ServerConfig) -> Result<(), Box<dyn Error>> {
        if self.socket.is_none() {
            return Err(Box::new(RunBeforeBindError));
        }
        let socket = self.socket.clone().unwrap();

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Create the configuration for the QUIC connections.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        config
            .load_cert_chain_from_pem_file("example_cert/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("example_cert/cert.key")
            .unwrap();

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        
        // Only set a maximum timeout if the value is something 
        // Will be none if user specified timeout of 0
        if server_config.max_idle_timeout.is_some() {
            config.set_max_idle_timeout(server_config.max_idle_timeout.unwrap());
        }
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(1000);
        config.set_initial_max_streams_uni(1000);
        config.set_disable_active_migration(server_config.disable_active_migration.unwrap());
        config.enable_pacing(true);
        config.set_max_pacing_rate(server_config.max_pacing_rate.unwrap());
        match server_config.congestion_algorithm.as_ref().unwrap().as_str() {
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
        config.enable_hystart(server_config.enable_hystart.unwrap());
        config.discover_pmtu(server_config.discover_pmtu.unwrap());
        config.set_ack_delay_exponent(server_config.ack_delay_exponent.unwrap());
        config.set_max_ack_delay(server_config.max_ack_delay.unwrap());
        config.enable_dgram(true, 1000, 1000);
        config.enable_early_data();

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut clients = ClientMap::new();

        // CONNECT-IP things
        let (addr, _prefix) = split_ip_prefix(
            server_config
                .interface_address
                .as_ref()
                .unwrap()
                .to_string(),
        );
        let ipaddr = Ipv4Addr::from_str(&addr).unwrap();

        let mut current_ip = match get_next_ipv4(ipaddr, 0xFFFF0000) {
            Ok(v) => v,
            Err(e) => {
                panic!("Could not get a new IP: {e}");
            }
        };

        current_ip = match get_next_ipv4(current_ip, 0xFFFF0000) {
            Ok(v) => v,
            Err(e) => {
                panic!("Could not get a new IP: {e}");
            }
        };

        // Read statically assigned clients from config file if it exists
        let static_clients =
            match read_known_clients(server_config.client_config_path.as_ref().unwrap()).await {
                Ok(v) => v,
                Err(e) => {
                    panic!("Could not read static clients: {e}");
                }
            };

        let connect_ip_clients: ConnectIpClientList = Arc::new(Mutex::new(HashMap::new()));
        // Add all static clients to connect_ip_clients
        for (id, ip) in static_clients.lock().await.iter() {
            info!("Adding known client: {} at {}", id, ip);
            connect_ip_clients.lock().await.insert(
                *ip,
                ConnectIpClient {
                    assigned_addr: *ip,
                    id: id.to_string(),
                    static_addr: true,
                    sender: None,
                },
            );
        }

        // Start the handler for new clients
        let (client_register_sender, client_register_recv) = tokio::sync::mpsc::channel(1);
        let connect_ip_clients_clone = connect_ip_clients.clone();
        let static_clients_clone = static_clients.clone();
        let client_conf_path = server_config.client_config_path.as_ref().unwrap().clone();
        let _client_register_t = tokio::spawn(async move {
            client_register_handler(
                client_register_recv,
                connect_ip_clients_clone,
                static_clients_clone,
                client_conf_path,
            )
            .await
        });

        let (tun_sender, tun_receiver) =
            tokio::sync::mpsc::channel::<Vec<u8>>(MAX_CHANNEL_MESSAGES);
        // Create TUN handler (creates device automatically)
        let connect_ip_clients_clone = connect_ip_clients.clone();
        let server_config_clone = server_config.clone();
        let _tun_thread = tokio::spawn(async move {
            tun_socket_handler(connect_ip_clients_clone, tun_receiver, server_config_clone).await;
        });

        let local_addr = socket.local_addr().unwrap();
        'read: loop {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,

                Err(e) => {
                    panic!("recv_from() failed: {:?}", e);
                }
            };

            debug!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            debug!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let tx = if !clients.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id) {
                // TODO: move initialization to client task
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from).await {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send_to() would block");
                            break;
                        }

                        panic!("send_to() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");
                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from).await {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send_to() would block");
                            break;
                        }

                        panic!("send_to() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn =
                    quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                let (tx, rx) = mpsc::unbounded_channel();

                let mut client = Client {
                    conn,
                    quic_receiver: rx,
                    socket: socket.clone(),
                };

                // If the user wanted it, create a qlog file
                if server_config.create_qlog_file.unwrap() {
                    if let Some(dir) = server_config.qlog_file_path.clone() {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        client.conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                clients.insert(scid.clone(), tx);
                let tun_sender_clone = tun_sender.clone();
                let connect_ip_clients_clone = connect_ip_clients.clone();
                let static_clients_clone = static_clients.clone();
                let register_handler_clone = client_register_sender.clone();
                // FIrst reserve an address for the client
                {
                    let mut clients_bind = connect_ip_clients.lock().await;
                    if let Some(v) = get_next_free_ip(current_ip, &clients_bind) {
                        current_ip = v;
                        clients_bind.insert(
                            current_ip,
                            ConnectIpClient {
                                assigned_addr: current_ip,
                                id: "".to_string(),
                                static_addr: false,
                                sender: None,
                            },
                        );
                    }
                }
                tokio::spawn(async move {
                    handle_client(
                        client,
                        current_ip,
                        &tun_sender_clone,
                        connect_ip_clients_clone,
                        static_clients_clone,
                        register_handler_clone,
                    )
                    .await
                });

                clients.get(&scid).unwrap()
            } else {
                match clients.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            match tx.send(QuicReceived {
                recv_info,
                data: pkt_buf.to_vec(),
            }) {
                Ok(_) => {}
                _ => {
                    debug!("Error sending to {:?}", &hdr.dcid);
                    clients.remove(&hdr.dcid);
                }
            }
        }

        Ok(())
    }
}

///
/// Reads the known-clients toml file from disk and parses it
/// If the file doesn't exist we create it in the default location
///
pub async fn read_known_clients(config_path: &String) -> Result<StaticClientMap, ConfigError> {
    // Check if the file exists
    if !Path::new(&config_path).exists() {
        File::create_new(&config_path).await.unwrap_or_else(|e| {
            panic!("Could not create config file at \"{}\": {}", config_path, e)
        });
        return Ok(Arc::new(Mutex::new(HashMap::new())));
    }

    let mut file = match File::open(config_path.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Err(ConfigError::ConfigFileError((
                e.to_string(),
                config_path.to_owned(),
            )));
        }
    };
    let mut config_contents = String::new();
    match file.read_to_string(&mut config_contents).await {
        Ok(_) => {}
        Err(e) => {
            return Err(ConfigError::ConfigFileError((
                e.to_string(),
                config_path.to_owned(),
            )));
        }
    }
    #[derive(Deserialize, Debug)]
    struct Client {
        ip: String,
        id: String,
    }

    #[derive(Deserialize, Debug)]
    struct Config {
        #[serde(default)]
        clients: Vec<Client>,
    }

    let clients: Config = toml::from_str(&config_contents).unwrap();
    let res: StaticClientMap = Arc::new(Mutex::new(HashMap::new()));
    for c in clients.clients {
        res.lock()
            .await
            .insert(c.id, Ipv4Addr::from_str(&c.ip).unwrap());
    }
    Ok(res)
}




/**
 * Client handler that handles the connection for a single client
 */
async fn handle_client(
    mut client: Client,
    client_ip: Ipv4Addr,
    tun_sender: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ip_connect_clients: ConnectIpClientList,
    static_clients: StaticClientMap,
    register_handler: tokio::sync::mpsc::Sender<IpRegisterRequest>,
) {
    let mut http3_conn: Option<quiche::h3::Connection> = None;
    let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
    let mut client_handler = ClientHandler {
        connect_ip_session: None,
        client_ip,
        http3_sender,
        connect_ip_clients: ip_connect_clients.clone(),
        static_clients: static_clients.clone(),
        register_handler,
    };

    let mut out = [0; MAX_DATAGRAM_SIZE];

    let timeout = 5000; // milliseconds
    let sleep = tokio::time::sleep(Duration::from_millis(timeout));
    tokio::pin!(sleep);

    let mut http3_retry_send: Option<ToSend> = None;
    let mut interval = time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            // Send pending HTTP3 data in channel to HTTP3 connection on QUIC
            http3_to_send = http3_receiver.recv(),
                            if http3_conn.is_some() && http3_retry_send.is_none() => {
                if http3_to_send.is_none() {
                    unreachable!()
                }
                let mut to_send = http3_to_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                loop {
                    let result = match &to_send.content {
                        Content::Request { headers: _, stream_id_sender: _} => unreachable!(),
                        Content::Headers { headers } => {
                            debug!("sending http3 response {:?}", hdrs_to_strings(headers));
                            http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                        },
                        Content::Data { data } => {
                            debug!("sending http3 data of {} bytes to steam {}", data.len(), to_send.stream_id);
                            let mut written = 0;
                            loop {
                                if written >= data.len() {
                                    break Ok(())
                                }
                                match http3_conn.send_body(&mut client.conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                            //http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                            match send_h3_dgram(&mut client.conn, to_send.stream_id, payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed! {:?}", e);
                                            break;
                                        }
                                    }
                        },
                        Content::Finished => {
                            // TODO: Possibly kill IP Session?
                            Ok(())
                        },
                    };
                    match result {
                        Ok(_) => {},
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            if client.conn.stream_finished(to_send.stream_id) {
                                // TODO: Possibly kill IP Session?
                                break;
                            }

                            debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
                            break;
                        },
                        Err(e) => {
                            error!("A Connection {} stream {} send failed {:?}", client.conn.trace_id(), to_send.stream_id, e);
                            // TODO: Possibly kill IP Session?
                            break;
                        }
                    };
                    to_send = match http3_receiver.try_recv() {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                }
            },

            // handle QUIC received data
            recvd = client.quic_receiver.recv() => {
                match recvd {
                    Some(mut quic_received) => {
                        let read = match client.conn.recv(&mut quic_received.data, quic_received.recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Error when quic recv(): {}", e);
                                break
                            }
                        };
                        debug!("{} processed {} bytes", client.conn.trace_id(), read);

                    },
                    None => {
                        break // channel closed on the other side. Should not happen?
                    },
                }
                // Create a new HTTP/3 connection as soon as the QUIC connection
                // is established.
                if (client.conn.is_in_early_data() || client.conn.is_established()) &&
                    http3_conn.is_none()
                {
                    http3_conn = match create_http3_conn(&mut client) {
                        Some(v) => Some(v),
                        None => {continue}
                    }
                }

                if http3_conn.is_some() {
                    // Process HTTP/3 events.
                    let http3_conn = http3_conn.as_mut().unwrap();
                    while (handle_http3_event(
                        http3_conn,
                        &mut client,
                        &mut client_handler,
                        tun_sender).await).is_ok() {};
                }
            },

            // Retry sending in case of stream blocking
            _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                let mut to_send = http3_retry_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                let result = match &to_send.content {
                    Content::Request { headers: _, stream_id_sender: _ } => unreachable!(),
                    Content::Headers { headers } => {
                        debug!("retry sending http3 response {:?}", hdrs_to_strings(headers));
                        http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                    },
                    Content::Data { data } => {
                        debug!("retry sending http3 data of {} bytes", data.len());
                        let mut written = 0;
                        loop {
                            if written >= data.len() {
                                break Ok(())
                            }
                            match http3_conn.send_body(&mut client.conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                       // http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                        match send_h3_dgram(&mut client.conn, to_send.stream_id, payload) {
                                        Ok(v) => Ok(v),
                                        Err(e) => {
                                            error!("sending http3 datagram failed: {:?}", e);
                                            break;
                                        }
                                    }
                    },
                    Content::Finished => todo!(),
                };
                match result {
                    Ok(_) => {
                        http3_retry_send = None;
                    },
                    Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                        debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                        http3_retry_send = Some(to_send);
                    },
                    Err(e) => {
                        error!("B Connection {} stream {} send failed {:?}",
                            client.conn.trace_id(),
                            to_send.stream_id, e);
                        // TODO: Possibly kill IP Session?
                        http3_retry_send = None;
                    }
                };
            },

            () = &mut sleep => {
                trace!("timeout elapsed");
                sleep.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout));

                if client.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        client.conn.trace_id(),
                        client.conn.stats()
                    );
                }
            },
            else => break,
        }
        // Send pending QUIC packets
        loop {
            let (write, send_info) = match client.conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("QUIC connection {} done writing", client.conn.trace_id());
                    break;
                }

                Err(e) => {
                    error!(
                        "QUIC connection {} send failed: {:?}",
                        client.conn.trace_id(),
                        e
                    );

                    client.conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            match client.socket.send_to(&out[..write], send_info.to).await {
                Ok(written) => debug!(
                    "{} written {} bytes out of {}",
                    client.conn.trace_id(),
                    written,
                    write
                ),
                Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
            }
        }
    }
}

/// 
/// Creates a new HTTP/3 connection for an existing & established QUIC connection
/// 
fn create_http3_conn(client: &mut Client) -> Option<quiche::h3::Connection> {
    debug!(
        "{} QUIC handshake completed, now trying HTTP/3",
        client.conn.trace_id()
    );

    let h3_config = quiche::h3::Config::new().unwrap();
    let h3_conn = match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
        Ok(v) => v,

        Err(e) => {
            error!("failed to create HTTP/3 connection: {}", e);
            return None;
        }
    };

    // TODO: sanity check h3 connection before adding to map
    Some(h3_conn)
}

/// 
/// Processes an HTTP/3 event
/// Creates CONNECT-IP session if requested.
/// 
async fn handle_http3_event(
    http3_conn: &mut quiche::h3::Connection,
    client: &mut Client,
    client_handler: &mut ClientHandler,
    tun_sender: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(), ClientError> {
    let mut buf = [0; 65535];
    // Process datagram-related events.
    while let Ok(len) = client.conn.dgram_recv(&mut buf) {
        let mut b = octets::Octets::with_slice(&buf);
        if let Ok(flow_id) = b.get_varint() {
            info!("Received DATAGRAM flow_id={} len={}", flow_id, len,);

            // TODO: Check if this is actually a good way to check for the
            // length of the flow_id

            let flow_id_len = varint_len(flow_id);
            if client_handler.connect_ip_session.is_some() {
                {
                    let ip_session = client_handler.connect_ip_session.as_ref().unwrap();
                    if ip_session.flow_id == flow_id {
                        let data = &buf[flow_id_len..len];
                        ip_session
                            .ip_h3_sender
                            .send(Content::Datagram {
                                payload: data.to_vec(),
                            })
                            .await
                            .expect("Could not send datagram to ip handler.");
                    }
                }
            } else {
                debug!("received datagram on unknown flow: {}", flow_id)
            }
        }
    }
    match http3_conn.poll(&mut client.conn) {
        Ok((stream_id, quiche::h3::Event::Headers { list: headers, .. })) => {
            info!(
                "{} got request {:?} on stream id {}",
                client.conn.trace_id(),
                hdrs_to_strings(&headers),
                stream_id
            );

            let mut method = None;
            let mut authority = None;
            let mut protocol = None;
            let mut scheme = None;
            let mut path = None;

            // Look for the request's path and method.
            for hdr in headers.iter() {
                match hdr.name() {
                    b":method" => method = Some(hdr.value()),
                    b":authority" => authority = Some(std::str::from_utf8(hdr.value()).unwrap()),
                    b":protocol" => protocol = Some(hdr.value()),
                    b":scheme" => scheme = Some(hdr.value()),
                    b":path" => path = Some(hdr.value()),
                    _ => (),
                }
            }
            if method == Some(b"CONNECT") {
                if let Some(authority) = authority {
                    if protocol == Some(b"connect-ip") && scheme.is_some() && path.is_some()
                    // && !authority.is_empty()
                    {
                        debug!("Got request for connect-ip!");
                        // Check the path
                        let path = path.unwrap();

                        debug!(
                            "connecting ip to {} from authority {}",
                            std::str::from_utf8(path).unwrap(),
                            //peer_addr,
                            authority
                        );
                        // acquire http3 and TUN sender clones

                        // For sending messages from the ip handler to the http3 sender
                        let http3_sender_clone = client_handler.http3_sender.clone();

                        // These are for receiving messages from the TUN device
                        let (tun_sender_from, from_tun_receiver) =
                            mpsc::channel::<Vec<u8>>(MAX_CHANNEL_MESSAGES);
                        let conn_ip_client = ConnectIpClient {
                            assigned_addr: client_handler.client_ip,
                            id: "".to_string(),
                            static_addr: false,
                            sender: Some(tun_sender_from),
                        };
                        client_handler
                            .connect_ip_clients
                            .lock()
                            .await
                            .insert(client_handler.client_ip, conn_ip_client);

                        // For sending received http3 messages to the ip connect handler
                        let (ip_http3_sender, ip_http3_receiver) =
                            mpsc::channel::<Content>(MAX_CHANNEL_MESSAGES);
                        let flow_id = stream_id / 4;

                        if client_handler.connect_ip_session.is_some() {
                            debug!("Replacing old IpConnectSession!");
                            {
                                let ip_session =
                                    client_handler.connect_ip_session.as_ref().unwrap();
                                if !ip_session.handler_thread.as_ref().unwrap().is_finished() {
                                    ip_session.handler_thread.as_ref().unwrap().abort();
                                }
                            }
                        }
                        let _ = std::mem::replace(
                            &mut client_handler.connect_ip_session,
                            Some(IpConnectSession {
                                flow_id,
                                stream_id,
                                ip_h3_sender: ip_http3_sender,
                                handler_thread: None,
                            }),
                        );

                        // spawn handler thread for this one
                        let assigned_ip = client_handler.client_ip;
                        let static_clients_clone = client_handler.static_clients.clone();
                        let client_handler_clone = client_handler.register_handler.clone();

                        // For sending messages to the TUN device
                        let tun_sender_clone = tun_sender.clone();

                        // For looking up other clients
                        client_handler
                            .connect_ip_session
                            .as_mut()
                            .unwrap()
                            .handler_thread = Some(tokio::spawn(async move {
                            connect_ip_handler(
                                stream_id,
                                flow_id,
                                http3_sender_clone,
                                from_tun_receiver,
                                tun_sender_clone,
                                ip_http3_receiver,
                                assigned_ip,
                                static_clients_clone,
                                client_handler_clone,
                            )
                            .await;
                        }));
                    }
                } else {
                    // TODO: send error
                }
            }
        }

        Ok((stream_id, quiche::h3::Event::Data)) => {
            info!(
                "{} got data on stream id {}",
                client.conn.trace_id(),
                stream_id
            );
            while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                if client_handler.connect_ip_session.is_some() {
                    // TODO: Check if streamID is even correct?
                    {
                        let ip_session = client_handler.connect_ip_session.as_ref().unwrap();
                        if ip_session.stream_id == stream_id {
                            // connect-ip data, must be a capsule
                            debug!(
                                "got {} bytes of data on ip connect stream {}",
                                read, stream_id
                            );
                            let data = &buf[..read];
                            ip_session
                                .ip_h3_sender
                                .send(Content::Data {
                                    data: data.to_vec(),
                                })
                                .await
                                .expect("channel send failed");
                        }
                    }
                } else {
                    debug!(
                        "received {} bytes of stream data on unknown stream {}",
                        read, stream_id
                    );
                }
            }
        }

        Ok((stream_id, quiche::h3::Event::Finished)) => {
            info!("finished received, stream id: {} closing", stream_id);
            // TODO: do we need to shutdown the stream on our side?
            while let Ok(_read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                // TODO: Do we need to do something here?
            }
            if client_handler
                .connect_ip_clients
                .lock()
                .await
                .contains_key(&client_handler.client_ip)
            {
                // stop the connect_ip_connection
                {
                    let ip_session = client_handler.connect_ip_session.as_ref().unwrap();
                    ip_session.handler_thread.as_ref().unwrap().abort();
                }
                client_handler.connect_ip_session.take();
                client_handler
                    .connect_ip_clients
                    .lock()
                    .await
                    .remove(&client_handler.client_ip);
            }
            // TODO: Possibly kill IP Session?
            if client_handler.connect_ip_session.is_some() {
                client_handler.connect_ip_session.as_mut().unwrap().handler_thread.as_mut().unwrap().abort();
            }
        }

        Ok((stream_id, quiche::h3::Event::Reset(e))) => {
            error!(
                "request was reset by peer with {}, stream id: {} closed",
                e, stream_id
            );
            // TODO: do we need to shutdown the stream on our side?
            while let Ok(_read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                // TODO: Do we need to do something here?
            }
            if client_handler
                .connect_ip_clients
                .lock()
                .await
                .contains_key(&client_handler.client_ip)
            {
                // stop the connect_ip_connection
                {
                    let ip_session = client_handler.connect_ip_session.as_ref().unwrap();
                    ip_session.handler_thread.as_ref().unwrap().abort();
                }
                client_handler.connect_ip_session.take();
                client_handler
                    .connect_ip_clients
                    .lock()
                    .await
                    .remove(&client_handler.client_ip);
            }
            // TODO: Possibly kill IP Session?
            if client_handler.connect_ip_session.is_some() {
                client_handler.connect_ip_session.as_mut().unwrap().handler_thread.as_mut().unwrap().abort();
            }
        }
        Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

        Ok((_goaway_id, quiche::h3::Event::GoAway)) => unreachable!(),

        Err(quiche::h3::Error::Done) => {
            return Err(ClientError::Other("quiche error: Done".to_string()));
        }

        Err(e) => {
            error!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);
            return Err(ClientError::Other("HTTP/3 error".to_string()));
        }
    }
    Ok(())
}

///
/// Set up the TUN device.
/// Will execute several IP commands to route traffic accordingly.
/// 
fn set_ip_settings(server_config: ServerConfig) -> Result<(), Box<dyn Error>> {
    // Activate our TUN device
    let output = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            (server_config.interface_name.as_ref().unwrap()),
            "up",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Failed to bring up tun0: {:?}",
            String::from_utf8(output.stderr)
        )
        .into());
    }

    // Assign the specified address to our device
    let output = Command::new("ip")
        .args([
            "addr",
            "add",
            (server_config.interface_address.as_ref().unwrap()),
            "dev",
            (server_config.interface_name.as_ref().unwrap()),
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Failed to assign IP to tun0: {:?}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // decode device address to get range
    let prefix_index = &server_config.interface_address.as_ref().unwrap().find("/");
    if prefix_index.is_none() {
        panic!(
            "Malformed device address: {}",
            &server_config.interface_address.as_ref().unwrap()
        );
    }
    let addr = String::from_str(
        &server_config.interface_address.as_ref().unwrap()[..(prefix_index.unwrap())],
    )
    .unwrap();
    let ipaddr = Ipv4Addr::from_str(&addr).unwrap();
    ipaddr.octets()[3] = 0;
    let mut ip_range = ipaddr.to_string();
    ip_range.push_str("/32");

    // Route traffic of our subnet to us
    let route_output = Command::new("ip")
        .args([
            "route",
            "add",
            &ip_range,
            "via",
            (server_config.local_uplink_device_ip.as_ref().unwrap()),
            "dev",
            (server_config.local_uplink_device_name.as_ref().unwrap()),
        ])
        .output()
        .expect("Failed to execute IP ROUTE command");

    if !route_output.status.success() {
        eprintln!(
            "Failed to set route: {}",
            String::from_utf8_lossy(&route_output.stderr)
        );
    }

    // Set the MTU of our device
    let mtu_output = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            server_config.interface_name.as_ref().unwrap(),
            "mtu",
            server_config.mtu.as_ref().unwrap(),
        ])
        .output()
        .expect("Failed to execute MTU size command");

    if !mtu_output.status.success() {
        eprintln!(
            "Failed to set MTU to tun device: {}",
            String::from_utf8_lossy(&mtu_output.stderr)
        );
    }

    // Allow re-routing in iptables
    let iptables = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            (server_config.local_uplink_device_name.as_ref().unwrap()),
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

    Ok(())
}

///
/// Destroy the device. 
/// TODO: This is not used right now since the server/client can exit gracefully
/// In the future we should delete the correct device
/// 
#[allow(unreachable_code)]
fn destroy_tun_interface() {
    unreachable!();
    let output = Command::new("ip")
        .arg("link")
        .arg("delete")
        .arg("tun0")
        .output()
        .expect("Failed to execute command to delete TUN interface");

    if !output.status.success() {
        eprintln!(
            "Failed to delete TUN interface: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// 
/// Creates a TUN socket and sets it up in the system.
/// Will then create a writer and a reader thread which are connected to channels.
/// 
async fn tun_socket_handler(
    ip_handlers: ConnectIpClientList,
    mut tun_sender: tokio::sync::mpsc::Receiver<Vec<u8>>,
    server_config: ServerConfig,
) {
    // first create tun socket
    let mut config = tun2::Configuration::default();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    config.tun_name(server_config.interface_name.as_ref().unwrap());
    let dev = tun2::create_as_async(&config).unwrap();
    set_ip_settings(server_config).unwrap_or_else(|e| panic!("Error setting up TUN: {e}"));

    let (mut reader, mut writer) = tokio::io::split(dev);
    let ip_handlers_clone = ip_handlers.clone();
    // create reader thread
    // Reads from the TUN device and sends messages to connect_ip handler(s)
    let read_t = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let size = reader
                .read(&mut buf)
                .await
                .expect("Could not read from reader");
            let pkt = &buf[..size];
            // parse packet to get destination ip
            // then send it to handler for dest ip
            if get_ip_version(pkt) == 6 {
                debug!("Ignore ipv6 for now...");
                continue;
            }

            let dest = get_ipv4_pkt_dest(pkt);
            if let Some(ip_handler_) = ip_handlers_clone.lock().await.get(&dest)
            {
                info!(
                    "Tun Handler received packet | Src: {} To: {}",
                    get_ipv4_pkt_source(pkt),
                    &dest
                );

                if ip_handler_.sender.is_some() {
                    ip_handler_
                        .sender
                        .as_ref()
                        .unwrap()
                        .send(pkt.to_vec())
                        .await
                        .expect("Could not send a message to ip handler channel!");
                } else {
                    error!("Could not find ip sender for ip: {}", &dest);
                }
            } else {
                info!(
                    "Got packet for unknown client | Src: {} To: {}",
                    get_ipv4_pkt_source(pkt),
                    &dest
                );
            }
            
        }
    });

    // create writer thread
    // Waits for messages from the connect_ip handler(s) and sends them via TUN device
    // If we know the client this is directed to we should just forward the message to that client
    let write_t = tokio::spawn(async move {
        loop {
            if let Some(pkt) = tun_sender.recv().await {
                // TODO: For now we make sure to only send ipv4 packets
                // Get the version by looking at the first nibble
                let version = pkt[0] >> 4;
                if version == 4 {
                    // check if we can directly forward the packet to one of the other clients
                    let dest = get_ipv4_pkt_dest(&pkt);
                    if let Some(client) = ip_handlers.lock().await.get(&dest) {
                        client
                            .sender
                            .as_ref()
                            .unwrap()
                            .send(pkt)
                            .await
                            .expect("IP Channel sender error! Direct IP sending to client");
                    } else {
                        // All is okay, send the packet to the TUN interface
                        // call write as long as needed to send the entire packet
                        let mut pos = 0;
                        while pos < pkt.len() {
                            let written = match writer.write(&pkt[pos..]).await {
                                Ok(n) => n,
                                Err(e) => {
                                    if e.kind() == ErrorKind::Interrupted {
                                        0
                                    } else {
                                        panic!("Could not write to TUN device: {e}");
                                    }
                                }
                            };
                            pos += written;
                        }
                        debug!("TUN wrote {pos} bytes to device!");
                    }
                } else if version == 6 {
                    debug!("TUN Writer Received ipv6 packet, ignoring for now...");
                } else {
                    error!(
                        "TUN Writer received ip packet of unknown version: {}",
                        version
                    );
                }
            }
        }
    });
    match tokio::join!(read_t, write_t) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    }
    destroy_tun_interface();
}


///
/// Function for an established CONNECT-IP session
/// Starts a reader and a writer thread.
/// 
async fn connect_ip_handler(
    stream_id: u64,
    flow_id: u64,
    http3_sender: UnboundedSender<ToSend>,
    mut tun_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tun_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut http3_receiver: tokio::sync::mpsc::Receiver<Content>,
    mut assigned_ip: Ipv4Addr,
    static_clients: StaticClientMap,
    ip_register_handler: Sender<IpRegisterRequest>,
) {
    debug!("Creating new IP connect handler!");

    // SETUP STUFF
    let http3_sender_clone_1 = http3_sender.clone();
    let http3_sender_clone_2 = http3_sender.clone();
    let http3_sender_clone_3 = http3_sender.clone();

    // Changed if the client sends CLIENT_HELLO
    let mut static_client = false;
    let mut client_id = String::new();

    // Check for packets in the tun receiver
    // This receiver gets packets from the TUN interface that are supposed to be tunnelled
    // to the proxy client.
    // The packets are confirmed to be ipv4 packets so we don't need to worry about anything.
    // Just create the http3 datagram and send the packet.
    let read_task = tokio::spawn(async move {
        loop {
            if let Some(mut pkt) = tun_receiver.recv().await {
                // Decrease ttl
                pkt[8] -= 1;
                recalculate_checksum(&mut pkt);

                let to_send = encapsulate_ipv4(pkt, &flow_id, &0);
                debug!("Sending ip message to client: {}", assigned_ip);
                http3_sender_clone_1
                    .send(to_send)
                    .expect("Could not send datagram to http3 sender!");
            }
        }
    });

    // Check for packets in the http3 receiver
    // This receiver gets datagram bodies (which are just ip packets) from the client proxy
    // and handles them (sends them to the TUN interface)
    let write_task = tokio::spawn(async move {
        loop {
            if let Some(pkt) = http3_receiver.recv().await {
                match pkt {
                    Content::Request {
                        headers: _,
                        stream_id_sender: _,
                    } => unreachable!(),
                    Content::Headers { headers: _ } => unreachable!(),
                    Content::Data { data } => {
                        // Parse and handle received capsule
                        let cap = match Capsule::new(&data) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Ignoring invalid capsule: {e}");
                                continue;
                            }
                        };
                        match cap.capsule_type {
                            CapsuleType::AddressAssign(_) => {
                                debug!("Got ADDRESS_ASSIGN capsule, ignoring...");
                            }
                            CapsuleType::AddressRequest(c) => {
                                // Ask the address handler if the address is free
                                let mut ret_addr = Ipv4Addr::UNSPECIFIED;
                                if let IpLength::V4(addr) = c.requested.first().unwrap().ip_address
                                {
                                    let mut addr = Ipv4Addr::from(addr);
                                    // If the client only wants a static ip but doesn't care 
                                    // which it is we just reserve our current ip
                                    if addr == Ipv4Addr::UNSPECIFIED {
                                        addr = assigned_ip;
                                    }
                                    let (ip_addr_sender, mut ip_addr_receiver) =
                                        tokio::sync::mpsc::channel(1);
                                    let req = IpRegisterRequest {
                                        callback: ip_addr_sender,
                                        requested_address: addr,
                                        id: client_id.clone(),
                                        former_ip: assigned_ip,
                                        static_addr: static_client,
                                    };
                                    ip_register_handler.send(req)
                                        .await
                                        .expect("Could not send channel message to ip register handler!");
                                    if let Some(ret) = ip_addr_receiver.recv().await {
                                        info!("Got address for client: {ret}");
                                        ret_addr = ret;
                                        assigned_ip = ret;
                                    }

                                } else {
                                    error!("Client requested ipv6 address, not supported");
                                    // TODO: Implement some proper closing of the connection
                                    return;
                                }

                                let cap_buf =
                                    AddressAssign::create_sendable(ret_addr, None, Some(c.requested[0].request_id));
                                   // create_addr_assign(ret_addr, c.requested[0].request_id);
                                http3_sender_clone_2
                                    .send(ToSend {
                                        stream_id,
                                        content: Content::Data {
                                            data: cap_buf.to_vec(),
                                        },
                                        finished: false,
                                    })
                                    .expect("Could not send to http3 channel..");
                            }
                            CapsuleType::RouteAdvertisement(_) => todo!(),
                            CapsuleType::ClientHello(v) => {
                                // This means the client wants a static address
                                // Look up this client, if we already know the client
                                // we can simply reply with the assigned address.
                                // Otherwise we reply with another ClientHello to signal
                                // that we need the clients address information
                                static_client = true;
                                client_id = String::from_utf8(v.id)
                                    .expect("Client provided a invalid utf8 string");
                                info!("Received client hello from {}", client_id);
                                let cap_buf;
                                if let Some(ip_addr) = static_clients.lock().await.get(&client_id) {
                                    // We know this client already. Register it and send AddressAssign
                                    let mut ret_addr = Ipv4Addr::UNSPECIFIED;
                                    let (ip_addr_sender, mut ip_addr_receiver) =
                                        tokio::sync::mpsc::channel(1);
                                    let req = IpRegisterRequest {
                                        callback: ip_addr_sender,
                                        requested_address: *ip_addr,
                                        id: client_id.clone(),
                                        former_ip: assigned_ip,
                                        static_addr: true,
                                    };
                                    ip_register_handler.send(req).await.expect(
                                        "Could not send channel message to ip register handler!",
                                    );
                                    if let Some(ret) = ip_addr_receiver.recv().await {
                                        ret_addr = ret;
                                        assigned_ip = ret;
                                    }
                                    cap_buf = 
                                        AddressAssign::create_sendable(ret_addr, None, None);
                                } else {
                                    // Create a CLIENT_HELLO capsule to signal that we don't know
                                    // the client
                                    cap_buf = ClientHello::create_sendable("SERVER".to_owned()).unwrap();
                                }
                                http3_sender_clone_2
                                    .send(ToSend {
                                        stream_id,
                                        content: Content::Data {
                                            data: cap_buf.to_vec(),
                                        },
                                        finished: false,
                                    })
                                    .expect("Could not send to http3 channel..");
                            }
                        }
                    }
                    Content::Datagram { mut payload } => {
                        // just send the datagram
                        debug!("Received a datagram from connect-ip client");
                        let (context_id, length) = decode_var_int_get_length(&payload);
                        if context_id != 0 {
                            debug!("Received non-zero context_id (not implemented)!");
                            continue;
                        }

                        let pkt = &payload[length..];
                        match get_ip_version(pkt) {
                            4 => {
                                match check_ipv4_packet(pkt, (payload.len() - length) as u16) {
                                    Ok(_) => {}
                                    Err(Ipv4CheckError::WrongChecksumError) => {
                                        error!("Received IPv4 packet with invalid checksum, discarding..");
                                        continue;
                                    }
                                    Err(Ipv4CheckError::WrongSizeError) => {
                                        error!(
                                            "Received IPv4 packet with invalid size, discarding..."
                                        );
                                        continue;
                                    }
                                }
                                // If packet TTL is 0 or will be 0 after decreasing, discard
                                if get_ipv4_ttl(pkt) <= 1 {
                                    debug!("TTL 0, discarding packet..");
                                    continue;
                                }
                                payload[length + 8] -= 1;
                                recalculate_checksum(&mut payload[length..]);
                                tun_sender
                                    .send(payload[length..].to_vec())
                                    .await
                                    .expect("Wasn't able to send ip packet to tun handler");
                            }
                            6 => {
                                continue;
                            }
                            n => {
                                debug!("Received an invalid packet version: {n}");
                            }
                        }
                    }
                    Content::Finished => unreachable!(), //TODO: Maybe we can actually use this to terminate connections?
                }
            }
        }
    });

    // Signal to the client that the connection has been set up, and it can start sending
    debug!("Sending back ok to the client!");
    let headers = vec![quiche::h3::Header::new(b":status", b"200")];
    http3_sender_clone_3
        .send(ToSend {
            stream_id,
            content: Content::Headers { headers },
            finished: false,
        })
        .expect("channel send failed");

    println!("Registered a new client with IP: {}", assigned_ip);

    match tokio::join!(read_task, write_task) {
        (Err(e), Err(e2)) => {
            debug!(
                "Two errors occured when joining r/w tasks: {:?} | {:?}",
                e, e2
            );
        }
        (Err(e), _) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, Err(e)) => {
            debug!("An error occured when joining r/w tasks: {:?}", e);
        }
        (_, _) => {}
    };
}

///
/// Search for the next free IP.
/// Will start counting upwards from the given IP, and check each time if the IP is in use.
fn get_next_free_ip(
    mut start_ip: Ipv4Addr,
    existing_clients: &MutexGuard<HashMap<Ipv4Addr, ConnectIpClient>>,
) -> Option<Ipv4Addr> {
    while let Ok(v) = get_next_ipv4(start_ip, STANDARD_NETMASK) {
        if existing_clients.contains_key(&v) {
            start_ip = v;
        } else {
            return Some(v);
        }
    }
    None
}

///
/// Waits for new connecting clients.
/// If the client doesn't wish to be registered with a static IP it gets the first free ip address
/// we can find.
/// If the client does wish to be registered with a static IP we check if the address (range) has
/// a free address that is not in use at the moment. If there is none we reply with 0.0.0.0,
/// if we found a fitting address we reply with that address.
///
/// //TODO: Implement IP address *range* queries
/// //TODO: Can we take the address of a non-static client and give it to the requesting client?
///         The client would have to be able to handle address changes
/// //TODO: Currently we can't remove a client
async fn client_register_handler(
    mut receiver: Receiver<IpRegisterRequest>,
    connect_ip_clients: ConnectIpClientList,
    static_clients: StaticClientMap,
    config_path: String,
) {
    loop {
        if let Some(request) = receiver.recv().await {
            info!("Client is requesting address. Id: \"{}\" | Ip: {} | Former ip: {}", 
                request.id, 
                request.requested_address,
                request.former_ip);
            // We have to make sure noone adds a client during this
            let mut clients_binding = connect_ip_clients.lock().await;
            // if former ip == requested ip we only need to save the client as static if needed
            if request.former_ip == request.requested_address {
                let old_client = clients_binding.remove(&request.former_ip);
                let mut new_client = old_client.unwrap();
                new_client.static_addr = request.static_addr;
                new_client.id = request.id.clone();
                
                if request.static_addr {
                    add_static_client_config(request.requested_address, request.id.clone(), &config_path, &static_clients).await;
                }
                clients_binding.insert(request.requested_address, new_client);

                request.callback.send(request.former_ip).await
                    .expect("Couldn't send message to channel!");
                continue;
            }
            if clients_binding.contains_key(&request.requested_address) {
                if !request.static_addr {
                    // Client does not want to get registered
                    // We can simply give it the next free ip we find
                    let assigned_addr = request.requested_address;
                    if let Some(v) = get_next_free_ip(assigned_addr, &clients_binding) {
                        let old_client = clients_binding.remove(&request.former_ip);
                        if old_client.is_none() {
                            panic!("Tried to remove client from connected clients that wasn't in there!");
                        }

                        let mut new_client = old_client.unwrap();
                        new_client.assigned_addr = v;
                        clients_binding.insert(v, new_client);
                        // Pseudo register client and send address to callback
                        request
                            .callback
                            .send(v)
                            .await
                            .expect("Couldn't send message to channel!");
                        break;
                    } else {
                        error!("Could not assign address to new client!");
                        break;
                    }
                } else {
                    let old_client = clients_binding.remove(&request.former_ip).unwrap();
                    let client = clients_binding.get_mut(&request.requested_address).unwrap();

                    if client.id == request.id {
                        // send reply with requested address to the client
                        request
                            .callback
                            .send(request.requested_address)
                            .await
                            .expect("Couldn't send message to channel!");
                        client.static_addr = true;
                        client.sender = old_client.sender;
                    } else {
                        // Requested IP is blocked by another client
                        // send reply with 0.0.0.0 to the client
                        request
                            .callback
                            .send(Ipv4Addr::new(0, 0, 0, 0))
                            .await
                            .expect("Couldn't send message to channel!");
                        clients_binding.insert(request.former_ip, old_client);
                    }
                }
            } else {
                // We can simply assign this client the new ip
                // We don't need to do anything special, we can simply give this client the ip
                // get client's former entry, remove it, and reinsert it
                let old_client = clients_binding.remove(&request.former_ip);
                if old_client.is_none() {
                    panic!("Tried to remove client from connected clients that wasn't in there!");
                }
                let mut new_client = old_client.unwrap();

                // update the old clients data
                new_client.assigned_addr = request.requested_address;
                new_client.id = request.id.clone();
                new_client.static_addr = request.static_addr;

                clients_binding.insert(request.requested_address, new_client);

                request
                    .callback
                    .send(request.requested_address)
                    .await
                    .expect("Couldn't send message to channel!");

                if request.static_addr {
                    add_static_client_config(request.requested_address, request.id.clone(), &config_path, &static_clients).await;
                }
            }
        }
    }
}

async fn add_static_client_config(addr: Ipv4Addr, id: String, path: &str, static_clients: &StaticClientMap) {
    

    // If the static client is already known (for example when changing it's own address), we 
    // should remove it first from the static clients
    if static_clients.lock().await.contains_key(&id) {
        static_clients.lock().await.remove(&id);
    } 

    // save client to static_clients list as well
    static_clients
        .lock()
        .await
        .insert(id, addr);

    let mut new_contents = String::new();
    const CONFIG_DESCRIPTION: &str = 
        "# This file holds masquerade clients that registered static ip addresses\n\
         # You may add new clients here following this scheme: \n\
         # [[clients]]\n\
         # id = 'exampleID'\n\
         # ip = '10.8.1.1'\n\n";

    new_contents.push_str(CONFIG_DESCRIPTION);
    for c in static_clients.lock().await.iter() {
        new_contents.push_str(
            &format!(
                "[[clients]]\n\
                id = \'{}\'\n\
                ip = \'{}\'\n\n",
                c.0, c.1
            )
        );
        info!("Persisting client {}", c.0);
    }

    // Update the config file
    // TODO: We should probably limit the times the config file is rewritten
    //       This can be abused to spam IO, don't use in prod
    let mut file = OpenOptions::new()
        .write(true)
        .mode(0o777)
        .open(path)
        .await
        .unwrap();
    if let Err(e) = file.write_all(new_contents.as_bytes()).await {
        error!("Couldn't write to static client list: {e}");
    }

}