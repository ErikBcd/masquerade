// Base notes:
//  * Relay has one incoming and one outgoing connection
//  * Takes packets from incoming conn and sends to outgoing
//  * (also vice-versa, bidirectional)
//  * First connects to the specified server on a specified port,
//  * and then waits for a client connection on a specified port
//  * -> Client can be another relay

use env_logger::fmt::buffer;
use log::*;
use mio::net::UdpSocket;
use mio::Token;
use quiche::{Config, Connection, ConnectionId, Header};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use core::panic;
use std::collections::HashMap;
use std::error::Error;
use std::net::{self, SocketAddr, ToSocketAddrs, UdpSocket};

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::{client, common::*};

const MAX_BUF_SIZE: usize = 65507;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub struct Relay;

impl Relay {
    pub fn new() -> Relay {
        Relay {}
    }

    /**
     *  Runs this server relay.
     *  
     *  What a relay does: It acts as an intermediary between a sender and a server, e.g.
     *  a masquerade client and a masquerade (endpoint) server.
     *  As such it will only receive QUIC messages, unpack them and then create a new QUIC message
     *  and send it forth.
     *  This way the sender will never know the next server in the chain.
     *
     *  WARN: This is very much experimental.
     */
    pub async fn run(
        &self,
        server_addr: &String,
        listen_addr_server: &String,
        listen_addr_client: &String,
    ) -> Result<(), Box<dyn Error>> {
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        let rng = SystemRandom::new();
        let hmac_key = hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut buf = [0; MAX_BUF_SIZE];

        // Sockets
        let mut server_socket = mio::net::UdpSocket::bind(listen_addr_server.parse().unwrap())?;
        let mut client_socket = mio::net::UdpSocket::bind(listen_addr_client.parse().unwrap())?;
        poll.registry()
            .register(&mut server_socket, Token(0), mio::Interest::READABLE);
        poll.registry()
            .register(&mut client_socket, Token(1), mio::Interest::READABLE);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        // WARN: Don't do this in production
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
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.set_active_connection_id_limit(10);

        let mut client_connections: HashMap<
            ConnectionId<'static>,
            (Connection, SocketAddr, Instant),
        > = HashMap::new();
        let mut server_connections: HashMap<
            ConnectionId<'static>,
            (Connection, SocketAddr, Instant),
        > = HashMap::new();

        // Establish server connection
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut scid[..]).unwrap();
        let initial_conn_id = ConnectionId::from_ref(&scid);
        let server_conn = quiche::connect(
            None,
            &initial_conn_id,
            server_socket.local_addr().unwrap(),
            server_addr.parse().unwrap(),
            &mut config,
        )
        .unwrap();
        server_connections.insert(
            initial_conn_id.clone(),
            (server_conn, server_addr.parse().unwrap(), Instant::now()),
        );

        // Once both connections are established:
        //  Wait for data from one of the connections, then forward the data
        //  Also: When client or server lose connection, try to reconnect to server and/or wait for
        //  new client connection
        'read: loop {
            poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    // Server side
                    Token(0) => {
                        if event.is_readable() {
                            let (len, addr) = match server_socket.recv_from(&mut buffer) {
                                Ok(v) => v,
                                Err(e) => {
                                    panic!("recv_from() failed: {:?}", e);
                                }
                            };
                            let pkt_buf = &mut buf[..len];
                            let hdr = match quiche::Header::from_slice(
                                pkt_buf,
                                quiche::MAX_CONN_ID_LEN,
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    error!("Parsing packet header failed: {:?}", e);
                                    continue 'read;
                                }
                            };
                            let conn_id = ring::hmac::sign(&hmac_key, &hdr.dcid);
                            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                            let conn_id = conn_id.to_vec().into();
                            if !server_connections.contains_key(&conn_id) {
                                let c = quiche::connect(
                                    None,
                                    &conn_id,
                                    addr,
                                    server_addr.parse().unwrap(),
                                    &mut config,
                                )
                                .unwrap();
                                server_connections
                                    .insert(conn_id.clone(), (c, addr, Instant::now()));
                            }
                            if let Some((conn, s_addr, _)) =
                                server_connections.get_mut(&conn_id)
                            { // TODO: Debug this, too tired now..
                                conn.recv(&mut buffer[..len]).unwrap();
                                self.relay_data(
                                    conn,
                                    &mut buffer,
                                    &client_socket,
                                    listen_addr_client.parse().unwrap(),
                                    *s_addr,
                                    &mut client_connections,
                                    &mut config,
                                    &mut rng,
                                    &hmac_key,
                                    false,
                                );
                            }
                        }
                    }

                    // Client side
                    Token(1) => {}
                    _ => unreachable!(),
                }
            }
        }
    }

    /**
     *   Relays given data via the given connection
     *   Afterwards it takes care of other streams that exist for this connection.
     */
    fn relay(
        conn: &mut Connection,
        socket: &mut UdpSocket,
        addr: SocketAddr,
        local_addr: SocketAddr,
        buffer: &mut [u8],
        connections: &mut HashMap<ConnectionId<'static>, (Connection, SocketAddr)>,
        config: &mut Config,
        rng: &mut SystemRandom,
    ) {
        // Forward the QUIC data
        while let Ok((len, send_addr)) = conn.send(buffer) {
            socket.send_to(&buffer[..len], addr);
        }

        // Check for new incoming data on the connection and handle that directly
        for stream_id in conn.readable() {
            while let Ok((len, fin)) = conn.stream_recv(stream_id, buffer) {
                let conn_id = conn.destination_id().to_vec();
                if !connections.contains_key(&ConnectionId::from_ref(&conn_id)) {
                    let new_conn = quiche::connect(
                        None,
                        &ConnectionId::from_ref(&conn_id),
                        local_addr,
                        addr,
                        config,
                    )
                    .unwrap();
                    connections.insert(ConnectionId::from_ref(&conn_id), (new_conn, addr));
                }

                if let Some((remote_conn, _)) =
                    connections.get_mut(&ConnectionId::from_ref(&conn_id))
                {
                    remote_conn
                        .stream_send(stream_id, &buffer[..len], fin)
                        .unwrap();
                }
            }
        }
    }

    async fn connect_to_next(
        &self,
        socket: &mio::net::UdpSocket,
        server_addr: &String,
    ) -> Option<Connection> {
        // Try to connect to the specified server/relay (relay and server work the same from our
        // perspective)

        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        // WARN: Do not blindly set this to false in production, see quiche example
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
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.set_active_connection_id_limit(10);

        let mut keylog = None;

        if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
                .unwrap();

            keylog = Some(file);

            config.log_keys();
        }

        config.enable_dgram(true, 1000, 1000);

        let mut http_conn: Option<Box<dyn HttpConn>> = None;

        let mut app_proto_selected = false;

        // Generate a random source connection ID for the connection.
        let rng = SystemRandom::new();

        let scid = if !cfg!(feature = "fuzzing") {
            let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
            rng.fill(&mut conn_id[..]).unwrap();

            conn_id.to_vec()
        } else {
            // When fuzzing use an all zero connection ID.
            [0; quiche::MAX_CONN_ID_LEN].to_vec()
        };

        let scid = quiche::ConnectionId::from_ref(&scid);

        let local_addr = socket.local_addr().unwrap();

        // Create a QUIC connection and initiate handshake.
        // Resolve server address.
        let url = url::Url::parse(&server_addr).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        let mut conn =
            quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config).unwrap();

        info!(
            "connecting to {:} from {:} with scid {:?}",
            peer_addr,
            socket.local_addr().unwrap(),
            scid,
        );
        // Now send connection stuff!
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                trace!(
                    "{} -> {}: send() would block",
                    socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }
            warn!("send() failed: {e:?}");
            return None;
        }

        trace!("written {}", write);

        Some(conn)
    }

    async fn connect_client(&self, socket: &mio::net::UdpSocket) -> Option<Connection> {
        // Wait for a client to connect. Once we establish a connection, return that connection
        None
    }
}
