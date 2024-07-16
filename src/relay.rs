// Base notes:
//  * Relay has one incoming and one outgoing connection(s)
//  * Takes packets from incoming conn and sends to outgoing
//  * (also vice-versa, bidirectional)
//  * First connects to the specified server on a specified port,
//  * and then waits for a client connection on a specified port
//  * -> Client can be another relay

use log::*;
use mio::net::UdpSocket;
use mio::Token;
use quiche::{Config, Connection, ConnectionId, RecvInfo};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use core::panic;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;

use std::time::Instant;

use crate::common::*;

const MAX_BUF_SIZE: usize = 65507;
const SERVER_TOKEN: Token = Token(0);
const CLIENT_TOKEN: Token = Token(1);

type ClientMap = HashMap<ConnectionId<'static>,(Connection, SocketAddr, Instant),>;

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
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Sockets
        let mut server_socket = mio::net::UdpSocket::bind(listen_addr_server.parse().unwrap())?;
        let mut client_socket = mio::net::UdpSocket::bind(listen_addr_client.parse().unwrap())?;
        poll.registry()
            .register(&mut server_socket, SERVER_TOKEN, mio::Interest::READABLE)
            .expect("Could not register server socket!");
        poll.registry()
            .register(&mut client_socket, CLIENT_TOKEN, mio::Interest::READABLE)
            .expect("Could not register client socket!");

        // TODO: Make config editable via command line arguments
        let mut config = default_config();

        // TODO: Put server connection in it's own method, to clean this up a little
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut scid[..]).unwrap();
        let initial_conn_id = ConnectionId::from_ref(&scid[..]);

        // Establish server connection
        // TODO: Maybe put this into a loop that loops till we have a connection
        let mut server_conn = match quiche::connect(
            None,
            &initial_conn_id,
            server_socket.local_addr().unwrap(),
            server_addr.parse().unwrap(),
            &mut config,
        ) {
            Ok(v) => v,
            Err(e) => {
                panic!("Could not connect to next server: {:?}", e);
            }
        };

        info!(
            "connecting to {:} from {:} with scid {}",
            server_addr,
            server_socket.local_addr().unwrap(),
            hex_dump(&initial_conn_id)
        );

        let (write, send_info) = server_conn.send(&mut out).expect("initial send failed");

        while let Err(e) = server_socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                trace!(
                    "{} -> {}: send() would block",
                    server_socket.local_addr().unwrap(),
                    send_info.to
                );
                continue;
            }
            panic!("Could not send data to server after establishing connection!");
        }

        trace!("written {}", write);

        let mut client_connections = ClientMap::new();
        if server_conn.is_closed() {
            panic!("connection closed unexpectetly, {:?}", server_conn.stats());
        }
        // Handle all packets that we receive.
        // New packet either means we have a new connection,
        // or we have a packet to relay
        'read: loop {
            poll.poll(&mut events, None)?;
            for event in events.iter() {
                debug!("Handling an event with token {:?}", event.token());
                match event.token() {
                    // Server side
                    SERVER_TOKEN => {
                        if event.is_readable() {
                            let (len, addr) = match server_socket.recv_from(&mut buf) {
                                Ok(v) => v,
                                Err(e) => {
                                    panic!("recv_from() failed: {:?}", e);
                                }
                            };
                            let pkt_buf = &mut buf[..len];
                            match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                                Ok(v) => {
                                    let conn_id = generate_hmac_conn_id(&v.dcid, &hmac_key);
                                    if let Some((conn, client_addr, _)) =
                                        client_connections.get_mut(&conn_id)
                                    {
                                        let recv_info = RecvInfo {
                                            from: addr,
                                            to: *client_addr,
                                        };
                                        server_conn.recv(&mut buf[..len], recv_info).unwrap();
                                        self.relay_data(
                                            &mut server_conn,
                                            &mut buf,
                                            &mut client_socket,
                                            *client_addr,
                                            conn,
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Parsing packet header failed: {:?}", e);
                                    continue 'read;
                                }
                            };
                        }
                    }

                    // Client side
                    CLIENT_TOKEN => {
                        if event.is_readable() {
                            match self.handle_client(
                                &mut client_socket, 
                                &mut server_socket, 
                                &mut server_conn, 
                                &mut client_connections, 
                                &mut buf, 
                                &mut out, 
                                &hmac_key, 
                                listen_addr_client, 
                                server_addr, 
                                &mut config
                            ) {
                                Ok(_) => {continue 'read},
                                Err(e) => {
                                    debug!("Handling client: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    /**
     *   Relays given data via the given connection
     *   Afterwards it takes care of other streams that exist for this connection.
     */
    fn relay_data(
        &self,
        conn: &mut Connection,
        buffer: &mut [u8],
        socket: &mut UdpSocket,
        addr: SocketAddr,
        remote_conn: &mut Connection,
    ) {
        // Forward the QUIC data
        while let Ok((len, _send_addr)) = conn.send(buffer) {
            match socket.send_to(&buffer[..len], addr) {
                Ok(_) => {}
                Err(e) => {
                    warn!("Could not send data to {:?}, error: {:?}", addr, e);
                }
            }
        }

        // Check for new incoming data on the connection and handle that directly
        for stream_id in conn.readable() {
            while let Ok((len, fin)) = conn.stream_recv(stream_id, buffer) {
                if fin {
                    todo!("What if connection has ended?")
                }
                remote_conn
                    .stream_send(stream_id, &buffer[..len], fin)
                    .unwrap();
            }
        }
    }

    fn handle_client(
        &self,
        client_socket: &mut UdpSocket, 
        server_socket: &mut UdpSocket,
        server_conn: &mut Connection,
        client_connections: &mut ClientMap,
        buf: &mut [u8],
        out: &mut [u8],
        hmac_key: &hmac::Key,
        listen_addr_client: &String,
        server_addr: &String,
        config: &mut Config,
    ) -> Result<(), ClientError> {
        let (len, addr) = match client_socket.recv_from(buf) {
            Ok(v) => v,
            Err(e) => {
                panic!("recv_from() failed: {:?}", e);
            }
        };
        debug!("Handling event! Message from: {:?}", addr);
        let pkt_buf = &mut buf[..len];
        match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => {
                self.handle_message(&hdr);
                let conn_id = generate_hmac_conn_id(&hdr.dcid, &hmac_key);
                
                if !client_connections.contains_key(&conn_id) {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        return Ok(());
                    }
                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len = quiche::negotiate_version(
                            &hdr.scid, &hdr.dcid, out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = client_socket.send_to(out, addr) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send_to() would block");
                                return Err(ClientError::Other(format!("send() failed: {e:?}")));
                            }

                            panic!("send_to() failed: {:?}", e);
                        }
                        return Ok(());
                    }
                    // If we have no token, get a new one
                    let token = hdr.token.as_ref().unwrap();
                    if token.is_empty() {
                        warn!("Doing stateless retry!");
                        let new_token = mint_token(&hdr, &addr);
                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &conn_id,
                            &new_token,
                            hdr.version,
                            out,
                        )
                        .unwrap();
                        let out = &out[..len];
                        if let Err(e) = client_socket.send_to(out, addr) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                return Err(ClientError::Other(format!("send() failed: {e:?}")));
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        return Ok(())
                    }
                    let odcid = validate_token(&addr, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        return Ok(())
                    }
                    let scid = hdr.dcid.clone();
                    // TODO: Check the addresses, these might be wrong
                    match quiche::accept(
                        &scid,
                        odcid.as_ref(),
                        listen_addr_client.parse().unwrap(),
                        addr,
                        config,
                    ) {
                        Ok(v) => {
                            debug!(
                                "New client at {:} connection added: {:?}",
                                addr,
                                v.stats()
                            );
                            client_connections.insert(
                                scid.clone(),
                                (v, addr, Instant::now()),
                            );
                        }
                        Err(e) => {
                            warn!("Could not add connection: {:?}", e);
                        }
                    }
                } else if let Some((conn, _, _)) =
                    client_connections.get_mut(&conn_id)
                {
                    let recv_info = RecvInfo {
                        from: addr,
                        to: client_socket.local_addr().unwrap(),
                    };

                    conn.recv(&mut buf[..len], recv_info).unwrap();
                    self.relay_data(
                        conn,
                        buf,
                        server_socket,
                        server_addr.parse().unwrap(),
                        server_conn,
                    );
                    // TODO: Once QUIC conn is established create a new app protocol session
                }
            }
            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                return Ok(());
            }
        };
        Ok(())
    }

    fn handle_message(&self, hdr: &quiche::Header) {
        debug!("Header data: Type={:?}", hdr.ty);
    }
}

fn default_config() -> Config {
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

    config
}

fn generate_hmac_conn_id(dcid: &ConnectionId, key: &hmac::Key) -> ConnectionId<'static> {
    let tag = hmac::sign(key, dcid.as_ref());
    let hmac_conn_id = &tag.as_ref()[..quiche::MAX_CONN_ID_LEN];
    ConnectionId::from_vec(hmac_conn_id.to_vec())
}
