use quiche;
use quiche::h3::NameValue;

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedSender};

use log::*;

use crate::common::*;
use crate::client::*;

async fn handle_http1_stream(
    mut stream: TcpStream,
    http3_sender: UnboundedSender<ToSend>,
    connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
    _connect_sockets: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>,
) {
    let mut buf = [0; 65535];
    let mut pos = match stream.read(&mut buf).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error reading from TCP stream: {}", e);
            return;
        }
    };
    loop {
        match stream.try_read(&mut buf[pos..]) {
            Ok(read) => pos += read,
            Err(ref e) if would_block(e) => break,
            Err(ref e) if interrupted(e) => continue,
            Err(e) => {
                error!("Error reading from TCP stream: {}", e);
                return;
            }
        };
    }
    let peer_addr = stream.peer_addr().unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    //let res = req.parse(&buf[..pos]).unwrap();
    req.parse(&buf[..pos]).unwrap();
    if let Some(method) = req.method {
        if let Some(path) = req.path {
            if method.eq_ignore_ascii_case("CONNECT") {
                // TODO: Check Host?
                let headers = vec![
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":authority", path.as_bytes()),
                    quiche::h3::Header::new(b":authorization", b"dummy-authorization"),
                ];
                info!("sending HTTP3 request {:?}", headers);
                let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
                let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();
                http3_sender
                    .send(ToSend {
                        content: Content::Request {
                            headers,
                            stream_id_sender,
                        },
                        finished: false,
                        stream_id: u64::MAX,
                    })
                    .unwrap_or_else(|e| error!("sending HTTP3 request failed: {:?}", e));
                info!("Sent HTTP3 request");

                let stream_id = stream_id_receiver
                    .recv()
                    .await
                    .expect("stream_id receiver error");
                {
                    let mut connect_streams = connect_streams.lock().unwrap();
                    connect_streams.insert(stream_id, response_sender);
                    // TODO: potential race condition: the response could be received before connect_streams is even inserted and get dropped
                }

                let response = response_receiver
                    .recv()
                    .await
                    .expect("http3 response receiver error");
                if let Content::Headers { headers } = response {
                    info!("Got response {:?}", hdrs_to_strings(&headers));
                    let mut status = None;
                    for hdr in headers {
                        match hdr.name() {
                            b":status" => status = Some(hdr.value().to_owned()),
                            _ => (),
                        }
                    }
                    if let Some(status) = status {
                        if let Ok(status_str) = std::str::from_utf8(&status) {
                            if let Ok(status_code) = status_str.parse::<i32>() {
                                if status_code >= 200 && status_code < 300 {
                                    info!("connection established, sending 200 OK");
                                    match stream.write(&b"HTTP/1.1 200 OK\r\n\r\n".to_vec()).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!("Sending 200 OK failed: {:?}", e);
                                        }
                                    };
                                }
                            }
                        }
                    }
                } else {
                    error!("received others when expecting headers for connect");
                }

                let (mut read_half, mut write_half) = stream.into_split();
                let http3_sender_clone = http3_sender.clone();
                let read_task = tokio::spawn(async move {
                    let mut buf = [0; 65535];
                    loop {
                        let read = match read_half.read(&mut buf).await {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Error reading from TCP {}: {}", peer_addr, e);
                                break;
                            }
                        };
                        if read == 0 {
                            debug!("TCP connection closed from {}", peer_addr);
                            // TODO: Do we have to tell the server that the TCP connection is closed?
                            http3_sender_clone
                                .send(ToSend {
                                    stream_id: stream_id,
                                    content: Content::Finished,
                                    finished: false,
                                })
                                .unwrap_or_else(|e| error!("tcp finish message not sent: {:?}", e));
                            break;
                        }
                        debug!(
                            "read {} bytes from TCP from {} for stream {}",
                            read, peer_addr, stream_id
                        );
                        http3_sender_clone
                            .send(ToSend {
                                stream_id: stream_id,
                                content: Content::Data {
                                    data: buf[..read].to_vec(),
                                },
                                finished: false,
                            })
                            .unwrap_or_else(|e| error!("tcp finish message not sent: {:?}", e));
                    }
                });
                let write_task = tokio::spawn(async move {
                    loop {
                        let data = match response_receiver.recv().await {
                            Some(v) => v,
                            None => {
                                debug!("TCP receiver channel closed for stream {}", stream_id);
                                break;
                            }
                        };
                        match data {
                            Content::Request { .. } => unreachable!(),
                            Content::Headers { .. } => unreachable!(),
                            Content::Data { data } => {
                                let mut pos = 0;
                                while pos < data.len() {
                                    let bytes_written = match write_half.write(&data[pos..]).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            error!(
                                                "Error writing to TCP {} on stream id {}: {}",
                                                peer_addr, stream_id, e
                                            );
                                            return;
                                        }
                                    };
                                    pos += bytes_written;
                                }
                                debug!(
                                    "written {} bytes from TCP to {} for stream {}",
                                    data.len(),
                                    peer_addr,
                                    stream_id
                                );
                            }
                            Content::Datagram { .. } => unreachable!(),
                            Content::Finished => {
                                debug!("shutting down stream in write task");
                                break;
                            }
                        };
                    }
                });
                match tokio::join!(read_task, write_task) {
                    (Err(e), Err(e2)) => {
                        debug!("Two errors occured when joining r/w tasks: {:?} | {:?}", e, e2);
                    },
                    (Err(e), _) => {
                        debug!("An error occured when joining r/w tasks: {:?}", e);
                    },
                    (_, Err(e)) => {
                        debug!("An error occured when joining r/w tasks: {:?}", e);
                    },
                    (_, _) => {}
                };

                // {
                //     let mut connect_streams = connect_streams.lock().unwrap();
                //     connect_streams.remove(&stream_id);
                // }
                return;
            }
        }
    }
    match stream
        .write(&b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec())
        .await {
            Ok(_) => {},
            Err(e) => {
                error!("Error when writing 400 to tcp stream: {:?}", e);
            }
        };
}

pub struct Http1Client {
    client: Client,
}

impl Http1Client {
    pub fn new() -> Http1Client {
        Http1Client {
            client: Client::new(),
        }
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self.client.listen_addr();
    }

    pub async fn bind<T: tokio::net::ToSocketAddrs>(
        &mut self,
        bind_addr: T,
    ) -> Result<(), Box<dyn Error>> {
        self.client.bind(bind_addr).await
    }

    pub async fn run(&mut self, server_addr: &String) -> Result<(), Box<dyn Error>> {
        self.client.run(server_addr, handle_http1_stream).await
    }
}
