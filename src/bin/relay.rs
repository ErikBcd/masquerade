use std::{env, error::Error};

use masquerade_proxy::relay::Relay;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();
    
    let listen_addr_server = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4432".to_string());
    let listen_addr_client = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4431".to_string());

    let conn_addr = env::args().nth(2).unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let relay = Relay::new();

    relay.run(&conn_addr, &listen_addr_server, &listen_addr_client).await
}
