use std::{env, error::Error};

use masquerade_proxy::relay::Relay;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();
    
    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4432".to_string());
    let conn_addr = env::args().nth(2).unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let mut relay = Relay::new();
    relay.bind(bind_addr).await?;

    relay.run(&conn_addr).await
}
