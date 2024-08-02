use masquerade_proxy::ip_connect::IPConnectClientStarter;

use std::env;
use std::error::Error;
use log::error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let bind_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8899".to_string());

    let mut client = IPConnectClientStarter::new();
    client.init(&server_name, &bind_addr).await;
    client.run().await;

    Ok(())
}
