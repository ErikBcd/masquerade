use masquerade_proxy::ip_connect::client::ConnectIPClient;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());

    let newclient = ConnectIPClient;
    newclient.run(&server_name).await;

    Ok(())
}
