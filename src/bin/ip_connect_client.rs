use masquerade_proxy::ip_connect::client::ConnectIPClient;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());

    let dev_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "10.9.0.2/24".to_string());

    let tun_gateway = env::args()
        .nth(2)
        .unwrap_or_else(|| "10.9.0.1".to_string());

    let tun_name = env::args()
        .nth(3)
        .unwrap_or_else(|| "tunMasq".to_string());

    let newclient = ConnectIPClient;
    newclient.run(&server_name, dev_addr, tun_gateway, tun_name).await;

    Ok(())
}
