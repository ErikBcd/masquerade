use clap::{arg, command};
use log::info;
use masquerade_proxy::ip_connect::client::ConnectIPClient;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let matches = command!()
        .about("The CONNECT-IP client for Masquerade")
        .arg(arg!(-s --server_name <VALUE>).default_value("127.0.0.1:4433").required(false))
        .arg(arg!(-a --tun_addr <VALUE>).default_value("10.9.0.2/24").required(false))
        .arg(arg!(-g --tun_gateway <VALUE>).default_value("10.9.0.1").required(false))
        .arg(arg!(-n --tun_name <VALUE>).default_value("tunMC").required(false))
        .get_matches();


    let server_name = matches.get_one::<String>("server_name").expect("Bind address not here?");
    let tun_addr = matches.get_one::<String>("tun_addr").expect("Tun address not here?");
    let tun_name = matches.get_one::<String>("tun_name").expect("Bind address not here?");
    let tun_gateway = matches.get_one::<String>("tun_gateway").expect("Bind address not here?");

    info!("Starting connect-ip client with config: \nServer address: {}\nTUN Address: {}\nTUN Name: {}\nTUN Gateway: {}",
            server_name, tun_addr, tun_name, tun_gateway);
    let newclient = ConnectIPClient;
    newclient.run(
        server_name, 
        tun_addr.to_owned(), 
        tun_gateway.to_owned(), 
        tun_name.to_owned()).await;

    Ok(())
}
