use clap::{arg, command};
use log::info;
use masquerade_proxy::server::Server;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let matches = command!()
        .about("The Masquerade server")
        .arg(arg!(-b --bind_addr <VALUE>).default_value("0.0.0.0:4433").required(false))
        .arg(arg!(-a --tun_addr <VALUE>).default_value("10.8.0.1/24").required(false))
        .arg(arg!(-n --tun_name <VALUE>).default_value("tunMS").required(false))
        .arg(arg!(-l --local_ip <VALUE>).default_value("0.0.0.0").required(false))
        .arg(arg!(-d --link_dev <VALUE>).required(true))
        .get_matches();

    let bind_addr = matches.get_one::<String>("bind_addr").expect("Bind address not here?");
    let tun_addr = matches.get_one::<String>("tun_addr").expect("Bind address not here?");
    let tun_name = matches.get_one::<String>("tun_name").expect("Bind address not here?");
    let local_ip = matches.get_one::<String>("local_ip").expect("Bind address not here?");
    let link_dev = matches.get_one::<String>("link_dev").expect("Bind address not here?");

    info!("Starting server with config: \nUDP Bind address: {}\nTUN Address: {}\nTUN Name: {}\nLocal IP: {}\nLink Route Device: {}",
            bind_addr, tun_addr, tun_name, local_ip, link_dev);
    
    let mut server = Server::new();
    server.bind(bind_addr).await?;

    server.run(tun_addr.to_owned(), 
        tun_name.to_owned(), 
        local_ip.to_owned(), 
        link_dev.to_owned()).await
}
