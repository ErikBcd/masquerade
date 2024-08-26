use clap::{arg, command};
use masquerade_proxy::ip_connect::client::{ClientConfig, ConnectIPClient};
use masquerade_proxy::common::ConfigError;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;

fn read_config() -> Result<ClientConfig, ConfigError> { 
    let matches = command!()
        .about("The CONNECT-IP client for Masquerade")
        .arg(arg!(-s --server_name <VALUE>).required(false))
        .arg(arg!(-a --tun_addr <VALUE>).required(false))
        .arg(arg!(-g --tun_gateway <VALUE>).required(false))
        .arg(arg!(-n --tun_name <VALUE>).required(false))
        .arg(arg!(-c --config <VALUE>).default_value("./config/client_config.toml").required(false))
        .arg(arg!(--use_static_ip <bool>).required(false))
        .arg(arg!(--static_ip <VALUE>).required(false))
        .arg(arg!(--client_name <VALUE>).required(false))
        .get_matches();

    let config_path = matches.get_one::<String>("config").expect("Config path not here?");

    let mut file = match File::open(config_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(ConfigError::ConfigFileError((e.to_string(), config_path.to_owned())));
        },
    };
    let mut config_contents = String::new();
    match file.read_to_string(&mut config_contents) {
        Ok(_) => {},
        Err(e) => {
            return Err(ConfigError::ConfigFileError((e.to_string(), config_path.to_owned())));
        },
    }
    let mut config: ClientConfig = toml::from_str(&config_contents).unwrap();

    // Check for existing command line arguments and swap the values out 
    if let Some(server_name) = matches.get_one::<String>("server_name") {
        config.server_name = Some(server_name.to_owned());
    }
    if let Some(tun_addr) = matches.get_one::<String>("tun_addr") {
        config.tun_addr = Some(tun_addr.to_owned());
    }

    if let Some(tun_name) = matches.get_one::<String>("tun_name") {
        config.tun_name = Some(tun_name.to_owned());
    }

    if let Some(use_static_ip) = matches.get_one::<bool>("use_static_ip") {
        config.use_static_ip = Some(use_static_ip.to_owned());
    }

    if let Some(static_ip) = matches.get_one::<String>("static_ip") {
        config.desired_addr = Some(static_ip.to_owned());
    }

    if let Some(client_name) = matches.get_one::<String>("client_name") {
        config.client_name = Some(client_name.to_owned());
    }

    // Check the config for any missing arguments
    // Default arguments will be filled out automatically
    if config.server_name.is_none() {
        return Err(ConfigError::MissingArgument("server_name".to_owned()));
    }

    if config.tun_addr.is_none() {
        config.tun_addr = Some("10.9.0.2/24".to_owned());
    }

    if config.tun_name.is_none() {
        config.tun_name = Some("tunMC".to_owned());
    }

    if config.tun_gateway.is_none() {
        config.tun_gateway = Some("10.9.0.1".to_owned());
    }

    if config.use_static_ip.is_none() {
        config.use_static_ip = Some(false);
    }

    if config.desired_addr.is_none() {
        config.desired_addr = Some("0.0.0.0/32".to_owned());
    }

    if config.desired_addr.is_none() {
        config.client_name = Some("".to_owned());
    }

    // Sanity checks

    if config.client_name.as_ref().unwrap().len() > 255 {
        return Err(ConfigError::WrongArgument(
            format!("Given client name is too long! Length: {} | Max allowed is 256", 
            config.client_name.unwrap().len())));
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let newclient = ConnectIPClient;
    let conf = match read_config() {
        Ok(v) => v,
        Err(e) => {
            panic!("Error when reading config: {e}");
        },
    };

    println!("Starting connect-ip client with config: {}", conf);
    newclient.run(conf).await;

    Ok(())
}
