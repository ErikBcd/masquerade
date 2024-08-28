use clap::{arg, command};
use masquerade_proxy::common::ConfigError;
use masquerade_proxy::ip_connect::client::{ClientConfig, ConnectIPClient};

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;

fn read_config() -> Result<ClientConfig, ConfigError> {
    let matches = command!()
        .about("The CONNECT-IP client for Masquerade")
        .arg(arg!(-s --server_address <URL>).required(false)
            .help("Address of the Masquerade server. Can also be an ipaddress with port"))
        .arg(arg!(-a --interface_address <IPv4Address>).required(false)
            .help("Addressspace which the TUN device of the client will use. [default: 10.9.0.2/24]"))
        .arg(arg!(-g --interface_gateway <IPv4Address>).required(false)
            .help("Standard gateway the TUN device uses, should be within the addressspace defined in --interface_address. [default: 10.9.0.1]"))
        .arg(arg!(-n --interface_name <String>).required(false)
            .help("Name of the created TUN device. [default: tunMC]"))        
        .arg(
            arg!(-c --config <Path>)
                .default_value("./config/client_config.toml")
                .required(false).help("Path to the config file the client will use")
        )
        .arg(arg!(--use_static_address <bool>).required(false)
            .help("Set to true if the client should use a static address. [default: false]"))
        .arg(arg!(--static_address <IPv4Address>).required(false)
            .help("Set a static address within the VPN subnet for the client. [default: 0.0.0.0/32]"))
        .arg(arg!(--client_name <String>).required(false)
            .help("Identification of the client sent to the server. [default: \"\"/ Empty]"))
        .arg(arg!(--thread_channel_max <usize>).required(false)
            .help("The maximum amount of messages that each thread can buffer before dropping packets. [default: 200]")
            .value_parser(clap::value_parser!(usize)))   
        .get_matches();

    let config_path = matches
        .get_one::<String>("config")
        .expect("Config path not here?");

    let mut file = match File::open(config_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(ConfigError::ConfigFileError((
                e.to_string(),
                config_path.to_owned(),
            )));
        }
    };
    let mut config_contents = String::new();
    match file.read_to_string(&mut config_contents) {
        Ok(_) => {}
        Err(e) => {
            return Err(ConfigError::ConfigFileError((
                e.to_string(),
                config_path.to_owned(),
            )));
        }
    }
    let mut config: ClientConfig = toml::from_str(&config_contents).unwrap();

    // Check for existing command line arguments and swap the values out
    if let Some(server_address) = matches.get_one::<String>("server_address") {
        config.server_address = Some(server_address.to_owned());
    }
    if let Some(interface_address) = matches.get_one::<String>("interface_address") {
        config.interface_address = Some(interface_address.to_owned());
    }

    if let Some(interface_name) = matches.get_one::<String>("interface_name") {
        config.interface_name = Some(interface_name.to_owned());
    }

    if let Some(use_static_address) = matches.get_one::<bool>("use_static_address") {
        config.use_static_address = Some(use_static_address.to_owned());
    }

    if let Some(static_address) = matches.get_one::<String>("static_address") {
        config.static_address = Some(static_address.to_owned());
    }

    if let Some(client_name) = matches.get_one::<String>("client_name") {
        config.client_name = Some(client_name.to_owned());
    }

    if let Some(thread_channel_max) = matches.get_one::<usize>("thread_channel_max") {
        config.thread_channel_max = Some(thread_channel_max.to_owned());
    }

    // Check the config for any missing arguments
    // Default arguments will be filled out automatically
    if config.server_address.is_none() {
        return Err(ConfigError::MissingArgument("server_address".to_owned()));
    }

    if config.interface_address.is_none() {
        config.interface_address = Some("10.9.0.2/24".to_owned());
    }

    if config.interface_name.is_none() {
        config.interface_name = Some("tunMC".to_owned());
    }

    if config.interface_gateway.is_none() {
        config.interface_gateway = Some("10.9.0.1".to_owned());
    }

    if config.use_static_address.is_none() {
        config.use_static_address = Some(false);
    }

    if config.static_address.is_none() {
        config.static_address = Some("0.0.0.0/32".to_owned());
    }

    if config.client_name.is_none() {
        config.client_name = Some("".to_owned());
    }

    if config.thread_channel_max.is_none() {
        config.thread_channel_max = Some(200);
    }

    // Sanity checks

    if config.client_name.as_ref().unwrap().len() > 255 {
        return Err(ConfigError::WrongArgument(format!(
            "Given client name is too long! Length: {} | Max allowed is 256",
            config.client_name.unwrap().len()
        )));
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
        }
    };

    println!("Starting connect-ip client with config: \n{}", conf);
    newclient.run(conf).await;

    Ok(())
}
