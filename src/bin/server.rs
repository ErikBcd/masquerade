use clap::{arg, command};
use masquerade_proxy::common::ConfigError;
use masquerade_proxy::server::{Server, ServerConfig};

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;

fn read_config() -> Result<ServerConfig, ConfigError> {
    // Command line arguments take precedence over config file arguments
    let matches = command!()
        .about("The Masquerade server")
        .arg(arg!(-b --server_address <Ipv4Addr>).required(false)
            .help("Local address the server will run on. [default: 0.0.0.0:4433]"))
        .arg(arg!(-a --interface_address <Ipv4Addr>).required(false)
            .help("Address range the virtual network interface device will run on [default: 10.8.0.1/8]"))
        .arg(arg!(-n --interface_name <String>).required(false)
            .help("Name of the virtual network interface device [default: tunMS]"))
        .arg(arg!(-l --local_uplink_device_ip <Ipv4Addr>).required(false)
            .help("IP Address of the local network device connected to the local network [default: 0.0.0.0]"))
        .arg(arg!(-d --local_uplink_device_name <String>).required(false)
            .help("Device name of the local network device connected to the local network. Required."))
        .arg(arg!(-c --config <PATH>).default_value("./config/server_config.toml").required(false)
            .help("Path to the config file the server will use"))
        .arg(arg!(--client_config <PATH>).required(false)
            .help("Path to a file containing known client configurations. [default: ./config/server_known_clients.toml]"))
        .arg(arg!(--create_qlog_file <bool>).required(false)
            .help("Create a qlog file for the connections the server receives. [default: false]"))
        .arg(arg!(--qlog_file_path <PATH>).required(false)
            .help("Directory in which the qlog files will be saved if created. [default: ./qlog/]"))
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
    let mut config: ServerConfig = toml::from_str(&config_contents).unwrap();

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

    if let Some(local_uplink_device_ip) = matches.get_one::<String>("local_uplink_device_ip") {
        config.local_uplink_device_ip = Some(local_uplink_device_ip.to_owned());
    }

    if let Some(local_uplink_device_name) = matches.get_one::<String>("local_uplink_device_name") {
        config.local_uplink_device_name = Some(local_uplink_device_name.to_owned());
    }

    if let Some(client_config_path) = matches.get_one::<String>("client_config_path") {
        config.client_config_path = Some(client_config_path.to_owned());
    }

    if let Some(create_qlog_file) = matches.get_one::<bool>("create_qlog_file") {
        config.create_qlog_file = Some(create_qlog_file.to_owned());
    }

    if let Some(qlog_file_path) = matches.get_one::<String>("qlog_file_path") {
        config.qlog_file_path = Some(qlog_file_path.to_owned());
    }

    // Check the config for any missing arguments
    // Default arguments will be filled out automatically
    if config.server_address.is_none() {
        config.server_address = Some("0.0.0.0:4433".to_owned());
    }

    if config.interface_address.is_none() {
        config.interface_address = Some("10.8.0.1/8".to_owned());
    }

    if config.interface_name.is_none() {
        config.interface_name = Some("tunMS".to_owned());
    }

    if config.local_uplink_device_ip.is_none() {
        config.local_uplink_device_ip = Some("0.0.0.0".to_owned());
    }

    if config.client_config_path.is_none() {
        config.client_config_path = Some("./config/server_known_clients.toml".to_owned());
    }

    if config.create_qlog_file.is_none() {
        config.create_qlog_file = Some(false);
    }

    if config.qlog_file_path.is_none() {
        config.qlog_file_path = Some("./qlog/".to_owned());
    }

    if config.local_uplink_device_name.is_none() {
        return Err(ConfigError::MissingArgument(
            "local_uplink_device_name".to_owned(),
        ));
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let conf = match read_config() {
        Ok(v) => v,
        Err(e) => {
            panic!("Error when reading config: {e}");
        }
    };

    println!("Starting server with config: \n{}", conf);
    let mut server = Server::default();
    
    server.bind(conf.server_address.as_ref().unwrap()).await?;

    server.run(conf).await
}
