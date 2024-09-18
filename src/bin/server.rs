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
        .arg(arg!(--mtu <u32>).required(false)
            .help("MTU for the connection (should be same as server) [default: 1200]"))
        .arg(arg!(--congestion_algorithm <String>).required(false)
            .help("Congestion algorithm for QUIC to use. One of \"cubic\", \"bbr2\", \"bbr\", \"reno\" [default: cubic]"))
        .arg(arg!(--max_pacing_rate <u64>).required(false)
            .help("Maximum pacing rate for QUIC. 0 for no limit [default: 0]")
            .value_parser(clap::value_parser!(u64)))   
        .arg(arg!(--disable_active_migration <bool>).required(false)
            .help("Disable active migration for QUIC [default: false]"))
        .arg(arg!(--enable_hystart <bool>).required(false)
            .help("Enables hystart for QUIC [default: false]"))
        .arg(arg!(--discover_pmtu <bool>).required(false)
            .help("Enable Path MTU discovery for QUIC [default: false]"))
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

    if let Some(mtu) = matches.get_one::<String>("mtu") {
        config.mtu = Some(mtu.to_owned());
    }

    if let Some(congestion_algorithm) = matches.get_one::<String>("congestion_algorithm") {
        config.congestion_algorithm = Some(congestion_algorithm.to_owned());
    }

    if let Some(max_pacing_rate) = matches.get_one::<u64>("max_pacing_rate") {
        config.max_pacing_rate = Some(max_pacing_rate.to_owned());
    }

    if let Some(disable_active_migration) = matches.get_one::<bool>("disable_active_migration") {
        config.disable_active_migration = Some(disable_active_migration.to_owned());
    }

    if let Some(enable_hystart) = matches.get_one::<bool>("enable_hystart") {
        config.enable_hystart = Some(enable_hystart.to_owned());
    }

    if let Some(discover_pmtu) = matches.get_one::<bool>("discover_pmtu") {
        config.discover_pmtu = Some(discover_pmtu.to_owned());
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

    if config.mtu.is_none() {
        config.mtu = Some("1200".to_owned());
    }

    if config.congestion_algorithm.is_none() {
        config.congestion_algorithm = Some("cubic".to_owned());
    }

    if config.max_pacing_rate.is_none() {
        config.max_pacing_rate = Some(0);
    }

    if config.disable_active_migration.is_none() {
        config.disable_active_migration = Some(false);
    }

    if config.enable_hystart.is_none() {
        config.enable_hystart = Some(false);
    }

    if config.discover_pmtu.is_none() {
        config.discover_pmtu = Some(false);
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
