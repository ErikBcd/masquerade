use clap::{arg, command};
use log::info;
use masquerade_proxy::server::{Server, ServerConfig};
use masquerade_proxy::common::ConfigError;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;


fn read_config() -> Result<ServerConfig, ConfigError> {
    // Command line arguments take precedence over config file arguments
    let matches = command!()
        .about("The Masquerade server")
        .arg(arg!(-b --bind_addr <VALUE>).required(false))
        .arg(arg!(-a --tun_addr <VALUE>).required(false))
        .arg(arg!(-n --tun_name <VALUE>).required(false))
        .arg(arg!(-l --local_ip <VALUE>).required(false))
        .arg(arg!(-c --config <VALUE>).default_value("./config/server_config.toml").required(false))
        .arg(arg!(--client_config <VALUE>).required(false))
        .arg(arg!(-d --link_dev <VALUE>).required(false))
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
    let mut config: ServerConfig = toml::from_str(&config_contents).unwrap();

    // Check for existing command line arguments and swap the values out 
    if let Some(bind_addr) = matches.get_one::<String>("bind_addr") {
        config.bind_addr = Some(bind_addr.to_owned());
    }
    if let Some(tun_addr) = matches.get_one::<String>("tun_addr") {
        config.tun_addr = Some(tun_addr.to_owned());
    }

    if let Some(tun_name) = matches.get_one::<String>("tun_name") {
        config.tun_name = Some(tun_name.to_owned());
    }

    if let Some(local_ip) = matches.get_one::<String>("local_ip") {
        config.local_ip = Some(local_ip.to_owned());
    }

    if let Some(link_dev) = matches.get_one::<String>("link_dev") {
        config.link_dev = Some(link_dev.to_owned());
    }

    if let Some(client_config_path) = matches.get_one::<String>("client_config_path") {
        config.client_config_path = Some(client_config_path.to_owned());
    }

    // Check the config for any missing arguments
    // Default arguments will be filled out automatically
    if config.bind_addr.is_none() {
        config.bind_addr = Some("0.0.0.0:4433".to_owned());
    }

    if config.tun_addr.is_none() {
        config.tun_addr = Some("10.8.0.1/24".to_owned());
    }

    if config.tun_name.is_none() {
        config.tun_name = Some("tunMS".to_owned());
    }

    if config.local_ip.is_none() {
        config.local_ip = Some("0.0.0.0".to_owned());
    }

    if config.client_config_path.is_none() {
        config.client_config_path = Some("./config/server_known_clients.toml".to_owned());
    }

    if config.link_dev.is_none() {
        return Err(ConfigError::MissingArgument("link_dev".to_owned()));
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
        },
    };

    info!("Starting server with config: {}", conf);
    let mut server = Server::default();
    server.bind(conf.bind_addr.as_ref().unwrap()).await?;

    server.run(conf).await
}
