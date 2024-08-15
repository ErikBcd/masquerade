use std::{
    error::Error, io::Read, net::Ipv4Addr, sync::{Arc, Mutex}
};

use tun2::platform::posix::{Reader, Writer};
use tokio::sync::mpsc::{self};



#[derive(Debug, Clone)]
pub struct UdpBindError;

impl std::fmt::Display for UdpBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "get_udp(server_addr) has failed!")
    }
}
impl Error for UdpBindError {}

#[derive(Debug, Clone)]
pub struct HandleIPError {
    pub message: String,
}

impl std::fmt::Display for HandleIPError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Unable to handle IP message: {}", self.message)
    }
}
impl Error for HandleIPError {}

#[derive(Debug, Clone, PartialEq)]
pub struct IPError {
    pub message: String,
}

impl std::fmt::Display for IPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "get_udp(server_addr) has failed! Error: {}",
            self.message
        )
    }
}

#[derive(Debug, Clone)]
pub struct QUICStreamError {
    pub message: String,
}

impl std::fmt::Display for QUICStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Could not creat IP connect stream! Error: {}",
            self.message
        )
    }
}

/**
 * Sets the source ip address of a given IPv4 buffer to 
 * the given adress.
 */
pub fn set_ipv4_pkt_source(pkt: &mut Vec<u8>, ip: &Ipv4Addr) {
    pkt[12] = ip.octets()[0];
    pkt[13] = ip.octets()[1];
    pkt[14] = ip.octets()[2];
    pkt[15] = ip.octets()[3];
}