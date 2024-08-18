use std::{
    error::Error, net::Ipv4Addr
};

use packet::ip::v4::{self};

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

pub fn get_ipv4_pkt_source(pkt: &Vec<u8>) -> Ipv4Addr {
    Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])
}

/// Updates the checksum of a IPv4 header to be correct.
/// # Examples
/// ```
///     set_ipv4_pkt_source(&mut pkt.message, Ipv4Addr::new(192, 168, 0, 255));   
///     update_ipv4_checksum(&mut pkt.message, 60);
/// ```
/// 
pub fn update_ipv4_checksum(pkt: &mut Vec<u8>, header_length: u8) {
    let new_chcksm = v4::checksum(&pkt[.. header_length.into()]).to_be_bytes();
    pkt[10] = new_chcksm[0];
    pkt[11] = new_chcksm[1];
}