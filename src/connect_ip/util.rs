use std::{error::Error, net::Ipv4Addr};

use log::{debug, error};
use packet::ip::v4::{self};

use crate::common::{encode_var_int, Content, ToSend};

const UDP_ID: u8 = 17;
const TCP_ID: u8 = 6;

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

///
/// Creates a ToSend struct for sending IPSend
///
pub fn encapsulate_ipv4(pkt: Vec<u8>, flow_id: &u64, context_id: &u64) -> ToSend {
    let context_id_enc = encode_var_int(*context_id);
    let payload = [&context_id_enc, pkt.as_slice()].concat();
    ToSend {
        stream_id: *flow_id,
        content: Content::Datagram { payload },
        finished: false,
    }
}

#[inline]
///
/// Returns the version of the ip packet slice, given in the first nibble
pub fn get_ip_version(pkt: &[u8]) -> u8 {
    pkt[0] >> 4
}

#[inline]
///
/// Return the header length of a given packet slice
/// The header len is at the second nibble of a ipv4 packet
/// Header length is given in 32bit words. A header value of 0b1111 = 15, 15*32=480bit=60byte
pub fn get_ip_header_length(pkt: &[u8]) -> u8 {
    4 * (pkt[0] & 0b1111)
}

#[inline]
///
/// Return the ttl of a given packet slice
pub fn get_ipv4_ttl(pkt: &[u8]) -> u8 {
    pkt[8]
}

#[inline]
///
/// Sets the source ip address of a given IPv4 buffer to
/// the given adress.
/// Warning: This does NOT check if this is a valid IP packet, or even if the pkt
/// is long enough.
///
pub fn set_ipv4_pkt_source(pkt: &mut [u8], ip: &Ipv4Addr) {
    pkt[12] = ip.octets()[0];
    pkt[13] = ip.octets()[1];
    pkt[14] = ip.octets()[2];
    pkt[15] = ip.octets()[3];
}

#[inline]
///
/// Sets the destination ip address of a given IPv4 buffer to
/// the given adress.
/// Warning: This does NOT check if this is a valid IP packet, or even if the pkt
/// is long enough.
///
pub fn set_ipv4_pkt_destination(pkt: &mut [u8], ip: &Ipv4Addr) {
    pkt[16] = ip.octets()[0];
    pkt[17] = ip.octets()[1];
    pkt[18] = ip.octets()[2];
    pkt[19] = ip.octets()[3];
}

#[inline]
///
/// Reads the source addr of a given IPv4 packet.
/// Warning: This does NOT check if this is a valid IP packet, or even if the pkt
/// is long enough.
///
pub fn get_ipv4_pkt_source(pkt: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])
}

#[inline]
///
/// Reads the destination addr of a given IPv4 packet.
/// Warning: This does NOT check if this is a valid IP packet, or even if the pkt
/// is long enough.
///
pub fn get_ipv4_pkt_dest(pkt: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])
}

#[inline]
///
/// Read the checksum of a ipv4 packet
/// Does not *calculate* the checksum, only reads it from the header!
pub fn get_ipv4_hdr_checksum(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[10], pkt[11]])
}

#[derive(Debug, PartialEq)]
pub enum Ipv4CheckError {
    WrongChecksumError,
    WrongSizeError,
}

pub fn check_ipv4_packet(pkt: &[u8], len: u16) -> Result<(), Ipv4CheckError> {
    if u16::from(get_ip_header_length(pkt)) >= len {
        return Err(Ipv4CheckError::WrongSizeError);
    }
    let hdr_len = usize::from(get_ip_header_length(pkt));
    if get_ipv4_hdr_checksum(pkt) != v4::checksum(&pkt[..hdr_len]) {
        return Err(Ipv4CheckError::WrongChecksumError);
    }
    Ok(())
}

/// Updates the checksum of a IPv4 header to be correct.
/// # Examples
/// ```
///     set_ipv4_pkt_source(&mut pkt.message, Ipv4Addr::new(192, 168, 0, 255));   
///     update_ipv4_checksum(&mut pkt.message, 60);
/// ```
///
pub fn update_ipv4_checksum(pkt: &mut [u8], header_length: u8) {
    let new_chcksm = v4::checksum(&pkt[..header_length.into()]).to_be_bytes();
    pkt[10] = new_chcksm[0];
    pkt[11] = new_chcksm[1];
}

fn checksum_add(len: usize, buf: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for i in 0..len {
        if i & 1 != 0 {
            sum += u32::from(buf[i]);
        } else {
            sum += u32::from(buf[i]) << 8;
        }
    }
    sum
}

///
/// Recalculate the checksum of a udp or tcp packet
/// References:
///  - https://gist.github.com/fxlv/81209bbd150abfeaceb1f85ff076c9f3
///  - http://profesores.elo.utfsm.cl/~agv/elo322/UDP_Checksum_HowTo.html
pub fn calculate_tcp_udp_checksum(
    source: &[u8],
    dest: &[u8],
    proto: u8,
    pkt: &mut [u8],
    ip_header_len: usize,
) {
    if pkt.len() > 65535 {
        error!("Packet len is somehow larger than maximum allowed IP length.");
        return;
    }

    let payload_len = pkt.len() - ip_header_len;
    let checksum_offset: usize = match proto {
        17 => 6, // UDP
        6 => 16, // TCP
        _ => {
            debug!("Tried to calculate checksum of packet that isn't TCP or UDP!");
            return;
        }
    };

    // Set old checksum to 0
    pkt[checksum_offset + ip_header_len] = 0;
    pkt[checksum_offset + ip_header_len + 1] = 0;

    let mut chk: u32 = 0;

    chk += checksum_add(payload_len, &pkt[ip_header_len..]);
    chk += checksum_add(4, source);
    chk += checksum_add(4, dest);
    chk += u32::from(proto) + (payload_len as u32);

    while chk >> 16 != 0 {
        chk = (chk & 0xFFFF) + (chk >> 16);
    }
    let final_sum = !chk as u16;

    pkt[ip_header_len + checksum_offset] = (final_sum >> 8).try_into().unwrap();
    pkt[ip_header_len + checksum_offset + 1] = (final_sum & 0xff).try_into().unwrap();
}

///
/// Recalculates the checksum of a ipv4 packet.
/// If the payload is TCP or UDP we also recalculate that checksum.
pub fn recalculate_checksum(pkt: &mut [u8]) {
    // First recalculate the ipv4 header checksum
    let ip_ver = pkt[0] >> 4;

    if ip_ver == 6 {
        // TODO: Implement recalculation for ipv6 packets
        todo!();
    }

    let header_length = 4 * (pkt[0] & 0b1111);
    update_ipv4_checksum(pkt, header_length);

    let proto = pkt[9];

    // If this isn't a UDP/TCP packet we don't have anything else to do
    if proto != UDP_ID && proto != TCP_ID {
        return;
    }
    let source = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dest = [pkt[16], pkt[17], pkt[18], pkt[19]];
    calculate_tcp_udp_checksum(&source, &dest, proto, pkt, header_length.into());
}
