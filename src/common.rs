use log::error;
use quiche::h3::NameValue;
use tokio::sync::mpsc;

use crate::connect_ip::util::*;
use std::{
    net::{self, Ipv4Addr},
    str::FromStr,
};
pub const MAX_DATAGRAM_SIZE: usize = 65535;

#[derive(Debug)]
pub enum ConfigError {
    MissingArgument(String),
    ConfigFileError((String, String)),
    WrongArgument(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::MissingArgument(s) => {
                write!(f, "Argument required but not given: {s}")
            }
            ConfigError::ConfigFileError(s) => {
                write!(f, "Error when reading file \"{}\": {}", s.1, s.0)
            }
            ConfigError::WrongArgument(s) => {
                write!(f, "Wrong Argument: {s}")
            }
        }
    }
}

/// HTTP/3 message types.
#[derive(Debug)]
pub enum Content {
    Request {
        headers: Vec<quiche::h3::Header>,
        stream_id_sender: mpsc::Sender<u64>,
    },
    Headers {
        headers: Vec<quiche::h3::Header>,
    },
    Data {
        data: Vec<u8>,
    },
    Datagram {
        payload: Vec<u8>,
    },
    Finished,
}

/// QUIC packet
#[derive(Debug)]
pub struct ToSend {
    pub stream_id: u64, // or flow_id for DATAGRAM
    pub content: Content,
    pub finished: bool,
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &str,
    role: &str,
    id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

/// Gets the next IPv4 address
/// If the next address isn't allowed by the netmask an error is returned.
///
/// # Examples
/// ```
///     assert_eq!(
///        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 1), 0xFFFFFF00),
///        Ok(Ipv4Addr::new(192, 168, 0, 2)));
///
///     assert_eq!(
///        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 255), 0xFFFF0000),
///        Ok(Ipv4Addr::new(192, 168, 1, 0)));
///
///     assert_eq!(
///        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 255), 0xFFFFFF00),
///        Err(IPError { message: "Next address out of range!".to_owned()}));
/// ```
pub fn get_next_ipv4(ip: Ipv4Addr, netmask: u32) -> Result<Ipv4Addr, IPError> {
    let temp = ip;
    let mut val: u32 = u32::from(temp);
    let compare = val;
    val += 1;
    if (val & netmask) == (compare & netmask) {
        Ok(Ipv4Addr::from(val))
    } else {
        Err(IPError {
            message: "Next address out of range!".to_owned(),
        })
    }
}

///
/// Parses an IP and splits off the prefix
/// If the prefix was not found or if it wasn't possible to
/// parse the second part of the 2 tuple will be None.
///
/// # Examples
/// ```
///     assert_eq!(split_ip_prefix("192.168.0.0/24".to_string()),
///                 ("192.168.0.0".to_string(), Some(24)));
///                
///     assert_eq!(split_ip_prefix("192.168.0.0".to_string()),
///                 ("192.168.0.0".to_string(), None));
///     
///     assert_eq!(split_ip_prefix("192.168.0.0/ab".to_string()),
///                 ("192.168.0.0".to_string(), None));
/// ```
pub fn split_ip_prefix(ip: String) -> (String, Option<u8>) {
    let prefix_index = ip.find("/");
    if prefix_index.is_none() {
        return (ip, None);
    }
    let addr = String::from_str(&ip[..(prefix_index.unwrap())]).unwrap();
    let prefix_str = String::from_str(&ip[(prefix_index.unwrap() + 1)..]).unwrap();
    let prefix: u8 = match prefix_str.trim().parse() {
        Ok(v) => v,
        Err(e) => {
            error!("Couldn't parse prefix from IP: {} | Error: {}", ip, e);
            return (addr, None);
        }
    };

    (addr, Some(prefix))
}

pub fn send_h3_dgram(
    conn: &mut quiche::Connection,
    flow_id: u64,
    dgram_content: &[u8],
) -> quiche::Result<()> {
    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    // Creates a OctetsMut in the d vector
    let mut b = octets::OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

pub fn interrupted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Interrupted
}

/*
 * Decode variable-length integer in QUIC and related protocols
 *
 * ref: https://www.rfc-editor.org/rfc/rfc9000#sample-varint
 */
pub fn decode_var_int(data: &[u8]) -> (u64, &[u8]) {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v &= 0x3f;
    for i in 1..length - 1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    (v, &data[length..])
}

/*
 * Decode variable-length integer in QUIC and related protocols
 *
 * ref: https://www.rfc-editor.org/rfc/rfc9000#sample-varint
 *
 * Returns the length of the decoded integer and it's value
 */
pub fn decode_var_int_get_length(data: &[u8]) -> (u64, usize) {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v &= 0x3f;
    for i in 1..length - 1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    (v, length)
}

pub const MAX_VAR_INT: u64 = u64::pow(2, 62) - 1;
const MAX_INT_LEN_4: u64 = u64::pow(2, 30) - 1;
const MAX_INT_LEN_2: u64 = u64::pow(2, 14) - 1;
const MAX_INT_LEN_1: u64 = u64::pow(2, 6) - 1;

pub fn encode_var_int(v: u64) -> Vec<u8> {
    assert!(v <= MAX_VAR_INT);
    let (prefix, length) = if v > MAX_INT_LEN_4 {
        (3, 8)
    } else if v > MAX_INT_LEN_2 {
        (2, 4)
    } else if v > MAX_INT_LEN_1 {
        (1, 2)
    } else {
        (0, 1)
    };

    let mut encoded = v.to_be_bytes()[..length].to_vec();
    let prefix: u8 = prefix << 6;
    encoded[0] |= prefix;
    encoded
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
pub fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    // TODO: add cryptographic token
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
pub fn validate_token<'a>(
    src: &net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}
