use log::info;
use quiche::h3::NameValue;


pub const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn send_h3_dgram(
    conn: &mut quiche::Connection, flow_id: u64, dgram_content: &[u8],
) -> quiche::Result<()> {
    info!(
        "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
        flow_id, dgram_content
    );

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
    v = v & 0x3f;
    for i in 1..length-1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    (v, &data[length..])
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
    encoded[0] = encoded[0] | prefix;
    encoded
}

pub fn wrap_udp_connect_payload(context_id: u64, payload: &[u8]) -> Vec<u8> {
    let context_id = encode_var_int(context_id);
    [&context_id, payload].concat()
}

