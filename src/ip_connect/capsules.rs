use octets::Octets;

#[derive(Debug)]
pub enum CapsuleParseError {
    InvalidLength,
    InvalidCapsuleType,
    BufferTooShort,
    InvalidIPVersion,
    Other(String),
}

impl std::fmt::Display for CapsuleParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CapsuleParseError {}

enum CapsuleType {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
}

enum IP_Length {
    V6(u128),
    V4(u32),
}

struct Capsule {
    capsule_type: CapsuleType,
}

struct AddressAssign {
    length: u64,
    assigned_address: Vec<AssignedAddress>,
}

struct AssignedAddress {
    request_id: u64,
    ip_version: u8, // either 4 or 6
    ip_address: IP_Length,
    ip_prefix_len: u8,
}

struct AddressRequest {
    length: u64,
    requested: Vec<RequestedAddress>,
}
// Requesting an ip address like 0.0.0.0 or :: means sender doesn't have preference
struct RequestedAddress {
    request_id: u64,
    ip_version: u8,        // either 4 or 6
    ip_address: IP_Length, // length depends on ip_version
    ip_prefix_len: u8,
}

struct RouteAdvertisement {
    length: u64,
    addr_ranges: Vec<AddressRange>
}

struct AddressRange {
    ip_version: u8,
    start_ip: IP_Length, // must be less or equal to end_ip
    end_ip: IP_Length,
    ip_proto: u8, // 0 means any traffic is allowed. ICMP is always allowed
}

impl Capsule {
    /**
     * Parses the body of a DATA type HTTP/3 packet.
     */
    pub fn new(mut buf: &[u8], len: u32) -> Result<Capsule, CapsuleParseError> {
        //varint_parse_len(first)
        let mut oct = Octets::with_slice(buf);

        let capsule_type_id = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let c_type = match capsule_type_id {
            0x01 => {
                // ADDRESS_ASSIGN
                match AddressAssign::new(&mut oct) {
                    Ok(v) => CapsuleType::AddressAssign(v),
                    Err(e) => return Err(e),
                }
            }
            0x02 => match AddressRequest::new(&mut oct) {
                Ok(v) => CapsuleType::AddressRequest(v),
                Err(e) => return Err(e),
            },
            0x03 => match RouteAdvertisement::new(&mut oct) {
                Ok(v) => CapsuleType::RouteAdvertisement(v),
                Err(e) => return Err(e),
            },
            _ => return Err(CapsuleParseError::InvalidCapsuleType),
        };

        Ok(Capsule { capsule_type: c_type })
    }
}

impl AddressAssign {
    pub fn new(oct: &mut Octets) -> Result<AddressAssign, CapsuleParseError> {
        // First read the request id, which is of variable length
        // ADDRESS_ASSIGN
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut adresses: Vec<AssignedAddress> = Vec::new();
        while oct.off() < oct.len() - 1 {
            let req_id = oct
                .get_varint()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            let ip_ver = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            let addr = match read_ip(oct, &ip_ver) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let ip_pref_len = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            adresses.push(AssignedAddress {
                request_id: req_id,
                ip_version: ip_ver,
                ip_address: addr,
                ip_prefix_len: ip_pref_len,
            })
        }
        Ok(AddressAssign {
            length: length,
            assigned_address: adresses,
        })
    }
}

impl AddressRequest {
    pub fn new(oct: &mut Octets) -> Result<AddressRequest, CapsuleParseError> {
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut adresses: Vec<RequestedAddress> = Vec::new();
        while oct.off() < oct.len() - 1 {
            let req_id = oct
                .get_varint()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            let ip_ver = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            let addr = match read_ip(oct, &ip_ver) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let ip_pref_len = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            adresses.push(RequestedAddress {
                request_id: req_id,
                ip_version: ip_ver,
                ip_address: addr,
                ip_prefix_len: ip_pref_len,
            })
        }
        Ok(AddressRequest {
            length: length,
            requested: adresses,
        })
    }
}

impl RouteAdvertisement {
    pub fn new(oct: &mut Octets) -> Result<RouteAdvertisement, CapsuleParseError> {
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut adv: Vec<AddressRange> = Vec::new();
        while oct.off() < oct.len() - 1 {
            let ip_ver = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;
            let start = match read_ip(oct, &ip_ver) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let end = match read_ip(oct, &ip_ver) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            let proto = oct
                .get_u8()
                .map_err(|_| CapsuleParseError::BufferTooShort)?;

            adv.push(AddressRange { ip_version: ip_ver, start_ip: start, end_ip: end, ip_proto: proto });
        }
        Ok(RouteAdvertisement {
            length: length,
            addr_ranges: adv
        })
    }
}

fn read_ip(oct: &mut Octets, ip_ver: &u8) -> Result<IP_Length, CapsuleParseError> {
    let addr = match ip_ver {
        4 => IP_Length::V4(
            oct.get_u32()
                .map_err(|_| CapsuleParseError::BufferTooShort)?,
        ),
        6 => IP_Length::V6(
            oct.get_u128()
                .map_err(|_| CapsuleParseError::BufferTooShort)?,
        ),
        _ => {
            return Err(CapsuleParseError::InvalidIPVersion);
        }
    };
    Ok(addr)
}

pub trait OctetsExt {
    fn get_u128(&mut self) -> Result<u128, CapsuleParseError>;
}

impl<'a> OctetsExt for Octets<'a> {
    fn get_u128(&mut self) -> Result<u128, CapsuleParseError> {
        if self.cap() < 16 {
            return Err(CapsuleParseError::BufferTooShort);
        }

        let bytes = self
            .get_bytes(16)
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(&bytes.to_vec());
        Ok(u128::from_be_bytes(array))
    }
}
