use octets::{Octets, OctetsMut};

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

pub enum CapsuleType {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
}

#[derive(PartialEq, Debug)]
pub enum IpLength {
    V6(u128),
    V4(u32),
}
impl std::fmt::Display for IpLength {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Capsule {
    pub capsule_id: u64,
    pub capsule_type: CapsuleType,
}

pub struct AddressAssign {
    pub length: u64,
    pub assigned_address: Vec<AssignedAddress>,
}

pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: u8, // either 4 or 6
    pub ip_address: IpLength,
    pub ip_prefix_len: u8,
}

pub struct AddressRequest {
    pub length: u64,
    pub requested: Vec<RequestedAddress>,
}
// Requesting an ip address like 0.0.0.0 or :: means sender doesn't have preference
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_version: u8,       // either 4 or 6
    pub ip_address: IpLength, // length depends on ip_version
    pub ip_prefix_len: u8,
}

pub struct RouteAdvertisement {
    pub length: u64,
    pub addr_ranges: Vec<AddressRange>,
}

pub struct AddressRange {
    pub ip_version: u8,
    pub start_ip: IpLength, // must be less or equal to end_ip
    pub end_ip: IpLength,
    pub ip_proto: u8, // 0 means any traffic is allowed. ICMP is always allowed
}

impl Capsule {
    /**
     * Parses the body of a DATA type HTTP/3 packet.
     */
    pub fn new(buf: &[u8]) -> Result<Capsule, CapsuleParseError> {
        //varint_parse_len(first)
        let mut oct = Octets::with_slice(buf);

        let capsule_type_id = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let c_type = match capsule_type_id {
            1 => {
                // ADDRESS_ASSIGN
                match AddressAssign::new(&mut oct) {
                    Ok(v) => CapsuleType::AddressAssign(v),
                    Err(e) => return Err(e),
                }
            }
            2 => match AddressRequest::new(&mut oct) {
                Ok(v) => CapsuleType::AddressRequest(v),
                Err(e) => return Err(e),
            },
            3 => match RouteAdvertisement::new(&mut oct) {
                Ok(v) => CapsuleType::RouteAdvertisement(v),
                Err(e) => return Err(e),
            },
            _ => return { Err(CapsuleParseError::InvalidCapsuleType) },
        };

        Ok(Capsule {
            capsule_id: capsule_type_id,
            capsule_type: c_type,
        })
    }

    /**
     * Serializes this capsule
     * Can be sent in a HTTP/3 DATA message as the payload.
     */
    pub fn serialize(&self, buf: &mut [u8]) -> Vec<u8> {
        let mut oct = OctetsMut::with_slice(buf);

        oct.put_varint(self.capsule_id).unwrap();

        match &self.capsule_type {
            CapsuleType::AddressAssign(v) => {
                v.serialize(&mut oct);
            }
            CapsuleType::AddressRequest(v) => {
                v.serialize(&mut oct);
            }
            CapsuleType::RouteAdvertisement(v) => {
                v.serialize(&mut oct);
            }
        };

        return oct.to_vec();
    }

    pub fn as_address_assign(&self) -> Option<&AddressAssign> {
        if let CapsuleType::AddressAssign(ref address_assign) = self.capsule_type {
            Some(address_assign)
        } else {
            None
        }
    }

    pub fn as_address_request(&self) -> Option<&AddressRequest> {
        if let CapsuleType::AddressRequest(ref address_request) = self.capsule_type {
            Some(address_request)
        } else {
            None
        }
    }

    pub fn as_route_advertisement(&self) -> Option<&RouteAdvertisement> {
        if let CapsuleType::RouteAdvertisement(ref route_advertisement) = self.capsule_type {
            Some(route_advertisement)
        } else {
            None
        }
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
        while oct.off() < (length - 1).try_into().unwrap() {
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

    /**
     * Serializes this capsule
     * Can be sent in a HTTP/3 DATA message as the payload.
     */
    pub fn serialize(&self, buf: &mut OctetsMut) {
        buf.put_varint(self.length).unwrap();

        for s in &self.assigned_address {
            buf.put_varint(s.request_id).unwrap();
            buf.put_u8(s.ip_version).unwrap();
            match s.ip_address {
                IpLength::V4(v) => {
                    buf.put_u32(v).unwrap();
                }
                IpLength::V6(v) => {
                    buf.put_bytes(&v.to_be_bytes()).unwrap();
                }
            }
            buf.put_u8(s.ip_prefix_len).unwrap();
        }
    }
}

impl AddressRequest {
    pub fn new(oct: &mut Octets) -> Result<AddressRequest, CapsuleParseError> {
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut adresses: Vec<RequestedAddress> = Vec::new();
        while oct.off() < (length - 1).try_into().unwrap() {
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

    /**
     * Serializes this capsule
     * Can be sent in a HTTP/3 DATA message as the payload.
     */
    pub fn serialize(&self, buf: &mut OctetsMut) {
        buf.put_varint(self.length).unwrap();

        for s in &self.requested {
            buf.put_varint(s.request_id).unwrap();
            buf.put_u8(s.ip_version).unwrap();
            match s.ip_address {
                IpLength::V4(v) => {
                    buf.put_u32(v).unwrap();
                }
                IpLength::V6(v) => {
                    buf.put_bytes(&v.to_be_bytes()).unwrap();
                }
            }
            buf.put_u8(s.ip_prefix_len).unwrap();
        }
    }
}

impl RouteAdvertisement {
    pub fn new(oct: &mut Octets) -> Result<RouteAdvertisement, CapsuleParseError> {
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut adv: Vec<AddressRange> = Vec::new();
        while oct.off() < (length - 1).try_into().unwrap() {
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

            adv.push(AddressRange {
                ip_version: ip_ver,
                start_ip: start,
                end_ip: end,
                ip_proto: proto,
            });
        }
        Ok(RouteAdvertisement {
            length: length,
            addr_ranges: adv,
        })
    }

    /**
     * Serializes this capsule
     * Can be sent in a HTTP/3 DATA message as the payload.
     */
    pub fn serialize(&self, buf: &mut OctetsMut) {
        buf.put_varint(self.length).unwrap();

        for s in &self.addr_ranges {
            buf.put_u8(s.ip_version).unwrap();
            match s.start_ip {
                IpLength::V4(v) => {
                    buf.put_u32(v).unwrap();
                }
                IpLength::V6(v) => {
                    buf.put_bytes(&v.to_be_bytes()).unwrap();
                }
            }
            match s.end_ip {
                IpLength::V4(v) => {
                    buf.put_u32(v).unwrap();
                }
                IpLength::V6(v) => {
                    buf.put_bytes(&v.to_be_bytes()).unwrap();
                }
            }

            buf.put_u8(s.ip_proto).unwrap();
        }
    }
}

/**
 * Reads an ip from the current position of the given octet.
 */
fn read_ip(oct: &mut Octets, ip_ver: &u8) -> Result<IpLength, CapsuleParseError> {
    let addr = match ip_ver {
        4 => IpLength::V4(
            oct.get_u32()
                .map_err(|_| CapsuleParseError::BufferTooShort)?,
        ),
        6 => IpLength::V6(
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
