use std::{net::Ipv4Addr, str::FromStr};

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

pub const ADDRESS_ASSIGN_ID: u64        = 0x01;
pub const ADDRESS_REQUEST_ID: u64       = 0x02;
pub const ROUTE_ADVERTISEMENT_ID: u64   = 0x03;
pub const CLIENT_HELLO_ID: u64          = 0x04;

pub const MAX_CLIENT_HELLO_ID_LEN: usize = 255;

impl std::error::Error for CapsuleParseError {}

#[derive(PartialEq, Debug)]
pub enum CapsuleType {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
    ClientHello(ClientHello),
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

#[derive(PartialEq, Debug)]
pub struct Capsule {
    pub capsule_id: u64,
    pub capsule_type: CapsuleType,
}

#[derive(PartialEq, Debug)]
pub struct ClientHello {
    pub length: u64,
    pub id_length: u8,
    pub id: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct AddressAssign {
    pub length: u64,
    pub assigned_address: Vec<AssignedAddress>,
}

#[derive(PartialEq, Debug)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: u8, // either 4 or 6
    pub ip_address: IpLength,
    pub ip_prefix_len: u8,
}

#[derive(PartialEq, Debug)]
pub struct AddressRequest {
    pub length: u64,
    pub requested: Vec<RequestedAddress>,
}

// Requesting an ip address like 0.0.0.0 or :: means sender doesn't have preference
#[derive(PartialEq, Debug)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_version: u8,       // either 4 or 6
    pub ip_address: IpLength, // length depends on ip_version
    pub ip_prefix_len: u8,
}

#[derive(PartialEq, Debug)]
pub struct RouteAdvertisement {
    pub length: u64,
    pub addr_ranges: Vec<AddressRange>,
}

#[derive(PartialEq, Debug)]
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
            ADDRESS_ASSIGN_ID => {
                // ADDRESS_ASSIGN
                match AddressAssign::new(&mut oct) {
                    Ok(v) => CapsuleType::AddressAssign(v),
                    Err(e) => return Err(e),
                }
            }
            ADDRESS_REQUEST_ID => match AddressRequest::new(&mut oct) {
                Ok(v) => CapsuleType::AddressRequest(v),
                Err(e) => return Err(e),
            },
            ROUTE_ADVERTISEMENT_ID => match RouteAdvertisement::new(&mut oct) {
                Ok(v) => CapsuleType::RouteAdvertisement(v),
                Err(e) => return Err(e),
            },
            CLIENT_HELLO_ID => match ClientHello::new(&mut oct) {
                Ok(v) => CapsuleType::ClientHello(v),
                Err(e) => return Err(e),
            }
            _ => return Err(CapsuleParseError::InvalidCapsuleType),
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
            },
            CapsuleType::ClientHello(v) => {
                v.serialize(&mut oct);
            },
        };

        oct.to_vec()
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

    pub fn as_client_hello(&self) -> Option<&ClientHello> {
        if let CapsuleType::ClientHello(ref client_hello) = self.capsule_type {
            Some(client_hello)
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
            length,
            assigned_address: adresses,
        })
    }

    /// 
    /// Creates a new basic Capsule containing an ADDRESS_ASSIGN.
    /// If prefix is None the requested prefix will be 32, 
    /// request_id defaults to 0
    /// 
    pub fn create_new(addr: Ipv4Addr, prefix: Option<u8>, request_id: Option<u64>) -> Capsule {
        let prefix = prefix.unwrap_or(32);
        let request_id = request_id.unwrap_or(0);

        let addr = AssignedAddress {
            request_id,
            ip_version: 4,
            ip_address: IpLength::V4(addr.into()),
            ip_prefix_len: prefix, // we only give out a single IP per client
        };
        let req_inner_cap = AddressAssign {
            length: 9,
            assigned_address: vec![addr],
        };
        Capsule {
            capsule_id: ADDRESS_ASSIGN_ID,
            capsule_type: CapsuleType::AddressAssign(req_inner_cap),
        }
    }

    /// 
    /// Creates a new serialized capsule containing an ADDRESS_ASSIGN
    /// If prefix is None the requested prefix will be 32,
    /// request_id defaults to 0
    /// 
    pub fn create_sendable(addr: Ipv4Addr, prefix: Option<u8>, request_id: Option<u64>) -> Vec<u8> {
        let cap = AddressAssign::create_new(addr, prefix, request_id);
        let mut buf = vec![0; 9];
        cap.serialize(&mut buf);
        buf
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
            length,
            requested: adresses,
        })
    }

    /// 
    /// Creates a new basic Capsule containing an ADDRESS_REQUEST.
    /// If prefix is None the requested prefix will be 32
    /// 
    pub fn create_new(addr: Ipv4Addr, prefix: Option<u8>, request_id: Option<u64>) -> Capsule {
        let prefix = prefix.unwrap_or(32);
        let request_id = request_id.unwrap_or(0);

        let addr_request = RequestedAddress {
            request_id,
            ip_version: 4,
            ip_address: IpLength::V4(addr.into()),
            ip_prefix_len: prefix,
        };

        let request_capsule = AddressRequest {
            length: 9,
            requested: vec![addr_request],
        };

        Capsule {
            capsule_id: ADDRESS_REQUEST_ID,
            capsule_type: super::capsules::CapsuleType::AddressRequest(
                request_capsule,
            ),
        }
    }

    /// 
    /// Creates a new serialized capsule containing an ADDRESS_REQUEST
    /// If prefix is None the requested prefix will be 32
    /// 
    pub fn create_sendable(addr: Ipv4Addr, prefix: Option<u8>, request_id: Option<u64>) -> Vec<u8> {
        let cap = AddressRequest::create_new(addr, prefix, request_id);
        let mut buf = vec![0; 9];
        cap.serialize(&mut buf);
        buf
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

impl ClientHello {
    pub fn new(oct: &mut Octets) -> Result<ClientHello, CapsuleParseError> {
        let length = oct
            .get_varint()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let id_length = oct
            .get_u8()
            .map_err(|_| CapsuleParseError::BufferTooShort)?;
        let mut id: Vec<u8> = Vec::new();
        for _ in 0..id_length {
            id.push(
                oct.get_u8()
                   .map_err(|_| CapsuleParseError::BufferTooShort)?
            );
        }

        Ok(ClientHello { length, id_length, id})
    }

    /// 
    /// Creates a new basic capsule containing a CLIENT_HELLO
    /// Returns a `CapsuleParseError` if the id is longer than MAX_CLIENT_HELLO_ID_LEN
    /// 
    pub fn create_new(id: String) -> Result<Capsule, CapsuleParseError> {
        if id.len() > MAX_CLIENT_HELLO_ID_LEN {
            return Err(CapsuleParseError::Other(
                format!("The requested CLIENT_HELLO was too long! Max: {} | Was: {}",
                MAX_CLIENT_HELLO_ID_LEN, id.len()
            )
            ))
        }
        let hell = ClientHello {
            length: (3 + id.len() as u64),
            id_length: (id.len() as u8),
            id: id.as_bytes().to_vec(),
        };

        Ok(Capsule {
            capsule_id: CLIENT_HELLO_ID,
            capsule_type: super::capsules::CapsuleType::ClientHello(
                hell,
            ),
        })
    }

    /// 
    /// Creates a new serialized capsule containing a CLIENT_HELLO
    /// Returns a `CapsuleParseError` if the id is longer than MAX_CLIENT_HELLO_ID_LEN
    /// 
    pub fn create_sendable(id: String) -> Result<Vec<u8>, CapsuleParseError> {
        let cap = match ClientHello::create_new(id) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let mut buf = vec![0; 9];
        cap.serialize(&mut buf);
        Ok(buf)
    }

    pub fn serialize(&self, buf: &mut OctetsMut) {
        buf.put_varint(self.length).unwrap();
        buf.put_u8(self.id_length).unwrap();

        for i in &self.id {
            buf.put_u8(*i).unwrap();
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
            length,
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
