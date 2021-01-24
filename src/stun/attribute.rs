// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;
use std::convert::TryInto;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::agent::AgentError;
use crate::stun::message::MAGIC_COOKIE;

use byteorder::{BigEndian, ByteOrder};

// 0x0000 is reserved
pub const MAPPED_ADDRESS: AttributeType = AttributeType(0x0001);
// 0x0002 is reserved, was RESPONSE-ADDRESS
// 0x0003 is reserved, was CHANGE-ADDRESS
// 0x0004 is reserved, was SOURCE-ADDRESS
// 0x0005 is reserved, was CHANGED-ADDRESS
pub const USERNAME: AttributeType = AttributeType(0x0006);
// 0x0007 is reserved, was PASSWORD
pub const MESSAGE_INTEGRITY: AttributeType = AttributeType(0x0008);
pub const ERROR_CODE: AttributeType = AttributeType(0x0009);
pub const UNKNOWN_ATTRIBUTES: AttributeType = AttributeType(0x000A);
// 0x000B is reserved, was REFLECTED_FROM
pub const REALM: AttributeType = AttributeType(0x0014);
pub const NONCE: AttributeType = AttributeType(0x0015);
pub const XOR_MAPPED_ADDRESS: AttributeType = AttributeType(0x0020);

pub const SOFTWARE: AttributeType = AttributeType(0x8022);
pub const ALTERNATE_SERVER: AttributeType = AttributeType(0x8023);
pub const FINGERPRINT: AttributeType = AttributeType(0x8028);

// RFC 8445
pub const PRIORITY: AttributeType = AttributeType(0x0024);
pub const USE_CANDIDATE: AttributeType = AttributeType(0x0025);

pub const ICE_CONTROLLED: AttributeType = AttributeType(0x0029);
pub const ICE_CONTROLLING: AttributeType = AttributeType(0x002A);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttributeType(u16);

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:#x}: {})", self.0, self.0, self.name())
    }
}

impl AttributeType {
    pub fn new(val: u16) -> Self {
        Self(val)
    }

    pub fn name(self) -> &'static str {
        match self {
            MAPPED_ADDRESS => "MAPPED-ADDRESS",
            USERNAME => "USERNAME",
            MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY",
            ERROR_CODE => "ERROR-CODE",
            UNKNOWN_ATTRIBUTES => "UNKNOWN-ATTRIBUTES",
            REALM => "REALM",
            NONCE => "NONCE",
            XOR_MAPPED_ADDRESS => "XOR-MAPPED-ADDRESS",
            SOFTWARE => "SOFTWARE",
            ALTERNATE_SERVER => "ALTERNATE-SERVER",
            FINGERPRINT => "FINGERPRINT",
            PRIORITY => "PRIORITY",
            USE_CANDIDATE => "USE-CANDIDATE",
            ICE_CONTROLLED => "ICE-CONTROLLED",
            ICE_CONTROLLING => "ICE-CONTROLLING",
            _ => "unknown",
        }
    }

    /// Check if comprehension is required for an `AttributeType`.  All integer attribute
    /// values < 0x800 require comprehension.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x0).comprehension_required(), true);
    /// assert_eq!(AttributeType::new(0x8000).comprehension_required(), false);
    /// ```
    pub fn comprehension_required(self) -> bool {
        self.0 < 0x8000
    }
}
impl From<u16> for AttributeType {
    fn from(f: u16) -> Self {
        Self::new(f)
    }
}
impl From<AttributeType> for u16 {
    fn from(f: AttributeType) -> Self {
        f.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AttributeHeader {
    pub atype: AttributeType,
    pub length: u16,
}

impl AttributeHeader {
    fn parse(data: &[u8]) -> Result<Self, AgentError> {
        if data.len() < 4 {
            return Err(AgentError::NotEnoughData);
        }
        let ret = Self {
            atype: BigEndian::read_u16(&data[0..2]).into(),
            length: BigEndian::read_u16(&data[2..4]),
        };
        //trace!("parsed {:?} into {:?}", data, ret);
        Ok(ret)
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 4];
        BigEndian::write_u16(&mut ret[0..2], self.atype.into());
        BigEndian::write_u16(&mut ret[2..4], self.length);
        ret
    }
}
impl From<AttributeHeader> for Vec<u8> {
    fn from(f: AttributeHeader) -> Self {
        f.to_bytes()
    }
}
impl TryFrom<&[u8]> for AttributeHeader {
    type Error = AgentError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        AttributeHeader::parse(value)
    }
}

pub trait Attribute: std::fmt::Debug + std::any::Any {
    /// Retrieve the `AttributeType` of an `Attribute`
    fn get_type(&self) -> AttributeType;

    /// Retrieve the length of an `Attribute`.  This is not the padded length as stored in a
    /// `Message`
    fn get_length(&self) -> u16;

    /// Helper to cast to an std::any::Any
    fn as_any(&self) -> &dyn std::any::Any
    where
        Self: Sized,
    {
        self
    }

    /// Convert an `Attribute` to a `RawAttribute`
    fn to_raw(&self) -> RawAttribute;

    /// Convert an `Attribute` from a `RawAttribute`
    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError>
    where
        Self: Sized;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub header: AttributeHeader,
    pub value: Vec<u8>,
}

macro_rules! display_attr {
    ($this:ident, $CamelType:ty, $default:ident) => {{
        if let Ok(attr) = <$CamelType>::from_raw($this) {
            format!("{}", attr)
        } else {
            $default
        }
    }};
}

impl std::fmt::Display for RawAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // try to get a more specialised display
        let malformed_str = format!(
            "{}(Malformed): len: {}, data: {:?})",
            self.get_type(),
            self.header.length,
            self.value
        );
        let display_str = if self.get_type() == SOFTWARE {
            display_attr!(self, Software, malformed_str)
        } else if self.get_type() == UNKNOWN_ATTRIBUTES {
            display_attr!(self, UnknownAttributes, malformed_str)
        } else if self.get_type() == ERROR_CODE {
            display_attr!(self, ErrorCode, malformed_str)
        } else if self.get_type() == USERNAME {
            display_attr!(self, Username, malformed_str)
        } else if self.get_type() == XOR_MAPPED_ADDRESS {
            display_attr!(self, XorMappedAddress, malformed_str)
        } else if self.get_type() == PRIORITY {
            display_attr!(self, Priority, malformed_str)
        } else if self.get_type() == USE_CANDIDATE {
            display_attr!(self, UseCandidate, malformed_str)
        } else if self.get_type() == ICE_CONTROLLED {
            display_attr!(self, IceControlled, malformed_str)
        } else if self.get_type() == ICE_CONTROLLING {
            display_attr!(self, IceControlling, malformed_str)
        } else if self.get_type() == MESSAGE_INTEGRITY {
            display_attr!(self, MessageIntegrity, malformed_str)
        } else if self.get_type() == FINGERPRINT {
            display_attr!(self, Fingerprint, malformed_str)
        } else {
            format!(
                "RawAttribute (type: {:?}, len: {}, data: {:?})",
                self.header.atype, self.header.length, &self.value
            )
        };
        write!(f, "{}", display_str)
    }
}

impl Attribute for RawAttribute {
    fn get_length(&self) -> u16 {
        self.header.length
    }

    fn get_type(&self) -> AttributeType {
        self.header.atype
    }

    fn to_raw(&self) -> RawAttribute {
        self.clone()
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        Ok(raw.clone())
    }
}

impl RawAttribute {
    pub fn new(atype: AttributeType, data: &[u8]) -> Self {
        Self {
            header: AttributeHeader {
                atype,
                length: data.len() as u16,
            },
            value: data.to_vec(),
        }
    }

    /// Deserialize a `RawAttribute` from bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::{RawAttribute, Attribute, AttributeType};
    /// let data = &[0, 1, 0, 2, 5, 6, 0, 0];
    /// let attr = RawAttribute::from_bytes(data).unwrap();
    /// assert_eq!(attr.get_type(), AttributeType::new(1));
    /// assert_eq!(attr.get_length(), 2);
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, AgentError> {
        let header = AttributeHeader::parse(data)?;
        // the advertised length is larger than actual data -> error
        if header.length > (data.len() - 4) as u16 {
            return Err(AgentError::InvalidSize);
        }
        let mut data = data[4..].to_vec();
        data.truncate(header.length as usize);
        //trace!("parsed into {:?} {:?}", header, data);
        Ok(Self {
            header,
            value: data,
        })
    }

    /// Serialize a `RawAttribute` to bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::{RawAttribute, Attribute, AttributeType};
    /// let attr = RawAttribute::new(AttributeType::new(1), &[5, 6]);
    /// assert_eq!(attr.to_bytes(), &[0, 1, 0, 2, 5, 6, 0, 0]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = self.header.into();
        ret.extend(&self.value);
        let len = ret.len();
        if len % 4 != 0 {
            // pad to 4 bytes
            ret.resize(len + 4 - (len % 4), 0);
        }
        ret
    }
}
impl From<RawAttribute> for Vec<u8> {
    fn from(f: RawAttribute) -> Self {
        f.to_bytes()
    }
}

impl TryFrom<&[u8]> for RawAttribute {
    type Error = AgentError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        RawAttribute::from_bytes(value)
    }
}

#[derive(Debug, Clone)]
pub struct Username {
    user: String,
}
impl Attribute for Username {
    fn get_type(&self) -> AttributeType {
        USERNAME
    }

    fn get_length(&self) -> u16 {
        self.user.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), self.user.as_bytes())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != USERNAME {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 513 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            user: std::str::from_utf8(&raw.value)
                .map_err(|_| AgentError::Malformed)?
                .to_owned(),
        })
    }
}

impl Username {
    pub fn new(user: &str) -> Result<Self, AgentError> {
        if user.len() > 513 {
            return Err(AgentError::InvalidSize);
        }
        // TODO: SASLPrep RFC4013 requirements
        Ok(Self {
            user: user.to_owned(),
        })
    }

    pub fn username(&self) -> &str {
        &self.user
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.user)
    }
}
impl TryFrom<&RawAttribute> for Username {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        Username::from_raw(value)
    }
}

impl From<Username> for RawAttribute {
    fn from(f: Username) -> Self {
        f.to_raw()
    }
}

#[derive(Debug, Clone)]
pub struct ErrorCode {
    code: u16,
    reason: String,
}
impl Attribute for ErrorCode {
    fn get_type(&self) -> AttributeType {
        ERROR_CODE
    }

    fn get_length(&self) -> u16 {
        self.reason.len() as u16 + 4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.get_length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push((self.code / 100) as u8);
        data.push((self.code % 100) as u8);
        data.extend(self.reason.as_bytes());
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != ERROR_CODE {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 763 + 4 {
            return Err(AgentError::TooBig);
        }
        let code_h = (raw.value[2] & 0x7) as u16;
        let code_tens = raw.value[3] as u16;
        if !(3..7).contains(&code_h) || code_tens > 99 {
            return Err(AgentError::Malformed);
        }
        let code = code_h * 100 + code_tens;
        Ok(Self {
            code,
            reason: std::str::from_utf8(&raw.value[4..])
                .map_err(|_| AgentError::Malformed)?
                .to_owned(),
        })
    }
}
impl ErrorCode {
    pub fn new(code: u16, reason: &str) -> Result<Self, AgentError> {
        if !(300..700).contains(&code) {
            return Err(AgentError::Malformed);
        }
        Ok(Self {
            code,
            reason: reason.to_owned(),
        })
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn default_reason_for_code(code: u16) -> &'static str {
        match code {
            301 => "Try Alternate",
            400 => "Bad Request",
            401 => "Unauthorized",
            420 => "Unknown Attribute",
            438 => "Stale Nonce",
            500 => "Server Error",
            // RFC 8445
            ROLE_CONFLICT => "Role Conflict",
            _ => "Unknown",
        }
    }
}

pub const ROLE_CONFLICT: u16 = 487;

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} '{}'", self.get_type(), self.code, self.reason)
    }
}

impl TryFrom<&RawAttribute> for ErrorCode {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        ErrorCode::from_raw(value)
    }
}

impl From<ErrorCode> for RawAttribute {
    fn from(f: ErrorCode) -> Self {
        f.to_raw()
    }
}

#[derive(Debug, Clone)]
pub struct UnknownAttributes {
    attributes: Vec<AttributeType>,
}
impl Attribute for UnknownAttributes {
    fn get_type(&self) -> AttributeType {
        UNKNOWN_ATTRIBUTES
    }

    fn get_length(&self) -> u16 {
        (self.attributes.len() as u16) * 2
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.get_length() as usize);
        for attr in &self.attributes {
            let mut encoded = vec![0; 2];
            BigEndian::write_u16(&mut encoded, (*attr).into());
            data.extend(encoded);
        }
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != UNKNOWN_ATTRIBUTES {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() % 2 != 0 {
            /* all attributes are 16-bits */
            return Err(AgentError::Malformed);
        }
        let mut attrs = vec![];
        for attr in raw.value.chunks_exact(2) {
            attrs.push(BigEndian::read_u16(attr).into());
        }
        Ok(Self { attributes: attrs })
    }
}
impl UnknownAttributes {
    pub fn new(attrs: &[AttributeType]) -> Self {
        Self {
            attributes: attrs.to_vec(),
        }
    }

    pub fn add_attribute(&mut self, attr: AttributeType) {
        if !self.has_attribute(attr) {
            self.attributes.push(attr);
        }
    }

    pub fn has_attribute(&self, attr: AttributeType) -> bool {
        self.attributes.iter().any(|&a| a == attr)
    }
}

impl std::fmt::Display for UnknownAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.get_type(), self.attributes)
    }
}

impl TryFrom<&RawAttribute> for UnknownAttributes {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        UnknownAttributes::from_raw(value)
    }
}

impl From<UnknownAttributes> for RawAttribute {
    fn from(f: UnknownAttributes) -> Self {
        f.to_raw()
    }
}

#[derive(Debug, Clone)]
pub struct Software {
    software: String,
}
impl Attribute for Software {
    fn get_type(&self) -> AttributeType {
        SOFTWARE
    }

    fn get_length(&self) -> u16 {
        self.software.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), self.software.as_bytes())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != SOFTWARE {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 763 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            software: std::str::from_utf8(&raw.value)
                .map_err(|_| AgentError::Malformed)?
                .to_owned(),
        })
    }
}

impl Software {
    pub fn new(software: &str) -> Result<Self, AgentError> {
        if software.len() > 768 {
            return Err(AgentError::InvalidSize);
        }
        Ok(Self {
            software: software.to_owned(),
        })
    }

    pub fn software(&self) -> &str {
        &self.software
    }
}

impl std::fmt::Display for Software {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.software)
    }
}

impl TryFrom<&RawAttribute> for Software {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        Software::from_raw(value)
    }
}

impl From<Software> for RawAttribute {
    fn from(f: Software) -> Self {
        f.to_raw()
    }
}

macro_rules! bytewise_xor {
    ($size:literal, $a:expr, $b:expr, $default:literal) => {{
        let mut arr = [$default; $size];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = $a[i] ^ $b[i];
        }
        arr
    }};
}

#[derive(Debug, Clone)]
pub struct XorMappedAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: SocketAddr,
}
impl Attribute for XorMappedAddress {
    fn get_type(&self) -> AttributeType {
        XOR_MAPPED_ADDRESS
    }

    fn get_length(&self) -> u16 {
        match self.addr {
            SocketAddr::V4(_) => 8,
            SocketAddr::V6(_) => 20,
        }
    }

    fn to_raw(&self) -> RawAttribute {
        match self.addr {
            SocketAddr::V4(addr) => {
                let mut buf = [0; 8];
                buf[1] = 0x1;
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u32::from(*addr.ip());
                BigEndian::write_u32(&mut buf[4..8], octets);
                RawAttribute::new(self.get_type(), &buf)
            }
            SocketAddr::V6(addr) => {
                let mut buf = [0; 20];
                buf[1] = 0x2;
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u128::from(*addr.ip());
                BigEndian::write_u128(&mut buf[2..4], octets);
                RawAttribute::new(self.get_type(), &buf)
            }
        }
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != XOR_MAPPED_ADDRESS {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(AgentError::NotEnoughData);
        }
        let port = BigEndian::read_u16(&raw.value[2..4]);
        let addr = match raw.value[1] {
            0x1 => {
                // ipv4
                if raw.value.len() < 8 {
                    return Err(AgentError::NotEnoughData);
                }
                if raw.value.len() > 8 {
                    return Err(AgentError::TooBig);
                }
                IpAddr::V4(Ipv4Addr::from(BigEndian::read_u32(&raw.value[4..8])))
            }
            0x2 => {
                // ipv6
                if raw.value.len() < 20 {
                    return Err(AgentError::NotEnoughData);
                }
                if raw.value.len() > 20 {
                    return Err(AgentError::TooBig);
                }
                let mut octets = [0; 16];
                octets.clone_from_slice(&raw.value[4..]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(AgentError::Malformed),
        };
        Ok(Self {
            addr: SocketAddr::new(addr, port),
        })
    }
}

impl XorMappedAddress {
    pub fn new(addr: SocketAddr, transaction: u128) -> Result<Self, AgentError> {
        Ok(Self {
            addr: XorMappedAddress::xor_addr(addr, transaction),
        })
    }

    fn xor_addr(addr: SocketAddr, transaction: u128) -> SocketAddr {
        match addr {
            SocketAddr::V4(addr) => {
                let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
                let const_octets = MAGIC_COOKIE.to_be_bytes();
                let addr_octets = addr.ip().octets();
                let octets = bytewise_xor!(4, const_octets, addr_octets, 0);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
            }
            SocketAddr::V6(addr) => {
                let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
                let const_octets = ((MAGIC_COOKIE as u128) << 96
                    | (transaction & 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff))
                    .to_be_bytes();
                let addr_octets = addr.ip().octets();
                let octets = bytewise_xor!(16, const_octets, addr_octets, 0);
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
        }
    }

    pub fn addr(&self, transaction: u128) -> SocketAddr {
        XorMappedAddress::xor_addr(self.addr, transaction)
    }
}

impl std::fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr {
            SocketAddr::V4(_) => write!(f, "{}: {:?}", self.get_type(), self.addr(0x0)),
            SocketAddr::V6(addr) => write!(f, "{}: XOR({:?})", self.get_type(), addr),
        }
    }
}

impl TryFrom<&RawAttribute> for XorMappedAddress {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        XorMappedAddress::from_raw(value)
    }
}

impl From<XorMappedAddress> for RawAttribute {
    fn from(f: XorMappedAddress) -> Self {
        f.to_raw()
    }
}

#[derive(Debug)]
pub struct Priority {
    priority: u32,
}

impl Attribute for Priority {
    fn get_type(&self) -> AttributeType {
        PRIORITY
    }

    fn get_length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], self.priority);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != PRIORITY {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(AgentError::NotEnoughData);
        }
        if raw.value.len() > 4 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            priority: BigEndian::read_u32(&raw.value[..4]),
        })
    }
}

impl Priority {
    pub fn new(priority: u32) -> Self {
        Self { priority }
    }

    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl TryFrom<&RawAttribute> for Priority {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        Priority::from_raw(value)
    }
}

impl From<Priority> for RawAttribute {
    fn from(f: Priority) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.priority)
    }
}

#[derive(Debug)]
pub struct UseCandidate {}

impl Attribute for UseCandidate {
    fn get_type(&self) -> AttributeType {
        USE_CANDIDATE
    }

    fn get_length(&self) -> u16 {
        0
    }

    fn to_raw(&self) -> RawAttribute {
        let buf = [0; 0];
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != USE_CANDIDATE {
            return Err(AgentError::WrongImplementation);
        }
        if !raw.value.is_empty() {
            return Err(AgentError::TooBig);
        }
        Ok(Self {})
    }
}

impl Default for UseCandidate {
    fn default() -> Self {
        UseCandidate::new()
    }
}

impl UseCandidate {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<&RawAttribute> for UseCandidate {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        UseCandidate::from_raw(value)
    }
}

impl From<UseCandidate> for RawAttribute {
    fn from(f: UseCandidate) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for UseCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

#[derive(Debug)]
pub struct IceControlled {
    tie_breaker: u64,
}

impl Attribute for IceControlled {
    fn get_type(&self) -> AttributeType {
        ICE_CONTROLLED
    }

    fn get_length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != ICE_CONTROLLED {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 8 {
            return Err(AgentError::NotEnoughData);
        }
        if raw.value.len() > 8 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlled {
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl TryFrom<&RawAttribute> for IceControlled {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        IceControlled::from_raw(value)
    }
}

impl From<IceControlled> for RawAttribute {
    fn from(f: IceControlled) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for IceControlled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

#[derive(Debug)]
pub struct IceControlling {
    tie_breaker: u64,
}

impl Attribute for IceControlling {
    fn get_type(&self) -> AttributeType {
        ICE_CONTROLLING
    }

    fn get_length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != ICE_CONTROLLING {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 8 {
            return Err(AgentError::NotEnoughData);
        }
        if raw.value.len() > 8 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlling {
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl TryFrom<&RawAttribute> for IceControlling {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        IceControlling::from_raw(value)
    }
}

impl From<IceControlling> for RawAttribute {
    fn from(f: IceControlling) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for IceControlling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

#[derive(Debug)]
pub struct MessageIntegrity {
    hmac: [u8; 20],
}

impl Attribute for MessageIntegrity {
    fn get_type(&self) -> AttributeType {
        MESSAGE_INTEGRITY
    }

    fn get_length(&self) -> u16 {
        20
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &self.hmac)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != MESSAGE_INTEGRITY {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 20 {
            return Err(AgentError::NotEnoughData);
        }
        if raw.value.len() > 20 {
            return Err(AgentError::TooBig);
        }
        // sized checked earlier
        let boxed: Box<[u8; 20]> = raw.value.clone().into_boxed_slice().try_into().unwrap();
        Ok(Self { hmac: *boxed })
    }
}

impl MessageIntegrity {
    pub fn new(hmac: [u8; 20]) -> Self {
        Self { hmac }
    }

    pub fn hmac(&self) -> &[u8; 20] {
        &self.hmac
    }
}

impl TryFrom<&RawAttribute> for MessageIntegrity {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        MessageIntegrity::from_raw(value)
    }
}
impl From<MessageIntegrity> for RawAttribute {
    fn from(f: MessageIntegrity) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for MessageIntegrity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", self.get_type())?;
        for val in self.hmac.iter() {
            write!(f, "{:02x}", val)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Fingerprint {
    fingerprint: [u8; 4],
}

impl Attribute for Fingerprint {
    fn get_type(&self) -> AttributeType {
        FINGERPRINT
    }

    fn get_length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let buf = bytewise_xor!(4, self.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, AgentError> {
        if raw.header.atype != FINGERPRINT {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(AgentError::NotEnoughData);
        }
        if raw.value.len() > 4 {
            return Err(AgentError::TooBig);
        }
        // sized checked earlier
        let boxed: Box<[u8; 4]> = raw.value.clone().into_boxed_slice().try_into().unwrap();
        let fingerprint = bytewise_xor!(4, *boxed, Fingerprint::XOR_CONSTANT, 0);
        Ok(Self { fingerprint })
    }
}

impl Fingerprint {
    pub const XOR_CONSTANT: [u8; 4] = [0x53, 0x54, 0x55, 0x4E];

    pub fn new(fingerprint: [u8; 4]) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint(&self) -> &[u8; 4] {
        &self.fingerprint
    }
}

impl TryFrom<&RawAttribute> for Fingerprint {
    type Error = AgentError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        Fingerprint::from_raw(value)
    }
}

impl From<Fingerprint> for RawAttribute {
    fn from(f: Fingerprint) -> Self {
        f.to_raw()
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", self.get_type())?;
        for val in self.fingerprint.iter() {
            write!(f, "{:02x}", val)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn raw_attribute_construct() {
        init();
        let a = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(a.get_type(), 1.into());
        let bytes = a.to_bytes();
        assert_eq!(bytes, &[0, 1, 0, 2, 80, 160, 0, 0]);
        let b = RawAttribute::from_bytes(&bytes).unwrap();
        assert_eq!(b.get_type(), 1.into());
    }

    #[test]
    fn raw_attribute_encoding() {
        init();
        let orig = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(orig.get_type(), 1.into());
        let raw = orig.to_raw();
        assert_eq!(orig.get_type(), raw.get_type());
        assert_eq!(orig.get_length(), raw.get_length());
        assert_eq!(orig.to_bytes(), raw.to_bytes());
    }

    #[test]
    fn username() {
        init();
        let s = "woohoo!";
        let user = Username::new(&s).unwrap();
        assert_eq!(user.get_type(), USERNAME);
        assert_eq!(user.username(), s);
        let raw: RawAttribute = user.into();
        let user2 = Username::try_from(&raw).unwrap();
        assert_eq!(user2.get_type(), USERNAME);
        assert_eq!(user2.username(), s);
    }

    #[test]
    fn error_code() {
        init();
        let codes = vec![300, 401, 699];
        for code in codes.into_iter() {
            let reason = ErrorCode::default_reason_for_code(code);
            let err = ErrorCode::new(code, &reason).unwrap();
            assert_eq!(err.get_type(), ERROR_CODE);
            assert_eq!(err.code(), code);
            assert_eq!(err.reason(), reason);
            let raw: RawAttribute = err.into();
            let err2 = ErrorCode::try_from(&raw).unwrap();
            assert_eq!(err2.get_type(), ERROR_CODE);
            assert_eq!(err2.code(), code);
            assert_eq!(err2.reason(), reason);
        }
    }

    #[test]
    fn unknown_attributes() {
        init();
        let mut unknown = UnknownAttributes::new(&[REALM]);
        unknown.add_attribute(ALTERNATE_SERVER);
        // duplicates ignored
        unknown.add_attribute(ALTERNATE_SERVER);
        assert_eq!(unknown.get_type(), UNKNOWN_ATTRIBUTES);
        assert_eq!(unknown.has_attribute(REALM), true);
        assert_eq!(unknown.has_attribute(ALTERNATE_SERVER), true);
        assert_eq!(unknown.has_attribute(NONCE), false);
        let raw: RawAttribute = unknown.into();
        let unknown2 = UnknownAttributes::try_from(&raw).unwrap();
        assert_eq!(unknown2.get_type(), UNKNOWN_ATTRIBUTES);
        assert_eq!(unknown2.has_attribute(REALM), true);
        assert_eq!(unknown2.has_attribute(ALTERNATE_SERVER), true);
        assert_eq!(unknown2.has_attribute(NONCE), false);
    }

    #[test]
    fn software() {
        init();
        let software = Software::new("software").unwrap();
        assert_eq!(software.get_type(), SOFTWARE);
        assert_eq!(software.software(), "software");
        let raw: RawAttribute = software.into();
        let software2 = Software::try_from(&raw).unwrap();
        assert_eq!(software2.get_type(), SOFTWARE);
        assert_eq!(software2.software(), "software");
    }

    #[test]
    fn xor_mapped_address() {
        init();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876;
        let addrs = &["192.168.0.1:40000".parse().unwrap()];
        for addr in addrs {
            let mapped = XorMappedAddress::new(*addr, transaction_id).unwrap();
            assert_eq!(mapped.get_type(), XOR_MAPPED_ADDRESS);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.into();
            let mapped2 = XorMappedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XOR_MAPPED_ADDRESS);
            assert_eq!(mapped2.addr(transaction_id), *addr);
        }
    }

    #[test]
    fn priority() {
        init();
        let val = 100;
        let priority = Priority::new(val);
        assert_eq!(priority.get_type(), PRIORITY);
        assert_eq!(priority.priority(), val);
        let raw: RawAttribute = priority.into();
        let mapped2 = Priority::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), PRIORITY);
        assert_eq!(mapped2.priority(), val);
    }

    #[test]
    fn use_candidate() {
        init();
        let use_candidate = UseCandidate::new();
        assert_eq!(use_candidate.get_type(), USE_CANDIDATE);
        let raw: RawAttribute = use_candidate.into();
        let mapped2 = UseCandidate::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), USE_CANDIDATE);
    }

    #[test]
    fn ice_controlling() {
        init();
        let tb = 100;
        let attr = IceControlling::new(tb);
        assert_eq!(attr.get_type(), ICE_CONTROLLING);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        let mapped2 = IceControlling::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), ICE_CONTROLLING);
        assert_eq!(mapped2.tie_breaker(), tb);
    }

    #[test]
    fn ice_controlled() {
        init();
        let tb = 100;
        let attr = IceControlled::new(tb);
        assert_eq!(attr.get_type(), ICE_CONTROLLED);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        let mapped2 = IceControlled::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), ICE_CONTROLLED);
        assert_eq!(mapped2.tie_breaker(), tb);
    }

    #[test]
    fn fingerprint() {
        init();
        let val = [1; 4];
        let attr = Fingerprint::new(val);
        assert_eq!(attr.get_type(), FINGERPRINT);
        assert_eq!(attr.fingerprint(), &val);
        let raw: RawAttribute = attr.into();
        let mapped2 = Fingerprint::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), FINGERPRINT);
        assert_eq!(mapped2.fingerprint(), &val);
    }

    #[test]
    fn message_integrity() {
        init();
        let val = [1; 20];
        let attr = MessageIntegrity::new(val);
        assert_eq!(attr.get_type(), MESSAGE_INTEGRITY);
        assert_eq!(attr.hmac(), &val);
        let raw: RawAttribute = attr.into();
        let mapped2 = MessageIntegrity::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), MESSAGE_INTEGRITY);
        assert_eq!(mapped2.hmac(), &val);
    }
}
