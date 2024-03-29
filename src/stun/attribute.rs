// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Attributes
//!
//! Provides for generating, parsing and manipulating STUN attributes as specified in one of
//! [RFC8489], [RFC5389], or [RFC3489].
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489

use std::convert::TryFrom;
use std::convert::TryInto;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::stun::agent::StunError;
use crate::stun::message::{TransactionId, MAGIC_COOKIE};

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

#[derive(Debug)]
pub enum StunParseError {
    Failed,
    WrongImplementation,
    NotEnoughData,
    TooBig,
    InvalidData,
    OutOfRange,
}

impl std::error::Error for StunParseError {}

impl std::fmt::Display for StunParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The type of an [`Attribute`] in a STUN [`Message`](crate::stun::message::Message)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttributeType(u16);

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:#x}: {})", self.0, self.0, self.name())
    }
}

impl AttributeType {
    /// Create a new AttributeType from an existing value
    ///
    /// Note: the value passed in is not encoded as in a stun message
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x123).value(), 0x123);
    /// ```
    pub fn new(val: u16) -> Self {
        Self(val)
    }

    /// Return the integer value of this AttributeType
    ///
    /// Note: the value returned is not encoded as in a stun message
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x123).value(), 0x123);
    /// ```
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns a human readable name of this `AttributeType` or "unknown"
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::XOR_MAPPED_ADDRESS;
    /// assert_eq!(XOR_MAPPED_ADDRESS.name(), "XOR-MAPPED-ADDRESS");
    /// ```
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

/// Structure for holding the header of a STUN attribute.  Contains the type and the length
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AttributeHeader {
    pub atype: AttributeType,
    pub length: u16,
}

impl AttributeHeader {
    fn parse(data: &[u8]) -> Result<Self, StunParseError> {
        if data.len() < 4 {
            return Err(StunParseError::NotEnoughData);
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
    type Error = StunParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        AttributeHeader::parse(value)
    }
}

/// A STUN attribute for use in [`Message`](crate::stun::message::Message)s
pub trait Attribute: std::fmt::Debug {
    /// Retrieve the `AttributeType` of an `Attribute`
    fn get_type(&self) -> AttributeType;

    /// Retrieve the length of an `Attribute`.  This is not the padded length as stored in a
    /// `Message`
    fn length(&self) -> u16;

    /// Convert an `Attribute` to a `RawAttribute`
    fn to_raw(&self) -> RawAttribute;

    /// Convert an `Attribute` from a `RawAttribute`
    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized;
}

/// The header and raw bytes of an unparsed [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    /// The [`AttributeHeader`] of this [`RawAttribute`]
    pub header: AttributeHeader,
    /// The raw bytes of this [`RawAttribute`]
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
    fn length(&self) -> u16 {
        self.header.length
    }

    fn get_type(&self) -> AttributeType {
        self.header.atype
    }

    fn to_raw(&self) -> RawAttribute {
        self.clone()
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
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
    /// assert_eq!(attr.length(), 2);
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, StunParseError> {
        let header = AttributeHeader::parse(data)?;
        // the advertised length is larger than actual data -> error
        if header.length > (data.len() - 4) as u16 {
            return Err(StunParseError::NotEnoughData);
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
    type Error = StunParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        RawAttribute::from_bytes(value)
    }
}

/// The username [`Attribute`]
#[derive(Debug, Clone)]
pub struct Username {
    user: String,
}
impl Attribute for Username {
    fn get_type(&self) -> AttributeType {
        USERNAME
    }

    fn length(&self) -> u16 {
        self.user.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), self.user.as_bytes())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != USERNAME {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 513 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            user: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

impl Username {
    /// Create a new [`Username`] [`Attribute`]
    ///
    /// # Errors
    ///
    /// - When the length of the username is longer than allowed in a STUN
    /// [`Message`](crate::stun::message::Message)
    /// - TODO: If converting through SASLPrep fails
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let username = Username::new ("user").unwrap();
    /// assert_eq!(username.username(), "user");
    /// ```
    pub fn new(user: &str) -> Result<Self, StunParseError> {
        if user.len() > 513 {
            return Err(StunParseError::TooBig);
        }
        // TODO: SASLPrep RFC4013 requirements
        Ok(Self {
            user: user.to_owned(),
        })
    }

    /// The username stored in a [`Username`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let username = Username::new ("user").unwrap();
    /// assert_eq!(username.username(), "user");
    /// ```
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
    type Error = StunParseError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        Username::from_raw(value)
    }
}

impl From<Username> for RawAttribute {
    fn from(f: Username) -> Self {
        f.to_raw()
    }
}

/// The ErrorCode [`Attribute`]
#[derive(Debug, Clone)]
pub struct ErrorCode {
    code: u16,
    reason: String,
}
impl Attribute for ErrorCode {
    fn get_type(&self) -> AttributeType {
        ERROR_CODE
    }

    fn length(&self) -> u16 {
        self.reason.len() as u16 + 4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push((self.code / 100) as u8);
        data.push((self.code % 100) as u8);
        data.extend(self.reason.as_bytes());
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ERROR_CODE {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 763 + 4 {
            return Err(StunParseError::TooBig);
        }
        let code_h = (raw.value[2] & 0x7) as u16;
        let code_tens = raw.value[3] as u16;
        if !(3..7).contains(&code_h) || code_tens > 99 {
            return Err(StunParseError::OutOfRange);
        }
        let code = code_h * 100 + code_tens;
        Ok(Self {
            code,
            reason: std::str::from_utf8(&raw.value[4..])
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

pub struct ErrorCodeBuilder<'reason> {
    code: u16,
    reason: Option<&'reason str>,
}

impl<'reason> ErrorCodeBuilder<'reason> {
    fn new(code: u16) -> Self {
        Self { code, reason: None }
    }

    /// Set the custom reason for this [`ErrorCode`]
    pub fn reason(mut self, reason: &'reason str) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Create the [`ErrorCode`] with the configured paramaters
    ///
    /// # Errors
    ///
    /// - When the code value is out of range [300, 699]
    pub fn build(self) -> Result<ErrorCode, StunParseError> {
        if !(300..700).contains(&self.code) {
            return Err(StunParseError::OutOfRange);
        }
        let reason = self
            .reason
            .unwrap_or_else(|| ErrorCode::default_reason_for_code(self.code))
            .to_owned();
        Ok(ErrorCode {
            code: self.code,
            reason,
        })
    }
}

impl ErrorCode {
    pub const TRY_ALTERNATE: u16 = 301;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const UNKNOWN_ATRIBUTE: u16 = 420;
    pub const STALE_NONCE: u16 = 438;
    pub const SERVER_ERROR: u16 = 500;
    pub const ROLE_CONFLICT: u16 = 487;

    /// Create a builder for creating a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let error = ErrorCode::builder (400).reason("bad error").build().unwrap();
    /// assert_eq!(error.code(), 400);
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn builder<'reason>(code: u16) -> ErrorCodeBuilder<'reason> {
        ErrorCodeBuilder::new(code)
    }

    /// Create a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Errors
    ///
    /// - When the code value is out of range [300, 699]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.code(), 400);
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn new(code: u16, reason: &str) -> Result<Self, StunParseError> {
        if !(300..700).contains(&code) {
            return Err(StunParseError::OutOfRange);
        }
        Ok(Self {
            code,
            reason: reason.to_owned(),
        })
    }

    /// The error code value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.code(), 400);
    /// ```
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The error code reason string
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Return some default reason strings for some error code values
    ///
    /// Currently the following are supported.
    ///
    ///  - 301 -> Try Alternate
    ///  - 400 -> Bad Request
    ///  - 401 -> Unauthorized
    ///  - 420 -> Unknown Attribute
    ///  - 438 -> Stale Nonce
    ///  - 500 -> Server Error
    ///  - 487 -> Role Conflict
    pub fn default_reason_for_code(code: u16) -> &'static str {
        match code {
            Self::TRY_ALTERNATE => "Try Alternate",
            Self::BAD_REQUEST => "Bad Request",
            Self::UNAUTHORIZED => "Unauthorized",
            Self::UNKNOWN_ATRIBUTE => "Unknown Attribute",
            Self::STALE_NONCE => "Stale Nonce",
            Self::SERVER_ERROR => "Server Error",
            // RFC 8445
            Self::ROLE_CONFLICT => "Role Conflict",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} '{}'", self.get_type(), self.code, self.reason)
    }
}

impl TryFrom<&RawAttribute> for ErrorCode {
    type Error = StunParseError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        ErrorCode::from_raw(value)
    }
}

impl From<ErrorCode> for RawAttribute {
    fn from(f: ErrorCode) -> Self {
        f.to_raw()
    }
}

/// The UnknownAttributes [`Attribute`]
#[derive(Debug, Clone)]
pub struct UnknownAttributes {
    attributes: Vec<AttributeType>,
}
impl Attribute for UnknownAttributes {
    fn get_type(&self) -> AttributeType {
        UNKNOWN_ATTRIBUTES
    }

    fn length(&self) -> u16 {
        (self.attributes.len() as u16) * 2
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.length() as usize);
        for attr in &self.attributes {
            let mut encoded = vec![0; 2];
            BigEndian::write_u16(&mut encoded, (*attr).into());
            data.extend(encoded);
        }
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != UNKNOWN_ATTRIBUTES {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() % 2 != 0 {
            /* all attributes are 16-bits */
            return Err(StunParseError::InvalidData);
        }
        let mut attrs = vec![];
        for attr in raw.value.chunks_exact(2) {
            attrs.push(BigEndian::read_u16(attr).into());
        }
        Ok(Self { attributes: attrs })
    }
}
impl UnknownAttributes {
    /// Create a new unknown attributes [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let unknown = UnknownAttributes::new(&[USERNAME]);
    /// assert!(unknown.has_attribute(USERNAME));
    /// ```
    pub fn new(attrs: &[AttributeType]) -> Self {
        Self {
            attributes: attrs.to_vec(),
        }
    }

    /// Add an [`AttributeType`] that is unsupported
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let mut unknown = UnknownAttributes::new(&[]);
    /// unknown.add_attribute(USERNAME);
    /// assert!(unknown.has_attribute(USERNAME));
    /// ```
    pub fn add_attribute(&mut self, attr: AttributeType) {
        if !self.has_attribute(attr) {
            self.attributes.push(attr);
        }
    }

    /// Check if an [`AttributeType`] is present
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let unknown = UnknownAttributes::new(&[USERNAME]);
    /// assert!(unknown.has_attribute(USERNAME));
    /// ```
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
    type Error = StunParseError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        UnknownAttributes::from_raw(value)
    }
}

impl From<UnknownAttributes> for RawAttribute {
    fn from(f: UnknownAttributes) -> Self {
        f.to_raw()
    }
}

/// The Software [`Attribute`]
#[derive(Debug, Clone)]
pub struct Software {
    software: String,
}
impl Attribute for Software {
    fn get_type(&self) -> AttributeType {
        SOFTWARE
    }

    fn length(&self) -> u16 {
        self.software.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), self.software.as_bytes())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != SOFTWARE {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 763 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            software: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

impl Software {
    /// Create a new unknown attributes [`Attribute`]
    ///
    /// # Errors
    ///
    /// If the length of the provided string is too long for the [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let software = Software::new("librice 0.1").unwrap();
    /// assert_eq!(software.software(), "librice 0.1");
    /// ```
    pub fn new(software: &str) -> Result<Self, StunParseError> {
        if software.len() > 768 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            software: software.to_owned(),
        })
    }

    /// The value of the software field
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let software = Software::new("librice 0.1").unwrap();
    /// assert_eq!(software.software(), "librice 0.1");
    /// ```
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
    type Error = StunParseError;

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

/// The XorMappedAddress [`Attribute`]
#[derive(Debug, Clone)]
pub struct XorMappedAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: SocketAddr,
}
impl Attribute for XorMappedAddress {
    fn get_type(&self) -> AttributeType {
        XOR_MAPPED_ADDRESS
    }

    fn length(&self) -> u16 {
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
                BigEndian::write_u128(&mut buf[4..20], octets);
                RawAttribute::new(self.get_type(), &buf)
            }
        }
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != XOR_MAPPED_ADDRESS {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        let port = BigEndian::read_u16(&raw.value[2..4]);
        let addr = match raw.value[1] {
            0x1 => {
                // ipv4
                if raw.value.len() < 8 {
                    return Err(StunParseError::NotEnoughData);
                }
                if raw.value.len() > 8 {
                    return Err(StunParseError::TooBig);
                }
                IpAddr::V4(Ipv4Addr::from(BigEndian::read_u32(&raw.value[4..8])))
            }
            0x2 => {
                // ipv6
                if raw.value.len() < 20 {
                    return Err(StunParseError::NotEnoughData);
                }
                if raw.value.len() > 20 {
                    return Err(StunParseError::TooBig);
                }
                let mut octets = [0; 16];
                octets.clone_from_slice(&raw.value[4..]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(StunParseError::InvalidData),
        };
        Ok(Self {
            addr: SocketAddr::new(addr, port),
        })
    }
}

impl XorMappedAddress {
    /// Create a new XorMappedAddress [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorMappedAddress::xor_addr(addr, transaction),
        }
    }

    fn xor_addr(addr: SocketAddr, transaction: TransactionId) -> SocketAddr {
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
                let transaction: u128 = transaction.into();
                let const_octets = ((MAGIC_COOKIE as u128) << 96
                    | (transaction & 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff))
                    .to_be_bytes();
                let addr_octets = addr.ip().octets();
                let octets = bytewise_xor!(16, const_octets, addr_octets, 0);
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
        }
    }

    /// Retrieve the address stored in a XorMappedAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        XorMappedAddress::xor_addr(self.addr, transaction)
    }
}

impl std::fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr {
            SocketAddr::V4(_) => write!(f, "{}: {:?}", self.get_type(), self.addr(0x0.into())),
            SocketAddr::V6(addr) => write!(f, "{}: XOR({:?})", self.get_type(), addr),
        }
    }
}

impl TryFrom<&RawAttribute> for XorMappedAddress {
    type Error = StunParseError;

    fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
        XorMappedAddress::from_raw(value)
    }
}

impl From<XorMappedAddress> for RawAttribute {
    fn from(f: XorMappedAddress) -> Self {
        f.to_raw()
    }
}

/// The Priority [`Attribute`]
#[derive(Debug)]
pub struct Priority {
    priority: u32,
}

impl Attribute for Priority {
    fn get_type(&self) -> AttributeType {
        PRIORITY
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], self.priority);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != PRIORITY {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            priority: BigEndian::read_u32(&raw.value[..4]),
        })
    }
}

impl Priority {
    /// Create a new Priority [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn new(priority: u32) -> Self {
        Self { priority }
    }

    /// Retrieve the priority value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl TryFrom<&RawAttribute> for Priority {
    type Error = StunParseError;

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

/// The UseCandidate [`Attribute`]
#[derive(Debug)]
pub struct UseCandidate {}

impl Attribute for UseCandidate {
    fn get_type(&self) -> AttributeType {
        USE_CANDIDATE
    }

    fn length(&self) -> u16 {
        0
    }

    fn to_raw(&self) -> RawAttribute {
        let buf = [0; 0];
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != USE_CANDIDATE {
            return Err(StunParseError::WrongImplementation);
        }
        if !raw.value.is_empty() {
            return Err(StunParseError::TooBig);
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
    /// Create a new UseCandidate [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let _use_candidate = UseCandidate::new();
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<&RawAttribute> for UseCandidate {
    type Error = StunParseError;

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

/// The IceControlled [`Attribute`]
#[derive(Debug)]
pub struct IceControlled {
    tie_breaker: u64,
}

impl Attribute for IceControlled {
    fn get_type(&self) -> AttributeType {
        ICE_CONTROLLED
    }

    fn length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ICE_CONTROLLED {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 8 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 8 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlled {
    /// Create a new IceControlled [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    /// Retrieve the tie breaker value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl TryFrom<&RawAttribute> for IceControlled {
    type Error = StunParseError;

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

/// The IceControlling [`Attribute`]
#[derive(Debug)]
pub struct IceControlling {
    tie_breaker: u64,
}

impl Attribute for IceControlling {
    fn get_type(&self) -> AttributeType {
        ICE_CONTROLLING
    }

    fn length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ICE_CONTROLLING {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 8 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 8 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlling {
    /// Create a new IceControlling [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    /// Create a new IceControlling [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl TryFrom<&RawAttribute> for IceControlling {
    type Error = StunParseError;

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

/// The MessageIntegrity [`Attribute`]
#[derive(Debug)]
pub struct MessageIntegrity {
    hmac: [u8; 20],
}

impl Attribute for MessageIntegrity {
    fn get_type(&self) -> AttributeType {
        MESSAGE_INTEGRITY
    }

    fn length(&self) -> u16 {
        20
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &self.hmac)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != MESSAGE_INTEGRITY {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 20 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 20 {
            return Err(StunParseError::TooBig);
        }
        // sized checked earlier
        let boxed: Box<[u8; 20]> = raw.value.clone().into_boxed_slice().try_into().unwrap();
        Ok(Self { hmac: *boxed })
    }
}

impl MessageIntegrity {
    /// Create a new MessageIntegrity [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let hmac = [0;20];
    /// let integrity = MessageIntegrity::new(hmac);
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn new(hmac: [u8; 20]) -> Self {
        Self { hmac }
    }

    /// Retrieve the value of the hmac
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let hmac = [0; 20];
    /// let integrity = MessageIntegrity::new(hmac);
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn hmac(&self) -> &[u8; 20] {
        &self.hmac
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// Note: use `MessageIntegrity::verify` for the actual verification to ensure constant time
    /// checks of the values to defeat certain types of timing attacks.
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::*;
    /// let key = [40; 10];
    /// let data = [10; 30];
    /// let expected = [209, 217, 210, 15, 124, 78, 87, 181, 211, 233, 165, 180, 44, 142, 81, 233, 138, 186, 184, 97];
    /// let integrity = MessageIntegrity::compute(&data, &key).unwrap();
    /// assert_eq!(integrity, expected);
    /// ```
    #[tracing::instrument(
        name = "MessageIntegrity::compute",
        level = "trace",
        err,
        ret,
        skip(data, key)
    )]
    pub fn compute(data: &[u8], key: &[u8]) -> Result<[u8; 20], StunError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(key)
            .map_err(|_| StunError::ParseError(StunParseError::InvalidData))?;
        hmac.update(data);
        let ret = hmac.finalize().into_bytes();
        ret.try_into()
            .map_err(|_| StunError::ParseError(StunParseError::InvalidData))
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::*;
    /// let key = [40; 10];
    /// let data = [10; 30];
    /// let expected = [209, 217, 210, 15, 124, 78, 87, 181, 211, 233, 165, 180, 44, 142, 81, 233, 138, 186, 184, 97];
    /// assert_eq!(MessageIntegrity::verify(&data, &key, &expected).unwrap(), ());
    /// ```
    #[tracing::instrument(
        name = "MessageIntegrity::verify",
        level = "debug",
        skip(data, key, expected)
    )]
    pub fn verify(data: &[u8], key: &[u8], expected: &[u8; 20]) -> Result<(), StunError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(key).map_err(|_| {
            error!("failed to create hmac from key data");
            StunError::ParseError(StunParseError::InvalidData)
        })?;
        hmac.update(data);
        hmac.verify_slice(expected).map_err(|_| {
            error!("integrity check failed");
            StunError::IntegrityCheckFailed
        })
    }
}

impl TryFrom<&RawAttribute> for MessageIntegrity {
    type Error = StunParseError;

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

/// The Fingerprint [`Attribute`]
#[derive(Debug)]
pub struct Fingerprint {
    fingerprint: [u8; 4],
}

impl Attribute for Fingerprint {
    fn get_type(&self) -> AttributeType {
        FINGERPRINT
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let buf = bytewise_xor!(4, self.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != FINGERPRINT {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        // sized checked earlier
        let boxed: Box<[u8; 4]> = raw.value.clone().into_boxed_slice().try_into().unwrap();
        let fingerprint = bytewise_xor!(4, *boxed, Fingerprint::XOR_CONSTANT, 0);
        Ok(Self { fingerprint })
    }
}

impl Fingerprint {
    const XOR_CONSTANT: [u8; 4] = [0x53, 0x54, 0x55, 0x4E];

    /// Create a new Fingerprint [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let value = [0;4];
    /// let fingerprint = Fingerprint::new(value);
    /// assert_eq!(fingerprint.fingerprint(), &value);
    /// ```
    pub fn new(fingerprint: [u8; 4]) -> Self {
        Self { fingerprint }
    }

    /// Retrieve the fingerprint value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// let value = [0;4];
    /// let fingerprint = Fingerprint::new(value);
    /// assert_eq!(fingerprint.fingerprint(), &value);
    /// ```
    pub fn fingerprint(&self) -> &[u8; 4] {
        &self.fingerprint
    }

    /// Compute the fingerprint of a specified block of data as required by STUN
    ///
    /// # Examples
    /// ```
    /// # use librice::stun::attribute::*;
    /// let value = [99;4];
    /// assert_eq!(Fingerprint::compute(&value), [216, 45, 250, 14]);
    /// ```
    pub fn compute(data: &[u8]) -> [u8; 4] {
        use crc::{Crc, CRC_32_ISO_HDLC};
        const CRC_ALGO: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        CRC_ALGO.checksum(data).to_be_bytes()
    }
}

impl TryFrom<&RawAttribute> for Fingerprint {
    type Error = StunParseError;

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
        crate::tests::test_init_log();
    }

    #[test]
    fn attribute_type() {
        init();
        let atype = ERROR_CODE;
        let anum: u16 = atype.into();
        assert_eq!(atype, anum.into());
    }

    #[test]
    fn short_attribute_header() {
        init();
        let data = [0; 1];
        // not enough data to parse the header
        let res: Result<AttributeHeader, _> = data.as_ref().try_into();
        assert!(res.is_err());
    }

    #[test]
    fn raw_attribute_construct() {
        init();
        let a = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(a.get_type(), 1.into());
        let bytes: Vec<_> = a.into();
        assert_eq!(bytes, &[0, 1, 0, 2, 80, 160, 0, 0]);
        let b = RawAttribute::try_from(bytes.as_ref()).unwrap();
        assert_eq!(b.get_type(), 1.into());
    }

    #[test]
    fn raw_attribute_encoding() {
        init();
        let orig = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(orig.get_type(), 1.into());
        let raw = orig.to_raw();
        assert_eq!(raw.get_type(), 1.into());
        assert_eq!(orig.get_type(), raw.get_type());
        assert_eq!(orig.length(), raw.length());
        assert_eq!(orig.to_bytes(), raw.to_bytes());
        let raw = RawAttribute::from_raw(&orig).unwrap();
        assert_eq!(raw.get_type(), 1.into());
        assert_eq!(orig.get_type(), raw.get_type());
        assert_eq!(orig.length(), raw.length());
        assert_eq!(orig.to_bytes(), raw.to_bytes());
        let mut data: Vec<_> = raw.into();
        let len = data.len();
        // one byte too big vs data size
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 + 1);
        assert!(matches!(
            RawAttribute::try_from(data.as_ref()),
            Err(StunParseError::NotEnoughData)
        ));
    }

    #[test]
    fn username() {
        init();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        assert_eq!(user.get_type(), USERNAME);
        assert_eq!(user.username(), s);
        assert_eq!(user.length() as usize, s.len());
        let raw: RawAttribute = user.into();
        assert_eq!(raw.get_type(), USERNAME);
        let user2 = Username::try_from(&raw).unwrap();
        assert_eq!(user2.get_type(), USERNAME);
        assert_eq!(user2.username(), s);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Username::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn error_code() {
        init();
        let codes = vec![300, 401, 699];
        for code in codes.iter().copied() {
            let reason = ErrorCode::default_reason_for_code(code);
            let err = ErrorCode::new(code, reason).unwrap();
            assert_eq!(err.get_type(), ERROR_CODE);
            assert_eq!(err.code(), code);
            assert_eq!(err.reason(), reason);
            let raw: RawAttribute = err.into();
            assert_eq!(raw.get_type(), ERROR_CODE);
            let err2 = ErrorCode::try_from(&raw).unwrap();
            assert_eq!(err2.get_type(), ERROR_CODE);
            assert_eq!(err2.code(), code);
            assert_eq!(err2.reason(), reason);
        }
        let code = codes[0];
        let reason = ErrorCode::default_reason_for_code(code);
        let err = ErrorCode::new(code, reason).unwrap();
        let raw: RawAttribute = err.into();
        // no data
        let mut data: Vec<_> = raw.clone().into();
        let len = 0;
        BigEndian::write_u16(&mut data[2..4], len as u16);
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::try_from(data[..len + 4].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn unknown_attributes() {
        init();
        let mut unknown = UnknownAttributes::new(&[REALM]);
        unknown.add_attribute(ALTERNATE_SERVER);
        // duplicates ignored
        unknown.add_attribute(ALTERNATE_SERVER);
        assert_eq!(unknown.get_type(), UNKNOWN_ATTRIBUTES);
        assert!(unknown.has_attribute(REALM));
        assert!(unknown.has_attribute(ALTERNATE_SERVER));
        assert!(!unknown.has_attribute(NONCE));
        let raw: RawAttribute = unknown.into();
        assert_eq!(raw.get_type(), UNKNOWN_ATTRIBUTES);
        let unknown2 = UnknownAttributes::try_from(&raw).unwrap();
        assert_eq!(unknown2.get_type(), UNKNOWN_ATTRIBUTES);
        assert!(unknown2.has_attribute(REALM));
        assert!(unknown2.has_attribute(ALTERNATE_SERVER));
        assert!(!unknown2.has_attribute(NONCE));
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            UnknownAttributes::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::InvalidData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            UnknownAttributes::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn software() {
        init();
        let software = Software::new("software").unwrap();
        assert_eq!(software.get_type(), SOFTWARE);
        assert_eq!(software.software(), "software");
        let raw: RawAttribute = software.into();
        assert_eq!(raw.get_type(), SOFTWARE);
        let software2 = Software::try_from(&raw).unwrap();
        assert_eq!(software2.get_type(), SOFTWARE);
        assert_eq!(software2.software(), "software");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Software::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn xor_mapped_address() {
        init();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorMappedAddress::new(*addr, transaction_id);
            assert_eq!(mapped.get_type(), XOR_MAPPED_ADDRESS);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.into();
            assert_eq!(raw.get_type(), XOR_MAPPED_ADDRESS);
            let mapped2 = XorMappedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XOR_MAPPED_ADDRESS);
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorMappedAddress::try_from(
                    &RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::NotEnoughData)
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorMappedAddress::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
                Err(StunParseError::WrongImplementation)
            ));
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
        assert_eq!(raw.get_type(), PRIORITY);
        let mapped2 = Priority::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), PRIORITY);
        assert_eq!(mapped2.priority(), val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Priority::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Priority::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn use_candidate() {
        init();
        let use_candidate = UseCandidate::new();
        assert_eq!(use_candidate.get_type(), USE_CANDIDATE);
        assert_eq!(use_candidate.length(), 0);
        let raw: RawAttribute = use_candidate.into();
        assert_eq!(raw.get_type(), USE_CANDIDATE);
        let mapped2 = UseCandidate::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), USE_CANDIDATE);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            UseCandidate::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn ice_controlling() {
        init();
        let tb = 100;
        let attr = IceControlling::new(tb);
        assert_eq!(attr.get_type(), ICE_CONTROLLING);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), ICE_CONTROLLING);
        let mapped2 = IceControlling::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), ICE_CONTROLLING);
        assert_eq!(mapped2.tie_breaker(), tb);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn ice_controlled() {
        init();
        let tb = 100;
        let attr = IceControlled::new(tb);
        assert_eq!(attr.get_type(), ICE_CONTROLLED);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), ICE_CONTROLLED);
        let mapped2 = IceControlled::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), ICE_CONTROLLED);
        assert_eq!(mapped2.tie_breaker(), tb);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn fingerprint() {
        init();
        let val = [1; 4];
        let attr = Fingerprint::new(val);
        assert_eq!(attr.get_type(), FINGERPRINT);
        assert_eq!(attr.fingerprint(), &val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), FINGERPRINT);
        let mapped2 = Fingerprint::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), FINGERPRINT);
        assert_eq!(mapped2.fingerprint(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn message_integrity() {
        init();
        let val = [1; 20];
        let attr = MessageIntegrity::new(val);
        assert_eq!(attr.get_type(), MESSAGE_INTEGRITY);
        assert_eq!(attr.hmac(), &val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), MESSAGE_INTEGRITY);
        let mapped2 = MessageIntegrity::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), MESSAGE_INTEGRITY);
        assert_eq!(mapped2.hmac(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            MessageIntegrity::try_from(&RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            MessageIntegrity::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }
}
