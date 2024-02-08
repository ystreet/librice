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
pub const MESSAGE_INTEGRITY_SHA256: AttributeType = AttributeType(0x001C);
pub const PASSWORD_ALGORITHM: AttributeType = AttributeType(0x001D);
pub const USERHASH: AttributeType = AttributeType(0x001E);
pub const XOR_MAPPED_ADDRESS: AttributeType = AttributeType(0x0020);

pub const PASSWORD_ALGORITHMS: AttributeType = AttributeType(0x8002);
pub const ALTERNATE_DOMAIN: AttributeType = AttributeType(0x8003);
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
pub struct AttributeType(pub u16);

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
    /// # use librice_proto::stun::attribute::AttributeType;
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
    /// # use librice_proto::stun::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x123).value(), 0x123);
    /// ```
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns a human readable name of this `AttributeType` or "unknown"
    ///
    /// # Examples
    /// ```
    /// # use librice_proto::stun::attribute::XOR_MAPPED_ADDRESS;
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
            MESSAGE_INTEGRITY_SHA256 => "MESSAGE-INTEGRITY-SHA256",
            PASSWORD_ALGORITHM => "PASSWORD-ALGORITHM",
            USERHASH => "USERHASH",
            XOR_MAPPED_ADDRESS => "XOR-MAPPED-ADDRESS",
            PASSWORD_ALGORITHMS => "PASSWORD_ALGORITHMS",
            ALTERNATE_DOMAIN => "ALTERNATE-DOMAIN",
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
    /// # use librice_proto::stun::attribute::AttributeType;
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
}

pub trait AttributeToRaw: Attribute + Into<RawAttribute>
where RawAttribute: for<'a> From<&'a Self> {
    /// Convert an `Attribute` to a `RawAttribute`
    fn to_raw(&self) -> RawAttribute;
//    where RawAttribute: for<'a> From<&'a Self>;
}
impl<T: Attribute + Into<RawAttribute>> AttributeToRaw
for T
    where RawAttribute: for<'a> From<&'a Self> {
    fn to_raw(&self) -> RawAttribute
    where RawAttribute: for<'a> From<&'a Self>
    {
        self.into()
    }
}
pub trait AttributeFromRaw<E>: Attribute + for<'a> TryFrom<&'a RawAttribute, Error = E> {
    /// Convert an `Attribute` from a `RawAttribute`
    fn from_raw(raw: &RawAttribute) -> Result<Self, E>
    where
        Self: Sized;
}

impl<E, T: Attribute + for<'a> TryFrom<&'a RawAttribute, Error = E>> AttributeFromRaw<E> for T {
    fn from_raw(raw: &RawAttribute) -> Result<T, E> {
        Self::try_from(raw)
    }
}

fn padded_attr_len(len: usize) -> usize {
    if len % 4 == 0 {
        len
    } else {
        len + 4 - len % 4
    }
}

pub(crate) fn padded_attr_size(attr: &RawAttribute) -> usize {
    4 + padded_attr_len(attr.length() as usize)
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

#[macro_export]
macro_rules! attr_from {
    ($CamelType:ty) => {
        impl std::convert::TryFrom<&RawAttribute> for $CamelType {
            type Error = StunParseError;

            fn try_from(value: &RawAttribute) -> Result<Self, Self::Error> {
                <$CamelType>::from_raw(value)
            }
        }

        impl std::convert::From<$CamelType> for RawAttribute {
            fn from(f: $CamelType) -> Self {
                f.to_raw()
            }
        }
    };
}
pub use attr_from;

impl std::fmt::Display for RawAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // try to get a more specialised display
        let malformed_str = format!(
            "{}(Malformed): len: {}, data: {:?})",
            self.get_type(),
            self.header.length,
            self.value
        );
        let display_str = match self.get_type() {
            USERNAME => display_attr!(self, Username, malformed_str),
            MESSAGE_INTEGRITY => display_attr!(self, MessageIntegrity, malformed_str),
            ERROR_CODE => display_attr!(self, ErrorCode, malformed_str),
            UNKNOWN_ATTRIBUTES => display_attr!(self, UnknownAttributes, malformed_str),
            REALM => display_attr!(self, Realm, malformed_str),
            NONCE => display_attr!(self, Nonce, malformed_str),
            MESSAGE_INTEGRITY_SHA256 => display_attr!(self, MessageIntegritySha256, malformed_str),
            PASSWORD_ALGORITHM => display_attr!(self, PasswordAlgorithm, malformed_str),
            //USERHASH => display_attr!(self, UserHash, malformed_str),
            XOR_MAPPED_ADDRESS => display_attr!(self, XorMappedAddress, malformed_str),
            PASSWORD_ALGORITHMS => display_attr!(self, PasswordAlgorithms, malformed_str),
            ALTERNATE_DOMAIN => display_attr!(self, AlternateDomain, malformed_str),
            SOFTWARE => display_attr!(self, Software, malformed_str),
            ALTERNATE_SERVER => display_attr!(self, AlternateServer, malformed_str),
            FINGERPRINT => display_attr!(self, Fingerprint, malformed_str),
            PRIORITY => display_attr!(self, Priority, malformed_str),
            USE_CANDIDATE => display_attr!(self, UseCandidate, malformed_str),
            ICE_CONTROLLED => display_attr!(self, IceControlled, malformed_str),
            ICE_CONTROLLING => display_attr!(self, IceControlling, malformed_str),
            _ => format!(
                "RawAttribute (type: {:?}, len: {}, data: {:?})",
                self.header.atype, self.header.length, &self.value
            ),
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
}
impl From<&RawAttribute> for RawAttribute {
    fn from(value: &RawAttribute) -> Self {
        value.clone()
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
    /// # use librice_proto::stun::attribute::{RawAttribute, Attribute, AttributeType};
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
    /// # use librice_proto::stun::attribute::{RawAttribute, Attribute, AttributeType};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<Username> for RawAttribute {
    fn from(value: Username) -> RawAttribute {
        RawAttribute::new(value.get_type(), value.user.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Username {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
/// The ErrorCode [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<ErrorCode> for RawAttribute {
    fn from(value: ErrorCode) -> RawAttribute {
        let mut data = Vec::with_capacity(value.length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push((value.code / 100) as u8);
        data.push((value.code % 100) as u8);
        data.extend(value.reason.as_bytes());
        RawAttribute::new(value.get_type(), &data)
    }
}
impl TryFrom<&RawAttribute> for ErrorCode {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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

/// Builder for an [`ErrorCode`]
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
    pub const FORBIDDEN: u16 = 403;
    pub const UNKNOWN_ATRIBUTE: u16 = 420;
    pub const ALLOCATION_MISMATCH: u16 = 437;
    pub const STALE_NONCE: u16 = 438;
    pub const ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
    pub const WRONG_CREDENTIALS: u16 = 441;
    pub const UNSUPPORTED_TRANSPORT_PROTOCOL: u16 = 442;
    pub const PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
    pub const ALLOCATION_QUOTA_REACHED: u16 = 486;
    pub const ROLE_CONFLICT: u16 = 487;
    pub const SERVER_ERROR: u16 = 500;
    pub const INSUFFICIENT_CAPACITY: u16 = 508;

    /// Create a builder for creating a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    ///  - 403 -> Forbidden
    ///  - 420 -> Unknown Attribute
    ///  - 437 -> Allocation Mismatch
    ///  - 438 -> Stale Nonce
    ///  - 440 -> Address Family Not Supported
    ///  - 441 -> Wrong Credentials
    ///  - 442 -> Supported Transport Protocol
    ///  - 443 -> Peer Address Family Mismatch
    ///  - 486 -> Allocation Quota Reached
    ///  - 487 -> Role Conflict
    ///  - 500 -> Server Error
    ///  - 508 -> Insufficient Capacity
    pub fn default_reason_for_code(code: u16) -> &'static str {
        match code {
            Self::TRY_ALTERNATE => "Try Alternate",
            Self::BAD_REQUEST => "Bad Request",
            Self::UNAUTHORIZED => "Unauthorized",
            Self::FORBIDDEN => "Forbidden",
            Self::UNKNOWN_ATRIBUTE => "Unknown Attribute",
            Self::ALLOCATION_MISMATCH => "Allocation Mismatch",
            Self::STALE_NONCE => "Stale Nonce",
            Self::ADDRESS_FAMILY_NOT_SUPPORTED => "Address Family Not Supported",
            Self::WRONG_CREDENTIALS => "Wrong Credentials",
            Self::UNSUPPORTED_TRANSPORT_PROTOCOL => "Unsupported Transport Protocol",
            Self::PEER_ADDRESS_FAMILY_MISMATCH => "Peer Address Family Mismatch",
            Self::ALLOCATION_QUOTA_REACHED => "Allocation Quota Reached",
            Self::ROLE_CONFLICT => "Role Conflict",
            Self::SERVER_ERROR => "Server Error",
            Self::INSUFFICIENT_CAPACITY => "Insufficient Capacity",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} '{}'", self.get_type(), self.code, self.reason)
    }
}

/// The UnknownAttributes [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<UnknownAttributes> for RawAttribute {
    fn from(value: UnknownAttributes) -> RawAttribute {
        let mut data = Vec::with_capacity(value.length() as usize);
        for attr in &value.attributes {
            let mut encoded = vec![0; 2];
            BigEndian::write_u16(&mut encoded, (*attr).into());
            data.extend(encoded);
        }
        RawAttribute::new(value.get_type(), &data)
    }
}
impl TryFrom<&RawAttribute> for UnknownAttributes {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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

/// The Software [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<Software> for RawAttribute {
    fn from(value: Software) -> RawAttribute {
        RawAttribute::new(value.get_type(), value.software.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Software {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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

macro_rules! bytewise_xor {
    ($size:literal, $a:expr, $b:expr, $default:literal) => {{
        let mut arr = [$default; $size];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = $a[i] ^ $b[i];
        }
        arr
    }};
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MappedSocketAddr {
    pub(crate) addr: SocketAddr,
}

impl MappedSocketAddr {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub(crate) fn length(&self) -> u16 {
        match self.addr {
            SocketAddr::V4(_) => 8,
            SocketAddr::V6(_) => 20,
        }
    }

    pub(crate) fn to_raw(&self, atype: AttributeType) -> RawAttribute {
        match self.addr {
            SocketAddr::V4(addr) => {
                let mut buf = [0; 8];
                buf[1] = AddressFamily::IPV4.to_byte();
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u32::from(*addr.ip());
                BigEndian::write_u32(&mut buf[4..8], octets);
                RawAttribute::new(atype, &buf)
            }
            SocketAddr::V6(addr) => {
                let mut buf = [0; 20];
                buf[1] = AddressFamily::IPV6.to_byte();
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u128::from(*addr.ip());
                BigEndian::write_u128(&mut buf[4..20], octets);
                RawAttribute::new(atype, &buf)
            }
        }
    }

    pub(crate) fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        let port = BigEndian::read_u16(&raw.value[2..4]);
        let family = AddressFamily::from_byte(raw.value[1])?;
        let addr = match family {
            AddressFamily::IPV4 => {
                // ipv4
                if raw.value.len() < 8 {
                    return Err(StunParseError::NotEnoughData);
                }
                if raw.value.len() > 8 {
                    return Err(StunParseError::TooBig);
                }
                IpAddr::V4(Ipv4Addr::from(BigEndian::read_u32(&raw.value[4..8])))
            }
            AddressFamily::IPV6 => {
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
        };
        Ok(Self {
            addr: SocketAddr::new(addr, port),
        })
    }
}

impl std::fmt::Display for MappedSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr {
            SocketAddr::V4(addr) => write!(f, "{:?}", addr),
            SocketAddr::V6(addr) => write!(f, "{:?}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XorSocketAddr {
    pub(crate) addr: MappedSocketAddr,
}

impl XorSocketAddr {
    pub(crate) fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: MappedSocketAddr::new(XorSocketAddr::xor_addr(addr, transaction)),
        }
    }

    pub(crate) fn length(&self) -> u16 {
        self.addr.length()
    }

    pub(crate) fn to_raw(&self, atype: AttributeType) -> RawAttribute {
        self.addr.to_raw(atype)
    }

    pub(crate) fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        let addr = MappedSocketAddr::from_raw(raw)?;
        Ok(Self { addr })
    }

    pub(crate) fn xor_addr(addr: SocketAddr, transaction: TransactionId) -> SocketAddr {
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

    pub(crate) fn addr(&self, transaction: TransactionId) -> SocketAddr {
        XorSocketAddr::xor_addr(self.addr.addr, transaction)
    }
}

impl std::fmt::Display for XorSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr.addr {
            SocketAddr::V4(_) => write!(f, "{:?}", self.addr(0x0.into())),
            SocketAddr::V6(addr) => write!(f, "XOR({:?})", addr),
        }
    }
}

/// The XorMappedAddress [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorMappedAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: XorSocketAddr,
}
impl Attribute for XorMappedAddress {
    fn get_type(&self) -> AttributeType {
        XOR_MAPPED_ADDRESS
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}
impl From<XorMappedAddress> for RawAttribute {
    fn from(value: XorMappedAddress) -> RawAttribute {
        value.addr.to_raw(value.get_type())
    }
}
impl TryFrom<&RawAttribute> for XorMappedAddress {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != XOR_MAPPED_ADDRESS {
            return Err(StunParseError::WrongImplementation);
        }
        Ok(Self {
            addr: XorSocketAddr::from_raw(&raw)?,
        })
    }
}

impl XorMappedAddress {
    /// Create a new XorMappedAddress [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a XorMappedAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}

/// The Priority [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<Priority> for RawAttribute {
    fn from(value: Priority) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], value.priority);
        RawAttribute::new(value.get_type(), &buf)
    }
}
impl TryFrom<&RawAttribute> for Priority {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.priority)
    }
}

/// The UseCandidate [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseCandidate {}

impl Attribute for UseCandidate {
    fn get_type(&self) -> AttributeType {
        USE_CANDIDATE
    }

    fn length(&self) -> u16 {
        0
    }
}
impl From<UseCandidate> for RawAttribute {
    fn from(value: UseCandidate) -> RawAttribute {
        let buf = [0; 0];
        RawAttribute::new(value.get_type(), &buf)
    }
}
impl TryFrom<&RawAttribute> for UseCandidate {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
    /// let _use_candidate = UseCandidate::new();
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl std::fmt::Display for UseCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

/// The IceControlled [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<IceControlled> for RawAttribute {
    fn from(value: IceControlled) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], value.tie_breaker);
        RawAttribute::new(value.get_type(), &buf)
    }
}
impl TryFrom<&RawAttribute> for IceControlled {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl std::fmt::Display for IceControlled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

/// The IceControlling [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<IceControlling> for RawAttribute {
    fn from(value: IceControlling) -> RawAttribute {
        let mut buf = [0; 8];

        BigEndian::write_u64(&mut buf[..8], value.tie_breaker);
        RawAttribute::new(value.get_type(), &buf)
    }
}
impl TryFrom<&RawAttribute> for IceControlling {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl std::fmt::Display for IceControlling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

/// The MessageIntegrity [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<MessageIntegrity> for RawAttribute {
    fn from(value: MessageIntegrity) -> RawAttribute {
        RawAttribute::new(value.get_type(), &value.hmac)
    }
}
impl TryFrom<&RawAttribute> for MessageIntegrity {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl From<Fingerprint> for RawAttribute {
    fn from(value: Fingerprint) -> RawAttribute {
        let buf = bytewise_xor!(4, value.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        RawAttribute::new(value.get_type(), &buf)
    }
}
impl TryFrom<&RawAttribute> for Fingerprint {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
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
    /// # use librice_proto::stun::attribute::*;
    /// let value = [99;4];
    /// assert_eq!(Fingerprint::compute(&value), [216, 45, 250, 14]);
    /// ```
    pub fn compute(data: &[u8]) -> [u8; 4] {
        use crc::{Crc, CRC_32_ISO_HDLC};
        const CRC_ALGO: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        CRC_ALGO.checksum(data).to_be_bytes()
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

/// The Userhash [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Userhash {
    hash: [u8; 32],
}

impl Attribute for Userhash {
    fn get_type(&self) -> AttributeType {
        USERHASH
    }

    fn length(&self) -> u16 {
        32
    }
}
impl From<Userhash> for RawAttribute {
    fn from(value: Userhash) -> RawAttribute {
        RawAttribute::new(value.get_type(), &value.hash)
    }
}

impl TryFrom<&RawAttribute> for Userhash {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != USERHASH {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 32 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 32 {
            return Err(StunParseError::TooBig);
        }
        // sized checked earlier
        let hash: [u8; 32] = raw.value[..32].try_into().unwrap();
        Ok(Self { hash })
    }
}

impl Userhash {
    /// Create a new Userhash [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let value = [0;32];
    /// let user = Userhash::new(value);
    /// assert_eq!(user.hash(), &value);
    /// ```
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Retrieve the hash value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let value = [0;32];
    /// let user = Userhash::new(value);
    /// assert_eq!(user.hash(), &value);
    /// ```
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Compute the hash of a specified block of data as required by STUN
    ///
    /// # Examples
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// assert_eq!(Userhash::compute("user", "realm"), [106, 48, 41, 17, 107, 71, 170, 152, 188, 170, 50, 83, 153, 115, 61, 193, 162, 60, 213, 126, 38, 184, 27, 239, 63, 246, 83, 28, 230, 36, 226, 218]);
    /// ```
    pub fn compute(user: &str, realm: &str) -> [u8; 32] {
        let data = user.to_string() + ":" + realm;
        use sha2::{Digest, Sha256};
        let ret = Sha256::digest(data);
        ret.as_slice().try_into().unwrap()
    }
}

impl std::fmt::Display for Userhash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", self.get_type())?;
        for val in self.hash.iter() {
            write!(f, "{:02x}", val)?;
        }
        Ok(())
    }
}

/// The MessageIntegritySha256 [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIntegritySha256 {
    hmac: Vec<u8>,
}

impl Attribute for MessageIntegritySha256 {
    fn get_type(&self) -> AttributeType {
        MESSAGE_INTEGRITY_SHA256
    }

    fn length(&self) -> u16 {
        self.hmac.len() as u16
    }
}
impl From<MessageIntegritySha256> for RawAttribute {
    fn from(value: MessageIntegritySha256) -> RawAttribute {
        RawAttribute::new(value.get_type(), &value.hmac)
    }
}
impl TryFrom<&RawAttribute> for MessageIntegritySha256 {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != MESSAGE_INTEGRITY_SHA256 {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 16 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 32 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidData);
        }
        Ok(Self {
            hmac: raw.value.to_vec(),
        })
    }
}

impl MessageIntegritySha256 {
    /// Create a new MessageIntegritySha256 [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let hmac = [0;20];
    /// let integrity = MessageIntegritySha256::new(&hmac).unwrap();
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn new(hmac: &[u8]) -> Result<Self, StunParseError> {
        if hmac.len() < 16 {
            return Err(StunParseError::NotEnoughData);
        }
        if hmac.len() > 32 {
            return Err(StunParseError::TooBig);
        }
        if hmac.len() % 4 != 0 {
            return Err(StunParseError::InvalidData);
        }
        Ok(Self {
            hmac: hmac.to_vec(),
        })
    }

    /// Retrieve the value of the hmac
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let hmac = [0; 20];
    /// let integrity = MessageIntegritySha256::new(&hmac).unwrap();
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn hmac(&self) -> &[u8] {
        &self.hmac
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// Note: use `MessageIntegritySha256::verify` for the actual verification to ensure constant time
    /// checks of the values to defeat certain types of timing attacks.
    ///
    /// # Examples
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let key = [40; 10];
    /// let data = [10; 30];
    /// let expected = [141, 112, 214, 41, 247, 110, 61, 95, 46, 245, 132, 79, 99, 16, 167, 95, 239, 168, 3, 63, 101, 78, 150, 24, 241, 139, 34, 229, 189, 37, 14, 113];
    /// let integrity = MessageIntegritySha256::compute(&data, &key).unwrap();
    /// assert_eq!(integrity, expected);
    /// ```
    #[tracing::instrument(
        name = "MessageIntegritySha256::compute",
        level = "trace",
        err,
        ret,
        skip(data, key)
    )]
    pub fn compute(data: &[u8], key: &[u8]) -> Result<[u8; 32], StunError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key)
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
    /// # use librice_proto::stun::attribute::*;
    /// let key = [40; 10];
    /// let data = [10; 30];
    /// let expected = [141, 112, 214, 41, 247, 110, 61, 95, 46, 245, 132, 79, 99, 16, 167, 95, 239, 168, 3, 63, 101, 78, 150, 24, 241, 139, 34, 229, 189, 37, 14, 113];
    /// assert_eq!(MessageIntegritySha256::verify(&data, &key, &expected).unwrap(), ());
    /// ```
    #[tracing::instrument(
        name = "MessageIntegrity::verify",
        level = "debug",
        skip(data, key, expected)
    )]
    pub fn verify(data: &[u8], key: &[u8], expected: &[u8]) -> Result<(), StunError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| {
            error!("failed to create hmac from key data");
            StunError::ParseError(StunParseError::InvalidData)
        })?;
        hmac.update(data);
        hmac.verify_truncated_left(expected).map_err(|_| {
            error!("integrity check failed");
            StunError::IntegrityCheckFailed
        })
    }
}

impl std::fmt::Display for MessageIntegritySha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", self.get_type())?;
        for val in self.hmac.iter() {
            write!(f, "{:02x}", val)?;
        }
        Ok(())
    }
}

/// The Realm [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    realm: String,
}

impl Attribute for Realm {
    fn get_type(&self) -> AttributeType {
        REALM
    }

    fn length(&self) -> u16 {
        self.realm.len() as u16
    }
}
impl From<Realm> for RawAttribute {
    fn from(value: Realm) -> RawAttribute {
        RawAttribute::new(value.get_type(), value.realm.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Realm {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != REALM {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 763 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            realm: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

impl Realm {
    /// Create a new Realm [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let realm = Realm::new("realm").unwrap();
    /// assert_eq!(realm.realm(), "realm");
    /// ```
    pub fn new(realm: &str) -> Result<Self, StunParseError> {
        if realm.len() > 763 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            realm: realm.to_string(),
        })
    }

    /// Retrieve the realm value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let realm = Realm::new("realm").unwrap();
    /// assert_eq!(realm.realm(), "realm");
    /// ```
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl std::fmt::Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.realm)
    }
}

/// The Nonce [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    nonce: String,
}

impl Attribute for Nonce {
    fn get_type(&self) -> AttributeType {
        NONCE
    }

    fn length(&self) -> u16 {
        self.nonce.len() as u16
    }
}
impl From<Nonce> for RawAttribute {
    fn from(value: Nonce) -> RawAttribute {
        RawAttribute::new(value.get_type(), value.nonce.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Nonce {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != NONCE {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 763 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            nonce: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

impl Nonce {
    /// Create a new Nonce [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let nonce = Nonce::new("nonce").unwrap();
    /// assert_eq!(nonce.nonce(), "nonce");
    /// ```
    pub fn new(nonce: &str) -> Result<Self, StunParseError> {
        if nonce.len() > 763 {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {
            nonce: nonce.to_string(),
        })
    }

    /// Retrieve the nonce value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let nonce = Nonce::new("nonce").unwrap();
    /// assert_eq!(nonce.nonce(), "nonce");
    /// ```
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.nonce)
    }
}

/// The hashing algorithm for the password
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithmValue {
    MD5,
    SHA256,
}

impl PasswordAlgorithmValue {
    fn len(&self) -> u16 {
        // all current algorithms have no parameter values
        0
    }

    fn write(&self, data: &mut [u8]) {
        let ty = match self {
            Self::MD5 => 0x1,
            Self::SHA256 => 0x2,
        };
        BigEndian::write_u16(&mut data[..2], ty);
        BigEndian::write_u16(&mut data[2..4], self.len());
    }

    fn read(data: &[u8]) -> Result<Self, StunParseError> {
        let ty = BigEndian::read_u16(&data[..2]);
        let len = BigEndian::read_u16(&data[2..4]);
        if len != 0 {
            return Err(StunParseError::TooBig);
        }
        Ok(match ty {
            0x1 => Self::MD5,
            0x2 => Self::SHA256,
            _ => return Err(StunParseError::OutOfRange),
        })
    }
}

impl std::fmt::Display for PasswordAlgorithmValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA256 => write!(f, "SHA256"),
        }
    }
}

/// The PasswordAlgorithms [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithms {
    algorithms: Vec<PasswordAlgorithmValue>,
}

impl Attribute for PasswordAlgorithms {
    fn get_type(&self) -> AttributeType {
        PASSWORD_ALGORITHMS
    }

    fn length(&self) -> u16 {
        let mut len = 0;
        for algo in self.algorithms.iter() {
            len += 4 + padded_attr_len(algo.len() as usize);
        }
        len as u16
    }
}
impl From<PasswordAlgorithms> for RawAttribute {
    fn from(value: PasswordAlgorithms) -> RawAttribute {
        let len = value.length() as usize;
        let mut data = vec![0; len];
        let mut i = 0;
        for algo in value.algorithms.iter() {
            algo.write(&mut data[i..]);
            i += 4 + padded_attr_len(algo.len() as usize);
        }
        RawAttribute::new(value.get_type(), &data)
    }
}
impl TryFrom<&RawAttribute> for PasswordAlgorithms {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != PASSWORD_ALGORITHMS {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidData);
        }
        let mut i = 0;
        let mut algorithms = vec![];
        while i < raw.value.len() {
            let algo = PasswordAlgorithmValue::read(&raw.value[i..])?;
            i += 4 + padded_attr_len(algo.len() as usize);
            algorithms.push(algo);
        }
        Ok(Self { algorithms })
    }
}

impl PasswordAlgorithms {
    /// Create a new PasswordAlgorithms [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let algorithms = PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]);
    /// assert_eq!(algorithms.algorithms(), &[PasswordAlgorithmValue::MD5]);
    /// ```
    pub fn new(algorithms: &[PasswordAlgorithmValue]) -> Self {
        Self {
            algorithms: algorithms.to_vec(),
        }
    }

    /// Retrieve the algorithms value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let algorithms = PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]);
    /// assert_eq!(algorithms.algorithms(), &[PasswordAlgorithmValue::MD5]);
    /// ```
    pub fn algorithms(&self) -> &[PasswordAlgorithmValue] {
        &self.algorithms
    }
}

impl std::fmt::Display for PasswordAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: [", self.get_type())?;
        for (i, algo) in self.algorithms.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", algo)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

/// The PasswordAlgorithm [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithm {
    algorithm: PasswordAlgorithmValue,
}

impl Attribute for PasswordAlgorithm {
    fn get_type(&self) -> AttributeType {
        PASSWORD_ALGORITHM
    }

    fn length(&self) -> u16 {
        4 + padded_attr_len(self.algorithm.len() as usize) as u16
    }
}

impl From<PasswordAlgorithm> for RawAttribute {
    fn from(value: PasswordAlgorithm) -> RawAttribute {
        let len = value.length() as usize;
        let mut data = vec![0; len];
        value.algorithm.write(&mut data);
        RawAttribute::new(value.get_type(), &data)
    }
}
impl TryFrom<&RawAttribute> for PasswordAlgorithm {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != PASSWORD_ALGORITHM {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidData);
        }
        let algorithm = PasswordAlgorithmValue::read(&raw.value)?;
        Ok(Self { algorithm })
    }
}

impl PasswordAlgorithm {
    /// Create a new PasswordAlgorithm [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let algorithm = PasswordAlgorithm::new(PasswordAlgorithmValue::MD5);
    /// assert_eq!(algorithm.algorithm(), PasswordAlgorithmValue::MD5);
    /// ```
    pub fn new(algorithm: PasswordAlgorithmValue) -> Self {
        Self { algorithm }
    }

    /// Retrieve the algorithm value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let algorithm = PasswordAlgorithm::new(PasswordAlgorithmValue::MD5);
    /// assert_eq!(algorithm.algorithm(), PasswordAlgorithmValue::MD5);
    /// ```
    pub fn algorithm(&self) -> PasswordAlgorithmValue {
        self.algorithm
    }
}

impl std::fmt::Display for PasswordAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.algorithm)
    }
}

/// The address family of the socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    IPV4,
    IPV6,
}

impl AddressFamily {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            AddressFamily::IPV4 => 0x1,
            AddressFamily::IPV6 => 0x2,
        }
    }

    pub(crate) fn from_byte(byte: u8) -> Result<AddressFamily, StunParseError> {
        match byte {
            0x1 => Ok(AddressFamily::IPV4),
            0x2 => Ok(AddressFamily::IPV6),
            _ => Err(StunParseError::InvalidData),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::IPV4 => write!(f, "IPV4"),
            AddressFamily::IPV6 => write!(f, "IPV6"),
        }
    }
}

/// The AlternateServer [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateServer {
    addr: MappedSocketAddr,
}

impl Attribute for AlternateServer {
    fn get_type(&self) -> AttributeType {
        ALTERNATE_SERVER
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl From<AlternateServer> for RawAttribute {
    fn from(value: AlternateServer) -> RawAttribute {
        value.addr.to_raw(value.get_type())
    }
}

impl TryFrom<&RawAttribute> for AlternateServer {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != ALTERNATE_SERVER {
            return Err(StunParseError::WrongImplementation);
        }
        let addr = MappedSocketAddr::from_raw(&raw)?;
        Ok(Self { addr })
    }
}

impl AlternateServer {
    /// Create a new AlternateServer [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let addr = "127.0.0.1:12345".parse().unwrap();
    /// let server = AlternateServer::new(addr);
    /// assert_eq!(server.server(), addr);
    /// ```
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr: MappedSocketAddr::new(addr),
        }
    }

    /// Retrieve the server value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let addr = "127.0.0.1:12345".parse().unwrap();
    /// let server = AlternateServer::new(addr);
    /// assert_eq!(server.server(), addr);
    /// ```
    pub fn server(&self) -> SocketAddr {
        self.addr.addr
    }
}

impl std::fmt::Display for AlternateServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}

/// The AlternateDomain [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateDomain {
    domain: String,
}

impl Attribute for AlternateDomain {
    fn get_type(&self) -> AttributeType {
        ALTERNATE_DOMAIN
    }

    fn length(&self) -> u16 {
        self.domain.len() as u16
    }
}
impl TryFrom<&RawAttribute> for AlternateDomain {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != ALTERNATE_DOMAIN {
            return Err(StunParseError::WrongImplementation);
        }
        // FIXME: should be ascii-only
        Ok(Self {
            domain: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}
impl From<AlternateDomain> for RawAttribute {
    fn from(value: AlternateDomain) -> RawAttribute {
        RawAttribute::new(value.get_type(), value.domain.as_bytes())
    }
}

impl AlternateDomain {
    /// Create a new AlternateDomain [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let dns = "example.com";
    /// let domain = AlternateDomain::new(dns);
    /// assert_eq!(domain.domain(), dns);
    /// ```
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }

    /// Retrieve the domain value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::stun::attribute::*;
    /// let dns = "example.com";
    /// let domain = AlternateDomain::new(dns);
    /// assert_eq!(domain.domain(), dns);
    /// ```
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl std::fmt::Display for AlternateDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.domain)
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
        let b = RawAttribute::from_bytes(bytes.as_ref()).unwrap();
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
        let mut data: Vec<_> = raw.into();
        let len = data.len();
        // one byte too big vs data size
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 + 1);
        assert!(matches!(
            RawAttribute::from_bytes(data.as_ref()),
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
            Username::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn error_code() {
        init();
        let codes = [300, 401, 699];
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
            ErrorCode::try_from(&RawAttribute::from_bytes(data[..len + 4].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            UnknownAttributes::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::InvalidData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            UnknownAttributes::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            Software::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
                XorMappedAddress::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            Priority::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Priority::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            UseCandidate::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            IceControlling::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            IceControlled::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            Fingerprint::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
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
            MessageIntegrity::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            MessageIntegrity::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn userhash() {
        init();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        assert_eq!(attr.get_type(), USERHASH);
        assert_eq!(attr.hash(), &hash);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), USERHASH);
        let mapped2 = Userhash::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), USERHASH);
        assert_eq!(mapped2.hash(), &hash);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Userhash::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Userhash::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn message_integrity_sha256() {
        init();
        let val = [1; 32];
        let attr = MessageIntegritySha256::new(&val).unwrap();
        assert_eq!(attr.get_type(), MESSAGE_INTEGRITY_SHA256);
        assert_eq!(attr.hmac(), &val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), MESSAGE_INTEGRITY_SHA256);
        let mapped2 = MessageIntegritySha256::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), MESSAGE_INTEGRITY_SHA256);
        assert_eq!(mapped2.hmac(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            MessageIntegritySha256::try_from(
                &RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()
            ),
            Err(StunParseError::InvalidData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            MessageIntegritySha256::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn realm() {
        init();
        let attr = Realm::new("realm").unwrap();
        assert_eq!(attr.get_type(), REALM);
        assert_eq!(attr.realm(), "realm");
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), REALM);
        let mapped2 = Realm::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), REALM);
        assert_eq!(mapped2.realm(), "realm");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Realm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn nonce() {
        init();
        let attr = Nonce::new("nonce").unwrap();
        assert_eq!(attr.get_type(), NONCE);
        assert_eq!(attr.nonce(), "nonce");
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), NONCE);
        let mapped2 = Nonce::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), NONCE);
        assert_eq!(mapped2.nonce(), "nonce");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Nonce::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn password_algorithms() {
        init();
        let vals = [PasswordAlgorithmValue::MD5, PasswordAlgorithmValue::SHA256];
        let attr = PasswordAlgorithms::new(&vals);
        assert_eq!(attr.get_type(), PASSWORD_ALGORITHMS);
        assert_eq!(attr.algorithms(), &vals);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), PASSWORD_ALGORITHMS);
        let mapped2 = PasswordAlgorithms::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), PASSWORD_ALGORITHMS);
        assert_eq!(mapped2.algorithms(), &vals);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            PasswordAlgorithms::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn password_algorithm() {
        init();
        let val = PasswordAlgorithmValue::SHA256;
        let attr = PasswordAlgorithm::new(val);
        assert_eq!(attr.get_type(), PASSWORD_ALGORITHM);
        assert_eq!(attr.algorithm(), val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), PASSWORD_ALGORITHM);
        let mapped2 = PasswordAlgorithm::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), PASSWORD_ALGORITHM);
        assert_eq!(mapped2.algorithm(), val);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            PasswordAlgorithm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn alternate_server() {
        init();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = AlternateServer::new(*addr);
            assert_eq!(mapped.get_type(), ALTERNATE_SERVER);
            assert_eq!(mapped.server(), *addr);
            let raw: RawAttribute = mapped.into();
            assert_eq!(raw.get_type(), ALTERNATE_SERVER);
            let mapped2 = AlternateServer::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), ALTERNATE_SERVER);
            assert_eq!(mapped2.server(), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                AlternateServer::try_from(
                    &RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::NotEnoughData)
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                AlternateServer::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongImplementation)
            ));
        }
    }

    #[test]
    fn alternative_domain() {
        init();
        let dns = "example.com";
        let attr = AlternateDomain::new(dns);
        assert_eq!(attr.get_type(), ALTERNATE_DOMAIN);
        assert_eq!(attr.domain(), dns);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), ALTERNATE_DOMAIN);
        let mapped2 = AlternateDomain::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), ALTERNATE_DOMAIN);
        assert_eq!(mapped2.domain(), dns);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            AlternateDomain::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }
}
