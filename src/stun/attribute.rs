// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::agent::AgentError;

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

    pub fn name(self) -> &'static str{
        match self {
            MAPPED_ADDRESS => "MAPPED-ADDRESS",
            USERNAME => "USERNAME",
            MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY",
            ERROR_CODE => "ERROR-CODE",
            UNKNOWN_ATTRIBUTES => "UNKNOWN-ATTRIBUTES",
            REALM => "REALM",
            NONCE => "NONCE",
            SOFTWARE => "SOFTWARE",
            ALTERNATE_SERVER => "ALTERNATE-SERVER",
            FINGERPRINT => "FINGERPRINT",
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
    fn parse (data: &[u8]) -> Result<Self,AgentError> {
        if data.len() < 4 {
            error!("not enough data");
            return Err(AgentError::NotEnoughData)
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
        BigEndian::write_u16 (&mut ret[0..2], self.atype.into());
        BigEndian::write_u16 (&mut ret[2..4], self.length);
        ret
    }
}
impl From<AttributeHeader> for Vec<u8> {
    fn from(f: AttributeHeader) -> Self {
        f.to_bytes()
    }
}

pub trait Attribute: std::fmt::Debug + std::any::Any {
    /// Retrieve the `AttributeType` of an `Attribute`
    fn get_type(&self) -> AttributeType;

    /// Retrieve the length of an `Attribute`.  This is not the padded length as stored in a
    /// `Message`
    fn get_length (&self) -> u16;

    /// Helper to cast to an std::any::Any
    fn as_any(&self) -> &dyn std::any::Any
            where Self: Sized {
        self
    }

    /// Convert an `Attribute` to a `RawAttribute`
    fn to_raw(&self) -> RawAttribute;

    /// Convert an `Attribute` from a `RawAttribute`
    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError>
    where Self: Sized;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub header: AttributeHeader,
    pub value: Vec<u8>
}

impl std::fmt::Display for RawAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // try to get a more specialised display
        let malformed_str = format!("{}(Malformed): len: {}, data: {:?})", self.get_type(), self.header.length, self.value);
        let display_str = if self.get_type() == SOFTWARE {
            if let Ok(software) = Software::from_raw(self.clone()) {
                format!("{}", software)
            } else {
                malformed_str
            }
        } else if self.get_type() == UNKNOWN_ATTRIBUTES {
            if let Ok(attrs) = UnknownAttributes::from_raw(self.clone()) {
                format!("{}", attrs)
            } else {
                malformed_str
            }
        } else if self.get_type() == ERROR_CODE {
            if let Ok(code) = ErrorCode::from_raw(self.clone()) {
                format!("{}", code)
            } else {
                malformed_str
            }
        } else if self.get_type() == USERNAME {
            if let Ok(user) = Username::from_raw(self.clone()) {
                format!("{}", user)
            } else {
                malformed_str
            }
        } else {
            format!("RawAttribute (type: {:?}, len: {}, data: {:?})", self.header.atype, self.header.length, &self.value)
        };
        write!(f, "{}", display_str)
    }
}

impl Attribute for RawAttribute {
    fn get_length (&self) -> u16 {
        self.header.length
    }

    fn get_type (&self) -> AttributeType {
        self.header.atype
    }

    fn to_raw(&self) -> RawAttribute {
        self.clone()
    }

    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError> {
        Ok(raw.clone())
    }
}

impl RawAttribute {
    pub fn new(atype: AttributeType, data: &[u8]) -> Self {
        Self {
            header: AttributeHeader {
                atype: atype,
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
    pub fn from_bytes(data: &[u8]) -> Result<Self,AgentError> {
        let header = AttributeHeader::parse(data)?;
        // the advertised length is larger than actual data -> error
        if header.length > (data.len() - 4) as u16 {
            return Err(AgentError::InvalidSize);
        }
        let mut data = data[4..].to_vec();
        data.truncate(header.length as usize);
        //trace!("parsed into {:?} {:?}", header, data);
        Ok (Self {
            header: header,
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

#[derive(Debug, Clone)]
pub struct Username {
    user: String,
}
impl Attribute for Username {
    fn get_type(&self) -> AttributeType {
        USERNAME
    }

    fn get_length (&self) -> u16 {
        self.user.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type().into(), self.user.as_bytes())
    }

    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError> {
        if raw.header.atype != USERNAME {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 513 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            user: std::str::from_utf8(&raw.value).map_err(|_| AgentError::Malformed)?.to_owned()
        })
    }
}

impl Username {
    pub fn new(user: &str) -> Result<Self,AgentError> {
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

#[derive(Debug, Clone)]
pub struct ErrorCode {
    code: u16,
    reason: String,
}
impl Attribute for ErrorCode {
    fn get_type(&self) -> AttributeType {
        ERROR_CODE
    }

    fn get_length (&self) -> u16 {
        self.reason.len() as u16 + 4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.get_length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push((self.code / 100) as u8);
        data.push((self.code % 100) as u8);
        data.extend(self.reason.as_bytes());
        RawAttribute::new(self.get_type().into(), &data)
    }

    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError> {
        if raw.header.atype != ERROR_CODE {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 763 + 4 {
            return Err(AgentError::TooBig);
        }
        let code_h = (raw.value[2] & 0x7) as u16;
        let code_tens = raw.value[3] as u16;
        if code_h < 3 || code_h > 6 || code_tens > 99 {
            return Err(AgentError::Malformed);
        }
        let code = code_h * 100 + code_tens;
        Ok(Self {
            code: code,
            reason: std::str::from_utf8(&raw.value[4..]).map_err(|_| AgentError::Malformed)?.to_owned()
        })
    }
}
impl ErrorCode {
    pub fn new(code: u16, reason: &str) -> Result<Self,AgentError> {
        if code < 300 || code > 699 {
            return Err(AgentError::Malformed);
        }
        Ok(Self {
            code: code,
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
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} '{}'", self.get_type(), self.code, self.reason)
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

    fn get_length (&self) -> u16 {
        (self.attributes.len() as u16) * 2
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.get_length() as usize);
        for attr in &self.attributes {
            let mut encoded = vec![0; 2];
            BigEndian::write_u16 (&mut encoded, (*attr).into());
            data.extend(encoded);
        }
        RawAttribute::new(self.get_type().into(), &data)
    }

    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError> {
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
        Ok(Self {
            attributes: attrs,
        })
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
        self.attributes.iter().find(|&&a| a == attr).is_some()
    }
}

impl std::fmt::Display for UnknownAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.get_type(), self.attributes)
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

    fn get_length (&self) -> u16 {
        self.software.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type().into(), self.software.as_bytes())
    }

    fn from_raw(raw: RawAttribute) -> Result<Self,AgentError> {
        if raw.header.atype != SOFTWARE {
            return Err(AgentError::WrongImplementation);
        }
        if raw.value.len() > 763 {
            return Err(AgentError::TooBig);
        }
        Ok(Self {
            software: std::str::from_utf8(&raw.value).map_err(|_| AgentError::Malformed)?.to_owned()
        })
    }
}

impl Software {
    pub fn new(software: &str) -> Result<Self,AgentError> {
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
        let raw = user.to_raw();
        let user2 = Username::from_raw(raw).unwrap();
        assert_eq!(user2.get_type(), USERNAME);
        assert_eq!(user2.username(), s);
    }

    #[test]
    fn error_code() {
        init();
        let code = 401;
        let reason = ErrorCode::default_reason_for_code(code);
        let err = ErrorCode::new(code, &reason).unwrap();
        assert_eq!(err.get_type(), ERROR_CODE);
        assert_eq!(err.code(), code);
        assert_eq!(err.reason(), reason);
        let raw = err.to_raw();
        let err2 = ErrorCode::from_raw(raw).unwrap();
        assert_eq!(err2.get_type(), ERROR_CODE);
        assert_eq!(err2.code(), code);
        assert_eq!(err2.reason(), reason);
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
        let raw = unknown.to_raw();
        let unknown2 = UnknownAttributes::from_raw(raw).unwrap();
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
        let raw = software.to_raw();
        let software2 = Software::from_raw(raw).unwrap();
        assert_eq!(software2.get_type(), SOFTWARE);
        assert_eq!(software2.software(), "software");
    }
}
