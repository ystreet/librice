// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::agent::AgentError;
use crate::stun::attribute::*;

use hmac::{Hmac, Mac, NewMac};

pub const MAGIC_COOKIE: u32 = 0x2112A442;

pub const BINDING: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongTermCredentials {
    pub username: String,
    pub password: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortTermCredentials {
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageIntegrityCredentials {
    ShortTerm(ShortTermCredentials),
    LongTerm(LongTermCredentials),
}

impl MessageIntegrityCredentials {
    fn make_hmac_key(&self) -> Vec<u8> {
        match self {
            MessageIntegrityCredentials::ShortTerm(short) => short.password.clone().into(),
            MessageIntegrityCredentials::LongTerm(long) => {
                let data = long.username.clone()
                    + ":"
                    + &long.nonce.clone()
                    + ":"
                    + &long.password.clone();
                data.into()
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    Success,
    Error,
}

impl MessageClass {
    pub fn is_response(self) -> bool {
        matches!(self, MessageClass::Success | MessageClass::Error)
    }

    fn to_bits(self) -> u16 {
        match self {
            MessageClass::Request => 0x000,
            MessageClass::Indication => 0x010,
            MessageClass::Success => 0x100,
            MessageClass::Error => 0x110,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MessageType(u16);

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MessageType(class: {:?}, method: {} ({:#x}))",
            self.class(),
            self.method(),
            self.method()
        )
    }
}

impl MessageType {
    pub fn class(self) -> MessageClass {
        let class = (self.0 & 0x10) >> 4 | (self.0 & 0x100) >> 7;
        match class {
            0x0 => MessageClass::Request,
            0x1 => MessageClass::Indication,
            0x2 => MessageClass::Success,
            0x3 => MessageClass::Error,
            _ => unreachable!(),
        }
    }

    pub fn has_class(self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    pub fn is_response(self) -> bool {
        self.class().is_response()
    }

    pub fn method(self) -> u16 {
        self.0 & 0xf | (self.0 & 0xe0) >> 1 | (self.0 & 0x3e00) >> 2
    }

    pub fn has_method(self, method: u16) -> bool {
        self.method() == method
    }

    pub fn from_class_method(class: MessageClass, method: u16) -> Self {
        let class_bits = MessageClass::to_bits(class);
        let method_bits = method & 0xf | (method & 0x70) << 1 | (method & 0xf80) << 2;
        // trace!("MessageType from class {:?} and method {:?} into {:?}", class, method,
        //     class_bits | method_bits);
        Self {
            0: class_bits | method_bits,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 2];
        BigEndian::write_u16(&mut ret[0..2], self.0);
        ret
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, AgentError> {
        let data = BigEndian::read_u16(data);
        if data & 0xc000 != 0x0 {
            /* not a stun packet */
            warn!("malformed {:?}", data);
            return Err(AgentError::Malformed);
        }
        Ok(Self { 0: data })
    }
}
impl From<MessageType> for Vec<u8> {
    fn from(f: MessageType) -> Self {
        f.to_bytes()
    }
}
impl TryFrom<&[u8]> for MessageType {
    type Error = AgentError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        MessageType::from_bytes(value)
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    msg_type: MessageType,
    transaction: u128, /* 96-bits valid */
    attributes: Vec<RawAttribute>,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message(class: {:?}, method: {} ({:#x}), transaction: {:#x}, attributes: ",
            self.get_type().class(),
            self.get_type().method(),
            self.get_type().method(),
            self.transaction_id()
        )?;
        if self.attributes.is_empty() {
            write!(f, "[]")?;
        } else {
            write!(f, "[")?;
            for (i, a) in self.attributes.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", a)?;
            }
            write!(f, "]")?;
        }
        write!(f, ")")
    }
}

fn padded_attr_size(attr: &dyn Attribute) -> usize {
    if attr.get_length() % 4 == 0 {
        4 + attr.get_length() as usize
    } else {
        8 + attr.get_length() as usize - attr.get_length() as usize % 4
    }
}

impl Message {
    pub fn new(mtype: MessageType, transaction: u128) -> Self {
        Self {
            msg_type: mtype,
            transaction,
            attributes: vec![],
        }
    }

    fn new_request(mtype: MessageType) -> Self {
        Message::new(mtype, Message::generate_transaction())
    }

    pub fn new_request_method(method: u16) -> Self {
        Message::new_request(MessageType::from_class_method(
            MessageClass::Request,
            method,
        ))
    }

    pub fn new_success(orig: &Message) -> Self {
        Message::new(
            MessageType::from_class_method(MessageClass::Success, orig.method()),
            orig.transaction_id(),
        )
    }

    pub fn new_error(orig: &Message) -> Self {
        Message::new(
            MessageType::from_class_method(MessageClass::Error, orig.method()),
            orig.transaction_id(),
        )
    }

    pub fn get_type(&self) -> MessageType {
        self.msg_type
    }

    pub fn class(&self) -> MessageClass {
        self.get_type().class()
    }

    pub fn has_class(&self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    pub fn is_response(&self) -> bool {
        self.class().is_response()
    }

    pub fn method(&self) -> u16 {
        self.get_type().method()
    }

    pub fn has_method(&self, method: u16) -> bool {
        self.method() == method
    }

    pub fn transaction_id(&self) -> u128 {
        self.transaction
    }

    pub fn generate_transaction() -> u128 {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        rng.gen::<u128>() & 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff
    }

    /// Serialize a `Message` to network bytes
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::{RawAttribute, Attribute};
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::new(MessageType::from_class_method(MessageClass::Request, BINDING), 1000);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr).is_ok());
    /// assert_eq!(message.to_bytes(), vec![0, 1, 0, 8, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232, 0, 1, 0, 1, 3, 0, 0, 0]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut attr_size = 0;
        for attr in &self.attributes {
            attr_size += padded_attr_size(attr);
        }
        let mut ret = Vec::with_capacity(20 + attr_size);
        ret.extend(self.msg_type.to_bytes());
        ret.resize(20, 0);
        let tid = (MAGIC_COOKIE as u128) << 96 | self.transaction & 0xffff_ffff_ffff_ffff_ffff_ffff;
        BigEndian::write_u128(&mut ret[4..20], tid);
        BigEndian::write_u16(&mut ret[2..4], attr_size as u16);
        for attr in &self.attributes {
            ret.extend(attr.to_bytes());
        }
        ret
    }

    /// Deserialize a `Message`
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::{RawAttribute, Attribute};
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let msg_data = vec![0, 1, 0, 8, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232, 0, 1, 0, 1, 3, 0, 0, 0];
    /// let mut message = Message::from_bytes(&msg_data).unwrap();
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// let msg_attr = message.get_attribute(1.into()).unwrap();
    /// assert_eq!(msg_attr, &attr);
    /// assert_eq!(message.get_type(), MessageType::from_class_method(MessageClass::Request, BINDING));
    /// assert_eq!(message.transaction_id(), 1000);
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, AgentError> {
        let orig_data = data;

        if data.len() < 20 {
            // always at least 20 bytes long
            return Err(AgentError::NotEnoughData);
        }
        let mtype = MessageType::from_bytes(data)?;
        let mlength = BigEndian::read_u16(&data[2..]) as usize;
        if mlength + 20 > data.len() {
            // mlength + header
            warn!(
                "malformed advertised size {:?} and data size {:?} don't match",
                mlength + 20,
                data.len()
            );
            return Err(AgentError::Malformed);
        }
        let tid = BigEndian::read_u128(&data[4..]);
        let cookie = (tid >> 96) as u32;
        if cookie != MAGIC_COOKIE {
            warn!(
                "malformed cookie constant {:?} != stored data {:?}",
                MAGIC_COOKIE, cookie
            );
            return Err(AgentError::Malformed);
        }
        let tid = tid & 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff;
        let mut ret = Self::new(mtype, tid);

        let mut data_offset = 20;
        let mut data = &data[20..];
        let mut seen_message_integrity = false;
        while !data.is_empty() {
            let attr = RawAttribute::from_bytes(data)?;
            let padded_len = padded_attr_size(&attr);

            if seen_message_integrity && attr.get_type() != FINGERPRINT {
                // only attribute valid after MESSAGE_INTEGRITY is FINGERPRINT
                warn!(
                    "unexpected attribute {} after MESSAGE_INTEGRITY",
                    attr.get_type()
                );
                return Err(AgentError::Malformed);
            }

            if attr.get_type() == MESSAGE_INTEGRITY {
                seen_message_integrity = true;
                // need credentials to validate the integrity of the message
            }
            if attr.get_type() == FINGERPRINT {
                let f = Fingerprint::from_raw(&attr)?;
                let msg_fingerprint = f.fingerprint();
                let mut fingerprint_data = orig_data[..data_offset].to_vec();
                BigEndian::write_u16(
                    &mut fingerprint_data[2..4],
                    (data_offset + padded_len - 20) as u16,
                );
                let calculated_fingerprint =
                    crc::crc32::checksum_ieee(&fingerprint_data).to_be_bytes();
                if &calculated_fingerprint != msg_fingerprint {
                    warn!(
                        "fingerprint mismatch {:?} != {:?}",
                        calculated_fingerprint, msg_fingerprint
                    );
                    return Err(AgentError::Malformed);
                }
            }
            ret.attributes.push(attr);
            data = &data[padded_len..];
            data_offset += padded_len;
        }
        Ok(ret)
    }

    pub fn validate_integrity(
        &self,
        orig_data: &[u8],
        credentials: &MessageIntegrityCredentials,
    ) -> Result<(), AgentError> {
        let raw = self
            .get_attribute(MESSAGE_INTEGRITY)
            .ok_or(AgentError::ResourceNotFound)?;
        let integrity = MessageIntegrity::try_from(raw)?;
        let msg_hmac = integrity.hmac();

        // find the location of the original MessageIntegrity attribute: XXX: maybe encode this into
        // the attribute instead?
        let data = orig_data;
        if data.len() < 20 {
            // always at least 20 bytes long
            return Err(AgentError::NotEnoughData);
        }
        let mut data = &data[20..];
        let mut data_offset = 20;
        while !data.is_empty() {
            let attr = RawAttribute::from_bytes(data)?;
            if attr.get_type() == MESSAGE_INTEGRITY {
                let msg = MessageIntegrity::try_from(&attr)?;
                if msg.hmac() != msg_hmac {
                    // data hmac is different from message hmac -> wrong data for this message.
                    return Err(AgentError::Malformed);
                }

                // HMAC is computed using all the data up to (exclusive of) the MESSAGE_INTEGRITY
                // but with a length field including the MESSAGE_INTEGRITY attribute...
                let key = credentials.make_hmac_key();
                let mut hmac =
                    Hmac::<sha1::Sha1>::new_varkey(&key).map_err(|_| AgentError::Malformed)?;
                let mut hmac_data = orig_data[..data_offset].to_vec();
                BigEndian::write_u16(&mut hmac_data[2..4], data_offset as u16 + 24 - 20);
                hmac.update(&hmac_data);
                return hmac
                    .verify(msg_hmac)
                    .map_err(|_| AgentError::IntegrityCheckFailed);
            }
            let padded_len = padded_attr_size(&attr);
            data = &data[padded_len..];
            data_offset += padded_len;
        }
        // no hmac in data but there was in the message? -> incompatible data for this message
        Err(AgentError::Malformed)
    }

    pub fn add_message_integrity(
        &mut self,
        credentials: &MessageIntegrityCredentials,
    ) -> Result<(), AgentError> {
        if self.get_attribute(MESSAGE_INTEGRITY).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        if self.get_attribute(FINGERPRINT).is_some() {
            return Err(AgentError::AlreadyExists);
        }

        // message-integrity is computed using all the data up to (exclusive of) the
        // MESSAGE-INTEGRITY but with a length field including the MESSAGE-INTEGRITY attribute...
        let mut bytes = self.to_bytes();
        // rewrite the length to include the message-integrity attribute
        let existing_len = BigEndian::read_u16(&bytes[2..4]);
        BigEndian::write_u16(&mut bytes[2..4], existing_len + 24);
        let key = credentials.make_hmac_key();
        let mut hmac = Hmac::<sha1::Sha1>::new_varkey(&key).map_err(|_| AgentError::Malformed)?;
        let hmac_data = bytes.to_vec();
        hmac.update(&hmac_data);
        let integrity = hmac.finalize().into_bytes();
        self.attributes
            .push(MessageIntegrity::new(integrity.into()).into());
        Ok(())
    }

    pub fn add_fingerprint(&mut self) -> Result<(), AgentError> {
        if  self.get_attribute(FINGERPRINT).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        // fingerprint is computed using all the data up to (exclusive of) the FINGERPRINT
        // but with a length field including the FINGERPRINT attribute...
        let mut bytes = self.to_bytes();
        // rewrite the length to include the fingerprint attribute
        let existing_len = BigEndian::read_u16(&bytes[2..4]);
        BigEndian::write_u16(&mut bytes[2..4], existing_len + 8);
        let fingerprint = crc::crc32::checksum_ieee(&bytes).to_be_bytes();
        self.attributes.push(Fingerprint::new(fingerprint).into());
        Ok(())
    }

    /// Add a `Attribute` to this `Message`.  Only one `AttributeType` can be added for each
    /// `Attribute.  Attempting to add multiple `Atribute`s of the same `AttributeType`.
    ///
    /// # Examples
    ///
    /// Add an `Attribute`
    ///
    /// ```
    /// # use librice::stun::attribute::RawAttribute;
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::new(MessageType::from_class_method(MessageClass::Request, BINDING), 0);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr.clone()).is_ok());
    /// assert!(message.add_attribute(attr).is_err());
    /// ```
    pub fn add_attribute(&mut self, attr: RawAttribute) -> Result<(), AgentError> {
        if attr.get_type() == MESSAGE_INTEGRITY {
            return Err(AgentError::WrongImplementation);
        }
        if attr.get_type() == FINGERPRINT {
            return Err(AgentError::WrongImplementation);
        }
        if self.get_attribute(attr.get_type()).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        // can't validly add generic attributes after message integrity or fingerprint
        if self.get_attribute(MESSAGE_INTEGRITY).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        if self.get_attribute(FINGERPRINT).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        self.attributes.push(attr);
        Ok(())
    }

    /// Retrieve an `Attribute` from this `Message`.
    ///
    /// # Examples
    ///
    /// Retrieve an `Attribute`
    ///
    /// ```
    /// # use librice::stun::attribute::{RawAttribute, Attribute};
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::new(MessageType::from_class_method(MessageClass::Request, BINDING), 0);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr.clone()).is_ok());
    /// assert_eq!(*message.get_attribute(1.into()).unwrap(), attr);
    /// ```
    pub fn get_attribute(&self, atype: AttributeType) -> Option<&RawAttribute> {
        self.attributes.iter().find(|attr| attr.get_type() == atype)
    }

    pub fn iter_attributes(&self) -> impl Iterator<Item = &RawAttribute> {
        self.attributes.iter()
    }

    pub fn check_attribute_types(
        msg: &Message,
        supported: &[AttributeType],
        required_in_msg: &[AttributeType],
    ) -> Option<Message> {
        // Attribute -> AttributeType
        let unsupported: Vec<AttributeType> = msg
            .iter_attributes()
            .map(|a| a.get_type())
            // attribute types that require comprehension but are not supported by the caller
            .filter(|&at| {
                at.comprehension_required() && supported.iter().position(|&a| a == at).is_none()
            })
            .collect();
        if !unsupported.is_empty() {
            debug!(
                "Message contains unknown comprehension required attributes {:?}",
                unsupported
            );
            return Message::unknown_attributes(msg, &unsupported).ok();
        }
        let has_required_attribute_missing =
            required_in_msg
                .iter()
                // attribute types we need in the message -> failure -> Bad Request
                .any(|&at| {
                    msg.iter_attributes()
                        .map(|a| a.get_type())
                        .position(|a| a == at)
                        .is_none()
                });
        if has_required_attribute_missing {
            debug!("Message is missing required attributes");
            return Message::bad_request(msg).ok();
        }
        None
    }

    pub fn unknown_attributes(
        src: &Message,
        attributes: &[AttributeType],
    ) -> Result<Message, AgentError> {
        let mut out = Message::new_error(src);
        out.add_attribute(Software::new("stund - librice v0.1")?.to_raw())?;
        out.add_attribute(ErrorCode::new(420, "Unknown Attributes")?.to_raw())?;
        if !attributes.is_empty() {
            out.add_attribute(UnknownAttributes::new(&attributes).to_raw())?;
        }
        Ok(out)
    }

    pub fn bad_request(src: &Message) -> Result<Message, AgentError> {
        let mut out = Message::new_error(src);
        out.add_attribute(Software::new("stund - librice v0.1")?.to_raw())?;
        out.add_attribute(ErrorCode::new(400, "Bad Request")?.to_raw())?;
        Ok(out)
    }

    pub fn has_attribute(&self, atype: AttributeType) -> bool {
        self.get_attribute(atype).is_some()
    }
}
impl From<Message> for Vec<u8> {
    fn from(f: Message) -> Self {
        f.to_bytes()
    }
}
impl TryFrom<&[u8]> for Message {
    type Error = AgentError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Message::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn msg_type_roundtrip() {
        init();
        /* validate that all methods/classes survive a roundtrip */
        for m in 0..0xfff {
            let classes = vec![
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::Success,
                MessageClass::Error,
            ];
            for c in classes {
                let mtype = MessageType::from_class_method(c, m);
                assert_eq!(mtype.class(), c);
                assert_eq!(mtype.method(), m);
            }
        }
    }

    #[test]
    fn msg_roundtrip() {
        init();
        /* validate that all methods/classes survive a roundtrip */
        for m in (0x009..0x4ff).step_by(0x123) {
            let classes = vec![
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::Success,
                MessageClass::Error,
            ];
            for c in classes {
                let mtype = MessageType::from_class_method(c, m);
                for tid in (0x18..0xffff_ffff_ffff_ffff_ff).step_by(0xfedc_ba98_7654_3210) {
                    let mut msg = Message::new(mtype, tid);
                    let attr = RawAttribute::new(1.into(), &[3]);
                    assert!(msg.add_attribute(attr.clone()).is_ok());
                    let data = msg.to_bytes();

                    let msg = Message::from_bytes(&data).unwrap();
                    let msg_attr = msg.get_attribute(1.into()).unwrap();
                    assert_eq!(msg_attr, &attr);
                    assert_eq!(msg.get_type(), mtype);
                    assert_eq!(msg.transaction_id(), tid);
                }
            }
        }
    }

    #[test]
    fn unknown_attributes() {
        let src = Message::new_request_method(BINDING);
        let msg = Message::unknown_attributes(&src, &[SOFTWARE]).unwrap();
        assert_eq!(msg.transaction_id(), src.transaction_id());
        assert_eq!(msg.class(), MessageClass::Error);
        assert_eq!(msg.method(), src.method());
        let err = ErrorCode::from_raw(msg.get_attribute(ERROR_CODE).unwrap()).unwrap();
        assert_eq!(err.code(), 420);
        let unknown_attrs =
            UnknownAttributes::from_raw(msg.get_attribute(UNKNOWN_ATTRIBUTES).unwrap()).unwrap();
        assert!(unknown_attrs.has_attribute(SOFTWARE));
    }

    #[test]
    fn bad_request() {
        let src = Message::new_request_method(BINDING);
        let msg = Message::bad_request(&src).unwrap();
        assert_eq!(msg.transaction_id(), src.transaction_id());
        assert_eq!(msg.class(), MessageClass::Error);
        assert_eq!(msg.method(), src.method());
        let err = ErrorCode::from_raw(msg.get_attribute(ERROR_CODE).unwrap()).unwrap();
        assert_eq!(err.code(), 400);
    }

    #[test]
    fn fingerprint() {
        init();
        let mut msg = Message::new_request_method(BINDING);
        let software_str = "s";
        msg.add_attribute(Software::new(software_str).unwrap().into())
            .unwrap();
        msg.add_fingerprint().unwrap();
        let orig_fingerprint =
            Fingerprint::try_from(msg.get_attribute(FINGERPRINT).unwrap()).unwrap();
        let bytes: Vec<_> = msg.into();
        // validates the fingerprint of the data when available
        let new_msg = Message::from_bytes(&bytes).unwrap();
        let software = Software::try_from(new_msg.get_attribute(SOFTWARE).unwrap()).unwrap();
        assert_eq!(software.software(), software_str);
        let new_fingerprint =
            Fingerprint::try_from(new_msg.get_attribute(FINGERPRINT).unwrap()).unwrap();
        assert_eq!(
            orig_fingerprint.fingerprint(),
            new_fingerprint.fingerprint()
        );
    }

    #[test]
    fn integrity() {
        init();
        let mut msg = Message::new_request_method(BINDING);
        let software_str = "s";
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "secret".to_owned(),
        });
        msg.add_attribute(Software::new(software_str).unwrap().into())
            .unwrap();
        msg.add_message_integrity(&credentials).unwrap();
        let bytes: Vec<_> = msg.clone().into();
        msg.validate_integrity(&bytes, &credentials).unwrap();
        let orig_integrity =
            MessageIntegrity::try_from(msg.get_attribute(MESSAGE_INTEGRITY).unwrap()).unwrap();
        // validates the fingerprint of the data when available
        let new_msg = Message::from_bytes(&bytes).unwrap();
        let software = Software::try_from(new_msg.get_attribute(SOFTWARE).unwrap()).unwrap();
        assert_eq!(software.software(), software_str);
        let new_integrity =
            MessageIntegrity::try_from(new_msg.get_attribute(MESSAGE_INTEGRITY).unwrap()).unwrap();
        assert_eq!(orig_integrity.hmac(), new_integrity.hmac());
        new_msg.validate_integrity(&bytes, &credentials).unwrap();
    }

    #[test]
    fn valid_attributes() {
        let mut src = Message::new_request_method(BINDING);
        src.add_attribute(Username::new("123").unwrap().into())
            .unwrap();
        src.add_attribute(Priority::new(123).into()).unwrap();

        // success case
        let res = Message::check_attribute_types(&src, &[USERNAME, PRIORITY], &[USERNAME]);
        assert!(res.is_none());

        // fingerprint required but not present
        let res = Message::check_attribute_types(&src, &[USERNAME, PRIORITY], &[FINGERPRINT]);
        assert!(res.is_some());
        let res = res.unwrap();
        assert!(res.has_class(MessageClass::Error));
        assert!(res.has_method(src.method()));
        let err = ErrorCode::from_raw(res.get_attribute(ERROR_CODE).unwrap()).unwrap();
        assert_eq!(err.code(), 400);

        // priority unsupported
        let res = Message::check_attribute_types(&src, &[USERNAME], &[]);
        assert!(res.is_some());
        let res = res.unwrap();
        assert!(res.has_class(MessageClass::Error));
        assert!(res.has_method(src.method()));
        let err = ErrorCode::from_raw(res.get_attribute(ERROR_CODE).unwrap()).unwrap();
        assert_eq!(err.code(), 420);
        let unknown =
            UnknownAttributes::from_raw(res.get_attribute(UNKNOWN_ATTRIBUTES).unwrap()).unwrap();
        assert!(unknown.has_attribute(PRIORITY));
    }
}
