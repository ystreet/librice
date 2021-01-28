// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Messages
//!
//! Provides types for generating, parsing, and manipulating STUN messages as specified in one of
//! [RFC8489], [RFC5389], or [RFC3489].
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::agent::AgentError;
use crate::stun::attribute::*;

use hmac::{Hmac, Mac, NewMac};

/// The value of magic cookie (in network byte order) as specified in RFC5389, and RFC8489.
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// The value of the binding message type.  Can be used in either a request or an indication
/// message.
pub const BINDING: u16 = 0x0001;

/// Structure for holding the required credentials for handling long-term STUN credentials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongTermCredentials {
    pub username: String,
    pub password: String,
    pub nonce: String,
}

/// Structure for holding the required credentials for handling short-term STUN credentials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortTermCredentials {
    pub password: String,
}

/// Enum for holding the credentials used to sign or verify a [`Message`]
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

/// The class of a [`Message`].
///
/// There are four classes of [`Message`]s within the STUN protocol:
///
///  - [Request][`MessageClass::Request`] indicates that a request is being made and a
///    response is expected.
///  - An [Indication][`MessageClass::Indication`] is a fire and forget [`Message`] where
///    no response is required or expected.
///  - [Success][`MessageClass::Success`] indicates that a [Request][`MessageClass::Request`]
///    was successfully handled and the
///  - [Error][`MessageClass::Error`] class indicates that an error was produced.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    Success,
    Error,
}

impl MessageClass {
    /// Returns whether this [`MessageClass`] is of a response type.  i.e. is either
    /// [`MessageClass::Success`] or [`MessageClass::Error`].
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

/// The type of a [`Message`].  A combination of a [`MessageClass`] and a STUN method.
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
    /// Create a new [`MessageType`] from the provided [`MessageClass`] and method
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.has_class(MessageClass::Indication), true);
    /// assert_eq!(mtype.has_method(BINDING), true);
    /// ```
    pub fn from_class_method(class: MessageClass, method: u16) -> Self {
        let class_bits = MessageClass::to_bits(class);
        let method_bits = method & 0xf | (method & 0x70) << 1 | (method & 0xf80) << 2;
        // trace!("MessageType from class {:?} and method {:?} into {:?}", class, method,
        //     class_bits | method_bits);
        Self {
            0: class_bits | method_bits,
        }
    }

    /// Retrieves the class of a [`MessageType`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.class(), MessageClass::Indication);
    /// ```
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

    /// Returns whether class of a [`MessageType`] is equal to the provided [`MessageClass`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert!(mtype.has_class(MessageClass::Indication));
    /// ```
    pub fn has_class(self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    /// Returns whether class of a [`MessageType`] indicates a response [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// assert_eq!(MessageType::from_class_method(MessageClass::Indication, BINDING)
    ///     .is_response(), false);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Request, BINDING)
    ///     .is_response(), false);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Success, BINDING)
    ///     .is_response(), true);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Error, BINDING)
    ///     .is_response(), true);
    /// ```
    pub fn is_response(self) -> bool {
        self.class().is_response()
    }

    /// Returns the method of a [`MessageType`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.method(), BINDING);
    /// ```
    pub fn method(self) -> u16 {
        self.0 & 0xf | (self.0 & 0xe0) >> 1 | (self.0 & 0x3e00) >> 2
    }

    /// Returns whether the method of a [`MessageType`] is equal to the provided value
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.has_method(BINDING), true);
    /// ```
    pub fn has_method(self, method: u16) -> bool {
        self.method() == method
    }

    /// Convert a [`MessageType`] to network bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 2];
        BigEndian::write_u16(&mut ret[0..2], self.0);
        ret
    }

    /// Convert a set of network bytes into a [`MessageType`] or return an error
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

/// The structure that encapsulates the entirety of a STUN message
///
/// Contains the [`MessageType`], a transaction ID, and a list of STUN
/// [`Attribute`](crate::stun::attribute::Attribute)s.
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
    /// Create a new [`Message`] with the provided [`MessageType`] and transaction ID
    ///
    /// Note you probably want to use one of the other helper constructors instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// let message = Message::new(mtype, 0);
    /// assert!(message.has_class(MessageClass::Indication));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn new(mtype: MessageType, transaction: u128) -> Self {
        Self {
            msg_type: mtype,
            transaction,
            attributes: vec![],
        }
    }

    /// Create a new request [`Message`] of the provided method
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert!(message.has_class(MessageClass::Request));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn new_request(method: u16) -> Self {
        Message::new(
            MessageType::from_class_method(MessageClass::Request, method),
            Message::generate_transaction(),
        )
    }

    /// Create a new success [`Message`] response from the provided request
    ///
    /// # Panics
    ///
    /// When a non-request [`Message`] is passed as the original input [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// let success = Message::new_success(&message);
    /// assert!(success.has_class(MessageClass::Success));
    /// assert!(success.has_method(BINDING));
    /// ```
    pub fn new_success(orig: &Message) -> Self {
        if !orig.has_class(MessageClass::Request) {
            panic!(
                "A success response message was attempted to be created from a non-request message"
            );
        }
        Message::new(
            MessageType::from_class_method(MessageClass::Success, orig.method()),
            orig.transaction_id(),
        )
    }

    /// Create a new error [`Message`] response from the provided request
    ///
    /// # Panics
    ///
    /// When a non-request [`Message`] is passed as the original input [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// let success = Message::new_error(&message);
    /// assert!(success.has_class(MessageClass::Error));
    /// assert!(success.has_method(BINDING));
    /// ```
    pub fn new_error(orig: &Message) -> Self {
        Message::new(
            MessageType::from_class_method(MessageClass::Error, orig.method()),
            orig.transaction_id(),
        )
    }

    /// Retrieve the [`MessageType`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert!(message.get_type().has_class(MessageClass::Request));
    /// assert!(message.get_type().has_method(BINDING));
    /// ```
    pub fn get_type(&self) -> MessageType {
        self.msg_type
    }

    /// Retrieve the [`MessageClass`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert_eq!(message.class(), MessageClass::Request);
    /// ```
    pub fn class(&self) -> MessageClass {
        self.get_type().class()
    }

    /// Returns whether the [`Message`] is of the specified [`MessageClass`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert!(message.has_class(MessageClass::Request));
    /// ```
    pub fn has_class(&self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    /// Returns whether the [`Message`] is a response
    ///
    /// This means that the [`Message`] has a class of either success or error
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert_eq!(message.is_response(), false);
    ///
    /// let error = Message::new_error(&message);
    /// assert_eq!(error.is_response(), true);
    ///
    /// let success = Message::new_success(&message);
    /// assert_eq!(success.is_response(), true);
    /// ```
    pub fn is_response(&self) -> bool {
        self.class().is_response()
    }

    /// Retrieves the method of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert_eq!(message.method(), BINDING);
    /// ```
    pub fn method(&self) -> u16 {
        self.get_type().method()
    }

    /// Returns whether the [`Message`] is of the specified method
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::new_request(BINDING);
    /// assert_eq!(message.has_method(BINDING), true);
    /// assert_eq!(message.has_method(0), false);
    /// ```
    pub fn has_method(&self, method: u16) -> bool {
        self.method() == method
    }

    /// Retrieves the 96-bit transaction ID of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    /// let transaction_id = Message::generate_transaction();
    /// let message = Message::new(mtype, transaction_id);
    /// assert_eq!(message.transaction_id(), transaction_id);
    /// ```
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

    /// Validates the MESSAGE_INTEGRITY attribute with the provided credentials
    ///
    /// The Original data that was used to construct this [`Message`] must be provided in order
    /// to successfully validate the [`Message`]
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

    /// Adds MESSAGE_INTEGRITY attribute to a [`Message`] using the provided credentials
    ///
    /// # Errors
    ///
    /// - If a MESSAGE_INTEGRITY attribute is already present
    /// - If a FINGERPRINT attribute is already present
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING,
    ///     MessageIntegrityCredentials, ShortTermCredentials};
    /// let mut message = Message::new_request(BINDING);
    /// let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials { password:
    ///     "pass".to_owned() });
    /// assert!(message.add_message_integrity(&credentials).is_ok());
    /// let data = message.to_bytes();
    /// assert!(message.validate_integrity(&data, &credentials).is_ok());
    ///
    /// // duplicate MESSAGE_INTEGRITY is an error
    /// assert!(message.add_message_integrity(&credentials).is_err());
    /// ```
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

    /// Adds FINGERPRINT attribute to a [`Message`]
    ///
    /// # Errors
    ///
    /// - If a FINGERPRINT attribute is already present
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::new_request(BINDING);
    /// assert!(message.add_fingerprint().is_ok());
    ///
    /// // duplicate FINGERPRINT is an error
    /// assert!(message.add_fingerprint().is_err());
    /// ```
    pub fn add_fingerprint(&mut self) -> Result<(), AgentError> {
        if self.get_attribute(FINGERPRINT).is_some() {
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
    /// `Attribute.  Attempting to add multiple `Atribute`s of the same `AttributeType` will fail.
    ///
    /// # Errors
    ///
    /// - if a MESSAGE_INTEGRITY attribute is attempted to be added.  Use
    /// `Message::add_message_integrity` instead.
    /// - if a FINGERPRINT attribute is attempted to be added. Use
    /// `Message::add_fingerprint` instead.
    /// - If the attribute already exists within the message
    /// - If attempting to add attributes when MESSAGE_INTEGRITY or FINGERPRINT atributes already
    /// exist
    ///
    /// # Examples
    ///
    /// Add an `Attribute`
    ///
    /// ```
    /// # use librice::stun::attribute::RawAttribute;
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::new_request(BINDING);
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
    /// let mut message = Message::new_request(BINDING);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr.clone()).is_ok());
    /// assert_eq!(*message.get_attribute(1.into()).unwrap(), attr);
    /// ```
    pub fn get_attribute(&self, atype: AttributeType) -> Option<&RawAttribute> {
        self.attributes.iter().find(|attr| attr.get_type() == atype)
    }

    /// Returns an iterator over the attributes in the [`Message`].
    pub fn iter_attributes(&self) -> impl Iterator<Item = &RawAttribute> {
        self.attributes.iter()
    }

    /// Check that a message [`Message`] only contains required attributes that are supported and
    /// have at least some set of required attributes.  Returns an appropriate error message on
    /// failure to meet these requirements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::attribute::*;
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// # use std::convert::TryInto;
    /// let mut message = Message::new_request(BINDING);
    /// // If nothing is required, no error response is returned
    /// assert!(matches!(Message::check_attribute_types(&message, &[], &[]), None));
    ///
    /// // If an atttribute is required that is not in the message, then and error response message
    /// // is generated
    /// let error_msg = Message::check_attribute_types(
    ///     &message,
    ///     &[],
    ///     &[SOFTWARE]
    /// ).unwrap();
    /// assert!(error_msg.has_attribute(ERROR_CODE));
    /// let error_code : ErrorCode =
    ///     error_msg.get_attribute(ERROR_CODE).unwrap().try_into().unwrap();
    /// assert_eq!(error_code.code(), 400);
    ///
    /// message.add_attribute(Username::new("user").unwrap().into());
    /// // If a Username is in the message but is not advertised as supported then an
    /// // 'UNKNOWN-ATTRIBUTES' error response is returned
    /// let error_msg = Message::check_attribute_types(&message, &[], &[]).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ERROR_CODE));
    /// let error_code : ErrorCode =
    ///     error_msg.get_attribute(ERROR_CODE).unwrap().try_into().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// assert!(error_msg.has_attribute(UNKNOWN_ATTRIBUTES));
    /// ```
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
        let has_required_attribute_missing = required_in_msg
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

    /// Generate an error message with an [`ERROR_CODE`] attribute signalling 'Unknown Attribute'
    /// and an [`UNKNOWN_ATTRIBUTES`] attribute containing the attributes that are unknown.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, BINDING};
    /// # use librice::stun::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::new_request(BINDING);
    /// let error_msg = Message::unknown_attributes(&msg, &[USERNAME]).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ERROR_CODE));
    /// let error_code : ErrorCode =
    ///     error_msg.get_attribute(ERROR_CODE).unwrap().try_into().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// let unknown : UnknownAttributes =
    ///     error_msg.get_attribute(UNKNOWN_ATTRIBUTES).unwrap().try_into().unwrap();
    /// assert!(unknown.has_attribute(USERNAME));
    /// ```
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

    /// Generate an error message with an [`ERROR_CODE`] attribute signalling a 'Bad Request'
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::stun::message::{Message, MessageType, MessageClass, BINDING};
    /// # use librice::stun::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::new_request(BINDING);
    /// let error_msg = Message::bad_request(&msg).unwrap();
    /// assert!(error_msg.has_attribute(ERROR_CODE));
    /// let error_code : ErrorCode =
    ///     error_msg.get_attribute(ERROR_CODE).unwrap().try_into().unwrap();
    /// assert_eq!(error_code.code(), 400);
    /// ```
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
        let src = Message::new_request(BINDING);
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
        let src = Message::new_request(BINDING);
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
        let mut msg = Message::new_request(BINDING);
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
        let mut msg = Message::new_request(BINDING);
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
        let mut src = Message::new_request(BINDING);
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

    #[test]
    fn rfc5769_vector1() {
        // https://tools.ietf.org/html/rfc5769#section-2.1
        let data = vec![
            0x00, 0x01, 0x00, 0x58, // Request type message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // } Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x10, // SOFTWARE header
            0x53, 0x54, 0x55, 0x4e, //   }
            0x20, 0x74, 0x65, 0x73, //   }  User-agent...
            0x74, 0x20, 0x63, 0x6c, //   }  ...name
            0x69, 0x65, 0x6e, 0x74, //   }
            0x00, 0x24, 0x00, 0x04, // PRIORITY header
            0x6e, 0x00, 0x01, 0xff, //   PRIORITY value
            0x80, 0x29, 0x00, 0x08, // ICE_CONTROLLED header
            0x93, 0x2f, 0xf9, 0xb1, //   Pseudo random number
            0x51, 0x26, 0x3b, 0x36, //   ... for tie breaker
            0x00, 0x06, 0x00, 0x09, // USERNAME header
            0x65, 0x76, 0x74, 0x6a, //   Username value
            0x3a, 0x68, 0x36, 0x76, //   (9 bytes)
            0x59, 0x20, 0x20, 0x20, //   (3 bytes padding)
            0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY header
            0x9a, 0xea, 0xa7, 0x0c, //   }
            0xbf, 0xd8, 0xcb, 0x56, //   }
            0x78, 0x1e, 0xf2, 0xb5, //   } HMAC-SHA1 fingerprint
            0xb2, 0xd3, 0xf2, 0x49, //   }
            0xc1, 0xb5, 0x71, 0xa2, //   }
            0x80, 0x28, 0x00, 0x04, // FINGERPRINT header
            0xe5, 0x7a, 0x3b, 0xcf, //   CRC32 fingerprint
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Request));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae);

        // SOFTWARE
        assert!(msg.has_attribute(SOFTWARE));
        let raw = msg.get_attribute(SOFTWARE).unwrap();
        assert!(matches!(Software::try_from(raw), Ok(_)));
        let software = Software::try_from(raw).unwrap();
        assert_eq!(software.software(), "STUN test client");

        // PRIORITY
        assert!(msg.has_attribute(PRIORITY));
        let raw = msg.get_attribute(PRIORITY).unwrap();
        assert!(matches!(Priority::try_from(raw), Ok(_)));
        let priority = Priority::try_from(raw).unwrap();
        assert_eq!(priority.priority(), 0x6e0001ff);

        // USERNAME
        assert!(msg.has_attribute(USERNAME));
        let raw = msg.get_attribute(USERNAME).unwrap();
        assert!(matches!(Username::try_from(raw), Ok(_)));
        let username = Username::try_from(raw).unwrap();
        assert_eq!(username.username(), "evtj:h6vY");

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        assert!(matches!(
            msg.validate_integrity(&data, &credentials),
            Ok(())
        ));

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(FINGERPRINT));

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = msg.to_bytes();
        // match the padding bytes with the original
        msg_data[73] = 0x20;
        msg_data[74] = 0x20;
        msg_data[75] = 0x20;
        assert_eq!(msg_data, data);
    }

    #[test]
    fn rfc5769_vector2() {
        // https://tools.ietf.org/html/rfc5769#section-2.2
        let data = vec![
            0x01, 0x01, 0x00, 0x3c, // Response type message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x0b, // SOFTWARE attribute header
            0x74, 0x65, 0x73, 0x74, //   }
            0x20, 0x76, 0x65, 0x63, //   }  UTF-8 server name
            0x74, 0x6f, 0x72, 0x20, //   }
            0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS attribute header
            0x00, 0x01, 0xa1, 0x47, //   Address family (IPv4) and xor'd mapped port number
            0xe1, 0x12, 0xa6, 0x43, //   Xor'd mapped IPv4 address
            0x00, 0x08, 0x00, 0x14, //   MESSAGE-INTEGRITY attribute header
            0x2b, 0x91, 0xf5, 0x99, // }
            0xfd, 0x9e, 0x90, 0xc3, // }
            0x8c, 0x74, 0x89, 0xf9, // }  HMAC-SHA1 fingerprint
            0x2a, 0xf9, 0xba, 0x53, // }
            0xf0, 0x6b, 0xe7, 0xd7, // }
            0x80, 0x28, 0x00, 0x04, //  FINGERPRINT attribute header
            0xc0, 0x7d, 0x4c, 0x96, //  CRC32 fingerprint
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Success));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae);

        // SOFTWARE
        assert!(msg.has_attribute(SOFTWARE));
        let raw = msg.get_attribute(SOFTWARE).unwrap();
        assert!(matches!(Software::try_from(raw), Ok(_)));
        let software = Software::try_from(raw).unwrap();
        assert_eq!(software.software(), "test vector");

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XOR_MAPPED_ADDRESS));
        let raw = msg.get_attribute(XOR_MAPPED_ADDRESS).unwrap();
        assert!(matches!(XorMappedAddress::try_from(raw), Ok(_)));
        let xor_mapped_addres = XorMappedAddress::try_from(raw).unwrap();
        assert_eq!(
            xor_mapped_addres.addr(msg.transaction_id()),
            "192.0.2.1:32853".parse().unwrap()
        );

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        assert!(matches!(
            msg.validate_integrity(&data, &credentials),
            Ok(())
        ));

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(FINGERPRINT));

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = msg.to_bytes();
        // match the padding bytes with the original
        msg_data[35] = 0x20;
        assert_eq!(msg_data, data);
    }

    #[test]
    fn rfc5769_vector3() {
        // https://tools.ietf.org/html/rfc5769#section-2.3
        let data = vec![
            0x01, 0x01, 0x00, 0x48, // Response type and message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x0b, //    SOFTWARE attribute header
            0x74, 0x65, 0x73, 0x74, // }
            0x20, 0x76, 0x65, 0x63, // }  UTF-8 server name
            0x74, 0x6f, 0x72, 0x20, // }
            0x00, 0x20, 0x00, 0x14, //    XOR-MAPPED-ADDRESS attribute header
            0x00, 0x02, 0xa1, 0x47, //    Address family (IPv6) and xor'd mapped port number
            0x01, 0x13, 0xa9, 0xfa, // }
            0xa5, 0xd3, 0xf1, 0x79, // }  Xor'd mapped IPv6 address
            0xbc, 0x25, 0xf4, 0xb5, // }
            0xbe, 0xd2, 0xb9, 0xd9, // }
            0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
            0xa3, 0x82, 0x95, 0x4e, // }
            0x4b, 0xe6, 0x7b, 0xf1, // }
            0x17, 0x84, 0xc9, 0x7c, // }  HMAC-SHA1 fingerprint
            0x82, 0x92, 0xc2, 0x75, // }
            0xbf, 0xe3, 0xed, 0x41, // }
            0x80, 0x28, 0x00, 0x04, //    FINGERPRINT attribute header
            0xc8, 0xfb, 0x0b, 0x4c, //    CRC32 fingerprint
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Success));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae);

        // SOFTWARE
        assert!(msg.has_attribute(SOFTWARE));
        let raw = msg.get_attribute(SOFTWARE).unwrap();
        assert!(matches!(Software::try_from(raw), Ok(_)));
        let software = Software::try_from(raw).unwrap();
        assert_eq!(software.software(), "test vector");

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XOR_MAPPED_ADDRESS));
        let raw = msg.get_attribute(XOR_MAPPED_ADDRESS).unwrap();
        assert!(matches!(XorMappedAddress::try_from(raw), Ok(_)));
        let xor_mapped_addres = XorMappedAddress::try_from(raw).unwrap();
        assert_eq!(
            xor_mapped_addres.addr(msg.transaction_id()),
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap()
        );

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        assert!(matches!(
            msg.validate_integrity(&data, &credentials),
            Ok(())
        ));

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(FINGERPRINT));

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = msg.to_bytes();
        // match the padding bytes with the original
        msg_data[35] = 0x20;
        assert_eq!(msg_data, data);
    }

    #[test]
    fn rfc5769_vector4() {
        // https://tools.ietf.org/html/rfc5769#section-2.4
        let data = vec![
            0x00, 0x01, 0x00, 0x60, //    Request type and message length
            0x21, 0x12, 0xa4, 0x42, //    Magic cookie
            0x78, 0xad, 0x34, 0x33, // }
            0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
            0x29, 0xda, 0x41, 0x2e, // }
            0x00, 0x06, 0x00, 0x12, //    USERNAME attribute header
            0xe3, 0x83, 0x9e, 0xe3, // }
            0x83, 0x88, 0xe3, 0x83, // }
            0xaa, 0xe3, 0x83, 0x83, // }  Username value (18 bytes) and padding (2 bytes)
            0xe3, 0x82, 0xaf, 0xe3, // }
            0x82, 0xb9, 0x00, 0x00, // }
            0x00, 0x15, 0x00, 0x1c, //    NONCE attribute header
            0x66, 0x2f, 0x2f, 0x34, // }
            0x39, 0x39, 0x6b, 0x39, // }
            0x35, 0x34, 0x64, 0x36, // }
            0x4f, 0x4c, 0x33, 0x34, // }  Nonce value
            0x6f, 0x4c, 0x39, 0x46, // }
            0x53, 0x54, 0x76, 0x79, // }
            0x36, 0x34, 0x73, 0x41, // }
            0x00, 0x14, 0x00, 0x0b, //    REALM attribute header
            0x65, 0x78, 0x61, 0x6d, // }
            0x70, 0x6c, 0x65, 0x2e, // }  Realm value (11 bytes) and padding (1 byte)
            0x6f, 0x72, 0x67, 0x00, // }
            0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
            0xf6, 0x70, 0x24, 0x65, // }
            0x6d, 0xd6, 0x4a, 0x3e, // }
            0x02, 0xb8, 0xe0, 0x71, // }  HMAC-SHA1 fingerprint
            0x2e, 0x85, 0xc9, 0xa2, // }
            0x8c, 0xa8, 0x96, 0x66, // }
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Request));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0x78ad_3433_c6ad_72c0_29da_412e);

        let long_term = LongTermCredentials {
            username: "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}".to_owned(),
            password: "The\u{00AD}M\u{00AA}tr\u{2168}".to_owned(),
            nonce: "f//499k954d6OL34oL9FSTvy64sA".to_owned(),
        };
        // USERNAME
        assert!(msg.has_attribute(USERNAME));
        let raw = msg.get_attribute(USERNAME).unwrap();
        assert!(matches!(Username::try_from(raw), Ok(_)));
        let username = Username::try_from(raw).unwrap();
        assert_eq!(username.username(), &long_term.username);

        // NONCE
        /* XXX: not currently implemented
        assert!(msg.has_attribute(NONCE));
        let raw = msg.get_attribute(NONCE).unwrap();
        assert!(matches!(Nonce::try_from(raw), Ok(_)));
        let nonce = Nonce::try_from(raw).unwrap();
        assert_eq!(nonce., &long_term.username);
        */

        // MESSAGE_INTEGRITY
        /* XXX: the password needs SASLPrep-ing to be useful here
        let credentials = MessageIntegrityCredentials::LongTerm(long_term);
        assert!(matches!(msg.validate_integrity(&data, &credentials), Ok(())));
        */

        assert_eq!(msg.to_bytes(), data);
    }
}
