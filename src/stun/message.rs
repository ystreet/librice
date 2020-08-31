// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::stun::attribute::{Attribute, RawAttribute, AttributeType};
use crate::agent::AgentError;

pub const MAGIC_COOKIE: u32 = 0x2112A442;

pub const BINDING: u16 = 0x0001;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    Success,
    Error,
}

impl MessageClass {
    pub fn is_response(self) -> bool {
        match self {
            MessageClass::Success | MessageClass::Error => true,
            _ => false,
        }
    }

    fn to_bits (self) -> u16 {
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
        write!(f, "MessageType(class: {:?}, method: {} ({:#x}))", self.class(), self.method(), self.method())
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

    pub fn method(self) -> u16 {
        self.0 & 0xf | (self.0 & 0xe0) >> 1 | (self.0 & 0x3e00) >> 2
    }

    pub fn from_class_method (class: MessageClass, method: u16) -> Self {
        let class_bits = MessageClass::to_bits (class);
        let method_bits = method & 0xf | (method & 0x70) << 1 | (method & 0xf80) << 2;
        // trace!("MessageType from class {:?} and method {:?} into {:?}", class, method,
        //     class_bits | method_bits);
        Self {
            0: class_bits | method_bits,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 2];
        BigEndian::write_u16 (&mut ret[0..2], self.0);
        ret
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self,AgentError> {
        let data = BigEndian::read_u16 (data);
        if data & 0xc000 != 0x0 {
            /* not a stun packet */
            error!("malformed {:?}", data);
            return Err(AgentError::Malformed);
        }
        Ok(Self {
            0: data,
        })
    }
}
impl From<MessageType> for Vec<u8> {
    fn from (f: MessageType) -> Self {
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
    transaction: u128,       /* 96-bits valid */
    attributes: Vec<RawAttribute>,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message(class: {:?}, method: {} ({:#x}), transaction: {:#x}, attributes: ", self.get_type().class(), self.get_type().method(), self.get_type().method(), self.transaction_id())?;
        if self.attributes.len() <= 0 {
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

fn padded_attr_size (attr: &dyn Attribute) -> usize {
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
            transaction: transaction,
            attributes: vec![],
        }
    }

    pub fn get_type(&self) -> MessageType {
        self.msg_type
    }

    pub fn transaction_id(&self) -> u128 {
        self.transaction
    }

    pub fn generate_transaction() -> u128 {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        rng.gen::<u128>() & 0x00000000_ffffffff_ffffffff_ffffffff
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
        let tid = (MAGIC_COOKIE as u128) << 96 | self.transaction & 0xffffffffffffffffffffffff;
        BigEndian::write_u128 (&mut ret[4..20], tid);
        BigEndian::write_u16 (&mut ret[2..4], attr_size as u16);
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
    pub fn from_bytes(data: &[u8]) -> Result<Self,AgentError> {
        if data.len() < 20 {
            // always at least 20 bytes long
            error!("not enough");
            return Err(AgentError::NotEnoughData)
        }
        let mtype = MessageType::from_bytes(data)?;
        let mlength = BigEndian::read_u16 (&data[2..]) as usize;
        if mlength + 20 > data.len() {
            // mlength + header
            error!("malformed {:?} {:?}", mlength + 20, data.len());
            return Err(AgentError::Malformed);
        }
        let tid = BigEndian::read_u128 (&data[4..]);
        let cookie = (tid >> 96) as u32;
        if cookie != MAGIC_COOKIE {
            error!("malformed {:?} != {:?} {:?}", MAGIC_COOKIE, cookie, tid >> 64);
            return Err(AgentError::Malformed);
        }
        let tid = tid & 0x00000000ffffffffffffffffffffffff;
        let mut data = &data[20..];
        let mut ret = Self::new (mtype, tid);
        while data.len() > 0 {
            let attr = RawAttribute::from_bytes(data)?;
            let padded_len = padded_attr_size(&attr);
            ret.attributes.push(attr);
            data = &data[padded_len..];
        }
        Ok(ret)
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
    pub fn add_attribute(&mut self, attr: RawAttribute) -> Result<(),AgentError> {
        if let Some(_) = self.get_attribute(attr.get_type()) {
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
}
impl From<Message> for Vec<u8> {
    fn from (f: Message) -> Self {
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
            let classes = vec![MessageClass::Request, MessageClass::Indication, MessageClass::Success, MessageClass::Error];
            for c in classes {
                let mtype = MessageType::from_class_method (c, m);
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
            let classes = vec![MessageClass::Request, MessageClass::Indication, MessageClass::Success, MessageClass::Error];
            for c in classes {
                let mtype = MessageType::from_class_method (c, m);
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
}
