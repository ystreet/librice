// Copyright (C) 2023 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Attributes for TURN
//!
//! Provides for generating, parsing and manipulating STUN attributes as specified as used in TURN
//! [RFC5766].
//!
//! [RFC5766]: https://tools.ietf.org/html/rfc5766

use std::net::SocketAddr;

use byteorder::{BigEndian, ByteOrder};

use crate::stun::{attribute::*, message::TransactionId};

pub const CHANNEL_NUMBER: AttributeType = AttributeType(0x000C);
pub const LIFETIME: AttributeType = AttributeType(0x000D);
// 0x0010 is reserved, was BANDWIDTH
pub const XOR_PEER_ADDRESS: AttributeType = AttributeType(0x0012);
pub const DATA: AttributeType = AttributeType(0x0013);
pub const XOR_RELAYED_ADDRESS: AttributeType = AttributeType(0x0016);
pub const REQUESTED_ADDRESS_FAMILY: AttributeType = AttributeType(0x0017);
pub const EVEN_PORT: AttributeType = AttributeType(0x0018);
pub const REQUESTED_TRANSPORT: AttributeType = AttributeType(0x0019);
pub const DONT_FRAGMENT: AttributeType = AttributeType(0x001A);
// 0x0021 is reserved, was TIMER-VAL
pub const RESERVATION_TOKEN: AttributeType = AttributeType(0x0022);

pub const ADDITIONAL_ADDRESS_FAMILY: AttributeType = AttributeType(0x8000);
pub const ADDRESS_ERROR_CODE: AttributeType = AttributeType(0x8001);
pub const ICMP: AttributeType = AttributeType(0x8004);

/// The channel number [`Attribute`]
#[derive(Debug, Clone)]
pub struct ChannelNumber {
    channel: u16,
}
impl Attribute for ChannelNumber {
    fn get_type(&self) -> AttributeType {
        CHANNEL_NUMBER
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u16(&mut buf[..2], self.channel);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != CHANNEL_NUMBER {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            channel: BigEndian::read_u16(&raw.value),
        })
    }
}

impl ChannelNumber {
    /// Create a new [`ChannelNumber`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let channel = ChannelNumber::new (42);
    /// assert_eq!(channel.channel(), 42);
    /// ```
    pub fn new(channel: u16) -> Self {
        Self { channel }
    }

    /// The channel number stored in a [`ChannelNuumber`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let channel = ChannelNumber::new (42);
    /// assert_eq!(channel.channel(), 42);
    /// ```
    pub fn channel(&self) -> u16 {
        self.channel
    }
}

impl std::fmt::Display for ChannelNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.channel)
    }
}
crate::stun::attribute::attr_from!(ChannelNumber);

/// The lifetime [`Attribute`]
#[derive(Debug, Clone)]
pub struct Lifetime {
    seconds: u32,
}
impl Attribute for Lifetime {
    fn get_type(&self) -> AttributeType {
        LIFETIME
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[..4], self.seconds);
        RawAttribute::new(self.get_type(), &buf)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != LIFETIME {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            seconds: BigEndian::read_u32(&raw.value),
        })
    }
}

impl Lifetime {
    /// Create a new [`Lifetime`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let lifetime = Lifetime::new (42);
    /// assert_eq!(lifetime.seconds(), 42);
    /// ```
    pub fn new(seconds: u32) -> Self {
        Self { seconds }
    }

    /// The number of seconds stored in a [`Lifetime`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let lifetime = Lifetime::new (42);
    /// assert_eq!(lifetime.seconds(), 42);
    /// ```
    pub fn seconds(&self) -> u32 {
        self.seconds
    }
}

impl std::fmt::Display for Lifetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.seconds)
    }
}
crate::stun::attribute::attr_from!(Lifetime);

/// The XorPeerAddress [`Attribute`]
#[derive(Debug, Clone)]
pub struct XorPeerAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: XorSocketAddr,
}
impl Attribute for XorPeerAddress {
    fn get_type(&self) -> AttributeType {
        XOR_PEER_ADDRESS
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }

    fn to_raw(&self) -> RawAttribute {
        self.addr.to_raw(self.get_type())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != XOR_PEER_ADDRESS {
            return Err(StunParseError::WrongImplementation);
        }
        Ok(Self {
            addr: XorSocketAddr::from_raw(raw)?,
        })
    }
}

impl XorPeerAddress {
    /// Create a new XorPeerAddress [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorPeerAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a XorPeerAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorPeerAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorPeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}
attr_from!(XorPeerAddress);

/// The Data [`Attribute`]
#[derive(Debug, Clone)]
pub struct Data {
    data: Vec<u8>,
}
impl Attribute for Data {
    fn get_type(&self) -> AttributeType {
        DATA
    }

    fn length(&self) -> u16 {
        self.data.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &self.data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != DATA {
            return Err(StunParseError::WrongImplementation);
        }
        Ok(Self {
            data: raw.value.clone(),
        })
    }
}

impl Data {
    /// Create a new Data [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let bytes = vec![0, 1, 2];
    /// let data = Data::new(&bytes);
    /// assert_eq!(data.data(), &bytes);
    /// ```
    pub fn new(data: &[u8]) -> Self {
        if data.len() > u16::MAX as usize {
            panic!(
                "Attempt made to create a Data attribute larger than {}",
                u16::MAX
            );
        }
        Self {
            data: data.to_vec(),
        }
    }

    /// Retrieve the address stored in a XorPeerAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let bytes = vec![0, 1, 2];
    /// let data = Data::new(&bytes);
    /// assert_eq!(data.data(), &bytes);
    /// ```
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: len:{}", self.get_type(), self.data.len())
    }
}
attr_from!(Data);

/// The RequestedAddressFamily [`Attribute`]
#[derive(Debug, Clone)]
pub struct RequestedAddressFamily {
    family: AddressFamily,
}
impl Attribute for RequestedAddressFamily {
    fn get_type(&self) -> AttributeType {
        REQUESTED_ADDRESS_FAMILY
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[self.family.to_byte(), 0, 0, 0])
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != REQUESTED_ADDRESS_FAMILY {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            family: AddressFamily::from_byte(raw.value[0])?,
        })
    }
}

impl RequestedAddressFamily {
    /// Create a new RequestedAddressFamily [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let family = RequestedAddressFamily::new(AddressFamily::IPV4);
    /// assert_eq!(family.family(), AddressFamily::IPV4);
    /// ```
    pub fn new(family: AddressFamily) -> Self {
        Self { family }
    }

    /// Retrieve the address stored in a XorPeerAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let family = RequestedAddressFamily::new(AddressFamily::IPV4);
    /// assert_eq!(family.family(), AddressFamily::IPV4);
    /// ```
    pub fn family(&self) -> AddressFamily {
        self.family
    }
}

impl std::fmt::Display for RequestedAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.family())
    }
}
attr_from!(RequestedAddressFamily);

/// The XorRelayedAddress [`Attribute`]
#[derive(Debug, Clone)]
pub struct XorRelayedAddress {
    addr: XorSocketAddr,
}
impl Attribute for XorRelayedAddress {
    fn get_type(&self) -> AttributeType {
        XOR_RELAYED_ADDRESS
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }

    fn to_raw(&self) -> RawAttribute {
        self.addr.to_raw(self.get_type())
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != XOR_RELAYED_ADDRESS {
            return Err(StunParseError::WrongImplementation);
        }
        Ok(Self {
            addr: XorSocketAddr::from_raw(raw)?,
        })
    }
}

impl XorRelayedAddress {
    /// Create a new XorRelayedAddress [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorRelayedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a XorPeerAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorRelayedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorRelayedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}
attr_from!(XorRelayedAddress);

/// The EvenPort [`Attribute`]
#[derive(Debug, Clone)]
pub struct EvenPort {
    bits: u8,
}
impl Attribute for EvenPort {
    fn get_type(&self) -> AttributeType {
        EVEN_PORT
    }

    fn length(&self) -> u16 {
        1
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[self.bits])
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != EVEN_PORT {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 1 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.is_empty() {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            bits: raw.value[0] & 0x80,
        })
    }
}

impl EvenPort {
    /// Create a new EvenPort [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let even_port = EvenPort::new(true);
    /// assert_eq!(even_port.requested(), true);
    /// ```
    pub fn new(request: bool) -> Self {
        let bits = if request { 0x80 } else { 0x00 };
        Self { bits }
    }

    /// Retrieve the address stored in a EvenPort
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let even_port = EvenPort::new(false);
    /// assert_eq!(even_port.requested(), false);
    /// ```
    pub fn requested(&self) -> bool {
        self.bits & 0x80 > 0
    }
}

impl std::fmt::Display for EvenPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.requested())
    }
}
attr_from!(EvenPort);

/// The RequestedTransport [`Attribute`]
#[derive(Debug, Clone)]
pub struct RequestedTransport {
    protocol: u8,
}
impl Attribute for RequestedTransport {
    fn get_type(&self) -> AttributeType {
        REQUESTED_TRANSPORT
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[self.protocol, 0, 0, 0])
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != REQUESTED_TRANSPORT {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            protocol: raw.value[0],
        })
    }
}

impl RequestedTransport {
    pub const UDP: u8 = 17;

    /// Create a new RequestedTransport [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let requested_transport = RequestedTransport::new(RequestedTransport::UDP);
    /// assert_eq!(requested_transport.protocol(), RequestedTransport::UDP);
    /// ```
    pub fn new(protocol: u8) -> Self {
        Self { protocol }
    }

    /// Retrieve the protocol stored in a RequestedTransport
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let requested_transport = RequestedTransport::new(RequestedTransport::UDP);
    /// assert_eq!(requested_transport.protocol(), RequestedTransport::UDP);
    /// ```
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
}

impl std::fmt::Display for RequestedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.protocol())
    }
}
attr_from!(RequestedTransport);

/// The DontFragment [`Attribute`]
#[derive(Default, Debug, Clone)]
pub struct DontFragment {}
impl Attribute for DontFragment {
    fn get_type(&self) -> AttributeType {
        DONT_FRAGMENT
    }

    fn length(&self) -> u16 {
        0
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[])
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != DONT_FRAGMENT {
            return Err(StunParseError::WrongImplementation);
        }
        if !raw.value.is_empty() {
            return Err(StunParseError::TooBig);
        }
        Ok(Self {})
    }
}

impl DontFragment {
    /// Create a new DontFragment [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let requested_transport = RequestedTransport::new(17);
    /// assert_eq!(requested_transport.protocol(), 17);
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl std::fmt::Display for DontFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}
attr_from!(DontFragment);

/// The ReservationToken [`Attribute`]
#[derive(Debug, Clone)]
pub struct ReservationToken {
    token: u64,
}
impl Attribute for ReservationToken {
    fn get_type(&self) -> AttributeType {
        RESERVATION_TOKEN
    }

    fn length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = vec![0; 8];
        BigEndian::write_u64(&mut data, self.token);
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != RESERVATION_TOKEN {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 8 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 8 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            token: BigEndian::read_u64(&raw.value),
        })
    }
}

impl ReservationToken {
    /// Create a new ReservationToken [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let token = ReservationToken::new(100);
    /// assert_eq!(token.token(), 100);
    /// ```
    pub fn new(token: u64) -> Self {
        Self { token }
    }

    /// Retrieve the token stored in a ReservationToken
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let token = ReservationToken::new(100);
    /// assert_eq!(token.token(), 100);
    /// ```
    pub fn token(&self) -> u64 {
        self.token
    }
}

impl std::fmt::Display for ReservationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x{:#x}", self.get_type(), self.token())
    }
}
attr_from!(ReservationToken);

/// The AdditionalAddressFamily [`Attribute`]
#[derive(Debug, Clone)]
pub struct AdditionalAddressFamily {
    family: AddressFamily,
}
impl Attribute for AdditionalAddressFamily {
    fn get_type(&self) -> AttributeType {
        ADDITIONAL_ADDRESS_FAMILY
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[self.family.to_byte(), 0, 0, 0])
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ADDITIONAL_ADDRESS_FAMILY {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 4 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 4 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            family: AddressFamily::from_byte(raw.value[0])?,
        })
    }
}

impl AdditionalAddressFamily {
    /// Create a new AdditionalAddressFamily [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let family = AdditionalAddressFamily::new(AddressFamily::IPV6).unwrap();
    /// assert_eq!(family.family(), AddressFamily::IPV6);
    /// ```
    pub fn new(family: AddressFamily) -> Result<Self, StunParseError> {
        if family != AddressFamily::IPV6 {
            return Err(StunParseError::InvalidData);
        }
        Ok(Self { family })
    }

    /// Retrieve the address stored in a XorPeerAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let family = AdditionalAddressFamily::new(AddressFamily::IPV6).unwrap();
    /// assert_eq!(family.family(), AddressFamily::IPV6);
    /// ```
    pub fn family(&self) -> AddressFamily {
        self.family
    }
}

impl std::fmt::Display for AdditionalAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.family())
    }
}
attr_from!(AdditionalAddressFamily);

/// The AddressErrorCode [`Attribute`]
#[derive(Debug, Clone)]
pub struct AddressErrorCode {
    family: AddressFamily,
    code: u16,
    reason: String,
}
impl Attribute for AddressErrorCode {
    fn get_type(&self) -> AttributeType {
        ADDRESS_ERROR_CODE
    }

    fn length(&self) -> u16 {
        4 + self.reason.len() as u16
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.length() as usize);
        data.push(self.family.to_byte());
        data.push(0u8);
        data.push((self.code / 100) as u8);
        data.push((self.code % 100) as u8);
        data.extend(self.reason.as_bytes());
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ADDRESS_ERROR_CODE {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() < 5 {
            return Err(StunParseError::NotEnoughData);
        }
        if raw.value.len() > 763 + 4 {
            return Err(StunParseError::TooBig);
        }
        let family = AddressFamily::from_byte(raw.value[0])?;
        let code_h = (raw.value[2] & 0x7) as u16;
        let code_tens = raw.value[3] as u16;
        if !(3..7).contains(&code_h) || code_tens > 99 {
            return Err(StunParseError::OutOfRange);
        }
        let code = code_h * 100 + code_tens;
        Ok(Self {
            family,
            code,
            reason: std::str::from_utf8(&raw.value[4..])
                .map_err(|_| StunParseError::InvalidData)?
                .to_owned(),
        })
    }
}

pub struct AddressErrorCodeBuilder<'reason> {
    family: AddressFamily,
    code: u16,
    reason: Option<&'reason str>,
}

impl<'reason> AddressErrorCodeBuilder<'reason> {
    fn new(family: AddressFamily, code: u16) -> Self {
        Self {
            family,
            code,
            reason: None,
        }
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
    pub fn build(self) -> Result<AddressErrorCode, StunParseError> {
        if !(300..700).contains(&self.code) {
            return Err(StunParseError::OutOfRange);
        }
        let reason = self
            .reason
            .unwrap_or_else(|| ErrorCode::default_reason_for_code(self.code))
            .to_owned();
        Ok(AddressErrorCode {
            family: self.family,
            code: self.code,
            reason,
        })
    }
}

impl AddressErrorCode {
    /// Create a builder for creating a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let error = AddressErrorCode::builder(AddressFamily::IPV6, 400).reason("bad error").build().unwrap();
    /// assert_eq!(error.code(), 400);
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn builder<'reason>(family: AddressFamily, code: u16) -> AddressErrorCodeBuilder<'reason> {
        AddressErrorCodeBuilder::new(family, code)
    }

    /// Create a new AddressErrorCode [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let err = AddressErrorCode::new(AddressFamily::IPV6, 440, "Not supported").unwrap();
    /// assert_eq!(err.code(), 440);
    /// ```
    pub fn new(
        family: AddressFamily,
        error_code: u16,
        reason: &str,
    ) -> Result<Self, StunParseError> {
        if !(300..700).contains(&error_code) {
            return Err(StunParseError::OutOfRange);
        }
        Ok(Self {
            family,
            code: error_code,
            reason: reason.to_string(),
        })
    }

    /// Retrieve the AddressFamily stored in a AddressErrorCode
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let err = AddressErrorCode::new(AddressFamily::IPV6, 440, "Not supported").unwrap();
    /// assert_eq!(err.family(), AddressFamily::IPV6);
    /// ```
    pub fn family(&self) -> AddressFamily {
        self.family
    }

    /// Retrieve the code stored in a AddressErrorCode
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let err = AddressErrorCode::new(AddressFamily::IPV6, 440, "Not supported").unwrap();
    /// assert_eq!(err.code(), 440);
    /// ```
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The error code reason string
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// # use librice::stun::attribute::AddressFamily;
    /// let error = AddressErrorCode::new (AddressFamily::IPV4, 400, "bad error").unwrap();
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for AddressErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.family())
    }
}
attr_from!(AddressErrorCode);

/// The Icmp [`Attribute`]
#[derive(Debug, Clone)]
pub struct Icmp {
    icmp_type: u8,
    icmp_code: u8,
    icmp_data: u32,
}
impl Attribute for Icmp {
    fn get_type(&self) -> AttributeType {
        ICMP
    }

    fn length(&self) -> u16 {
        8
    }

    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push(self.icmp_type);
        data.push(self.icmp_code);
        data.extend([0, 0, 0, 0]);
        BigEndian::write_u32(&mut data[4..], self.icmp_data);
        RawAttribute::new(self.get_type(), &data)
    }

    fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.header.atype != ICMP {
            return Err(StunParseError::WrongImplementation);
        }
        if raw.value.len() > 8 {
            return Err(StunParseError::TooBig);
        }
        if raw.value.len() < 8 {
            return Err(StunParseError::NotEnoughData);
        }
        Ok(Self {
            icmp_type: raw.value[2],
            icmp_code: raw.value[3],
            icmp_data: BigEndian::read_u32(&raw.value[4..]),
        })
    }
}

impl Icmp {
    /// Create a new Icmp [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let icmp = Icmp::new(2, 8, 0);
    /// assert_eq!(icmp.code(), 8);
    /// ```
    pub fn new(type_: u8, code: u8, data: u32) -> Self {
        Self {
            icmp_type: type_,
            icmp_code: code,
            icmp_data: data,
        }
    }

    /// Retrieve the type stored in a Icmp
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let icmp = Icmp::new(2, 8, 0);
    /// assert_eq!(icmp.icmp_type(), 2);
    /// ```
    pub fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Retrieve the code stored in a Icmp
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let icmp = Icmp::new(2, 8, 0);
    /// assert_eq!(icmp.code(), 8);
    /// ```
    pub fn code(&self) -> u8 {
        self.icmp_code
    }

    /// Retrieve the data stored in a Icmp
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::turn::attribute::*;
    /// let icmp = Icmp::new(2, 8, 0);
    /// assert_eq!(icmp.data(), 0);
    /// ```
    pub fn data(&self) -> u32 {
        self.icmp_data
    }
}

impl std::fmt::Display for Icmp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: T{} C{} D{}",
            self.get_type(),
            self.icmp_type,
            self.icmp_code,
            self.icmp_data
        )
    }
}
attr_from!(Icmp);

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn channel_number() {
        init();
        let c = ChannelNumber::new(6);
        assert_eq!(c.get_type(), CHANNEL_NUMBER);
        assert_eq!(c.channel(), 6);
        let raw: RawAttribute = c.into();
        assert_eq!(raw.get_type(), CHANNEL_NUMBER);
        let c2 = ChannelNumber::try_from(&raw).unwrap();
        assert_eq!(c2.get_type(), CHANNEL_NUMBER);
        assert_eq!(c2.channel(), 6);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ChannelNumber::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn lifetime() {
        init();
        let lifetime = Lifetime::new(600);
        assert_eq!(lifetime.get_type(), LIFETIME);
        assert_eq!(lifetime.seconds(), 600);
        let raw: RawAttribute = lifetime.into();
        assert_eq!(raw.get_type(), LIFETIME);
        let lifetime2 = Lifetime::try_from(&raw).unwrap();
        assert_eq!(lifetime2.get_type(), LIFETIME);
        assert_eq!(lifetime2.seconds(), 600);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Lifetime::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn xor_peer_address() {
        init();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorPeerAddress::new(*addr, transaction_id);
            assert_eq!(mapped.get_type(), XOR_PEER_ADDRESS);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.into();
            assert_eq!(raw.get_type(), XOR_PEER_ADDRESS);
            let mapped2 = XorPeerAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XOR_PEER_ADDRESS);
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorPeerAddress::try_from(
                    &RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::NotEnoughData)
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorPeerAddress::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
                Err(StunParseError::WrongImplementation)
            ));
        }
    }

    #[test]
    fn data() {
        init();
        let bytes = vec![0, 1, 2, 3, 4, 5];
        let data = Data::new(&bytes);
        assert_eq!(data.get_type(), DATA);
        assert_eq!(data.data(), &bytes);
        let raw: RawAttribute = data.into();
        assert_eq!(raw.get_type(), DATA);
        let data2 = Data::try_from(&raw).unwrap();
        assert_eq!(data2.get_type(), DATA);
        assert_eq!(data2.data(), &bytes);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Data::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn requested_address_family() {
        init();
        let family = RequestedAddressFamily::new(AddressFamily::IPV4);
        assert_eq!(family.get_type(), REQUESTED_ADDRESS_FAMILY);
        assert_eq!(family.family(), AddressFamily::IPV4);
        let raw: RawAttribute = family.into();
        assert_eq!(raw.get_type(), REQUESTED_ADDRESS_FAMILY);
        let family2 = RequestedAddressFamily::try_from(&raw).unwrap();
        assert_eq!(family2.get_type(), REQUESTED_ADDRESS_FAMILY);
        assert_eq!(family2.family(), AddressFamily::IPV4);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            RequestedAddressFamily::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn xor_relayed_address() {
        init();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorRelayedAddress::new(*addr, transaction_id);
            assert_eq!(mapped.get_type(), XOR_RELAYED_ADDRESS);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.into();
            assert_eq!(raw.get_type(), XOR_RELAYED_ADDRESS);
            let mapped2 = XorRelayedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XOR_RELAYED_ADDRESS);
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorRelayedAddress::try_from(
                    &RawAttribute::try_from(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::NotEnoughData)
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorRelayedAddress::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
                Err(StunParseError::WrongImplementation)
            ));
        }
    }

    #[test]
    fn even_port() {
        init();
        let even_port = EvenPort::new(true);
        assert_eq!(even_port.get_type(), EVEN_PORT);
        assert!(even_port.requested());
        let raw: RawAttribute = even_port.into();
        assert_eq!(raw.get_type(), EVEN_PORT);
        let even_port2 = EvenPort::try_from(&raw).unwrap();
        assert_eq!(even_port2.get_type(), EVEN_PORT);
        assert!(even_port2.requested());
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            EvenPort::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn requested_transport() {
        init();
        let trans = RequestedTransport::new(17);
        assert_eq!(trans.get_type(), REQUESTED_TRANSPORT);
        assert_eq!(trans.protocol(), 17);
        let raw: RawAttribute = trans.into();
        assert_eq!(raw.get_type(), REQUESTED_TRANSPORT);
        let trans2 = RequestedTransport::try_from(&raw).unwrap();
        assert_eq!(trans2.get_type(), REQUESTED_TRANSPORT);
        assert_eq!(trans2.protocol(), 17);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            RequestedTransport::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn dont_fragment() {
        init();
        let frag = DontFragment::new();
        assert_eq!(frag.get_type(), DONT_FRAGMENT);
        let raw: RawAttribute = frag.into();
        assert_eq!(raw.get_type(), DONT_FRAGMENT);
        let frag2 = DontFragment::try_from(&raw).unwrap();
        assert_eq!(frag2.get_type(), DONT_FRAGMENT);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            DontFragment::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn reservation_token() {
        init();
        let token = ReservationToken::new(200);
        assert_eq!(token.get_type(), RESERVATION_TOKEN);
        assert_eq!(token.token(), 200);
        let raw: RawAttribute = token.into();
        assert_eq!(raw.get_type(), RESERVATION_TOKEN);
        let token2 = ReservationToken::try_from(&raw).unwrap();
        assert_eq!(token2.get_type(), RESERVATION_TOKEN);
        assert_eq!(token2.token(), 200);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ReservationToken::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn additional_address_family() {
        init();
        let family = AdditionalAddressFamily::new(AddressFamily::IPV6).unwrap();
        assert_eq!(family.get_type(), ADDITIONAL_ADDRESS_FAMILY);
        assert_eq!(family.family(), AddressFamily::IPV6);
        let raw: RawAttribute = family.into();
        assert_eq!(raw.get_type(), ADDITIONAL_ADDRESS_FAMILY);
        let family2 = AdditionalAddressFamily::try_from(&raw).unwrap();
        assert_eq!(family2.get_type(), ADDITIONAL_ADDRESS_FAMILY);
        assert_eq!(family2.family(), AddressFamily::IPV6);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            AdditionalAddressFamily::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn address_error_code() {
        init();
        let codes = vec![300, 401, 699];
        for code in codes.iter().copied() {
            let reason = ErrorCode::default_reason_for_code(code);
            let err = AddressErrorCode::new(AddressFamily::IPV4, code, reason).unwrap();
            assert_eq!(err.get_type(), ADDRESS_ERROR_CODE);
            assert_eq!(err.family(), AddressFamily::IPV4);
            assert_eq!(err.code(), code);
            assert_eq!(err.reason(), reason);
            let raw: RawAttribute = err.into();
            assert_eq!(raw.get_type(), ADDRESS_ERROR_CODE);
            let err2 = AddressErrorCode::try_from(&raw).unwrap();
            assert_eq!(err2.get_type(), ADDRESS_ERROR_CODE);
            assert_eq!(err2.family(), AddressFamily::IPV4);
            assert_eq!(err2.code(), code);
            assert_eq!(err2.reason(), reason);
        }
        let code = codes[0];
        let reason = ErrorCode::default_reason_for_code(code);
        let err = AddressErrorCode::new(AddressFamily::IPV4, code, reason).unwrap();
        let raw: RawAttribute = err.into();
        // no data
        let mut data: Vec<_> = raw.clone().into();
        let len = 0;
        BigEndian::write_u16(&mut data[2..4], len as u16);
        assert!(matches!(
            AddressErrorCode::try_from(&RawAttribute::try_from(data[..len + 4].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            AddressErrorCode::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }

    #[test]
    fn icmp() {
        init();
        let err = Icmp::new(0, 2, 4);
        assert_eq!(err.get_type(), ICMP);
        assert_eq!(err.icmp_type(), 0);
        assert_eq!(err.code(), 2);
        assert_eq!(err.data(), 4);
        let raw: RawAttribute = err.into();
        assert_eq!(raw.get_type(), ICMP);
        let err2 = Icmp::try_from(&raw).unwrap();
        assert_eq!(err2.get_type(), ICMP);
        assert_eq!(err2.icmp_type(), 0);
        assert_eq!(err2.code(), 2);
        assert_eq!(err2.data(), 4);
        // no data
        let mut data: Vec<_> = raw.clone().into();
        let len = 0;
        BigEndian::write_u16(&mut data[2..4], len as u16);
        assert!(matches!(
            Icmp::try_from(&RawAttribute::try_from(data[..len + 4].as_ref()).unwrap()),
            Err(StunParseError::NotEnoughData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Icmp::try_from(&RawAttribute::try_from(data.as_ref()).unwrap()),
            Err(StunParseError::WrongImplementation)
        ));
    }
}
