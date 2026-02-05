// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use byteorder::{BigEndian, ByteOrder};

use stun_types::attribute::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite, RawAttribute,
};
use stun_types::message::StunParseError;
use stun_types::prelude::*;

/// The IceControlled [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceControlled {
    tie_breaker: u64,
}

impl AttributeStaticType for IceControlled {
    const TYPE: AttributeType = AttributeType::new(0x8029);
}
impl Attribute for IceControlled {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}
impl AttributeWrite for IceControlled {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(IceControlled::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u64(&mut dest[4..12], self.tie_breaker);
    }
}

impl AttributeFromRaw<'_> for IceControlled {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for IceControlled {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
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
    /// # use rice_stun_types::attribute::*;
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
    /// # use rice_stun_types::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl core::fmt::Display for IceControlled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

/// The IceControlling [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceControlling {
    tie_breaker: u64,
}

impl AttributeStaticType for IceControlling {
    const TYPE: AttributeType = AttributeType::new(0x802A);
}

impl Attribute for IceControlling {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}

impl AttributeWrite for IceControlling {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(IceControlling::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u64(&mut dest[4..12], self.tie_breaker);
    }
}

impl AttributeFromRaw<'_> for IceControlling {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for IceControlling {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
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
    /// # use rice_stun_types::attribute::*;
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
    /// # use rice_stun_types::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl core::fmt::Display for IceControlling {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::trace;

    use std::vec::Vec;

    #[test]
    fn ice_controlling() {
        let _log = crate::tests::test_init_log();
        let tb = 100;
        let attr = IceControlling::new(tb);
        trace!("{attr}");
        assert_eq!(attr.get_type(), IceControlling::TYPE);
        assert_eq!(attr.tie_breaker(), tb);
        assert_eq!(attr.length(), 8);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), IceControlling::TYPE);
        let mapped2 = IceControlling::try_from(&raw).unwrap();
        assert_eq!(mapped2.tie_breaker(), tb);
        let mut data = [0; 12];
        mapped2.write_into(&mut data).unwrap();
        assert_eq!(data.as_ref(), &raw.to_bytes());
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 8,
                actual: 7
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn ice_controlled() {
        let _log = crate::tests::test_init_log();
        let tb = 100;
        let attr = IceControlled::new(tb);
        trace!("{attr}");
        assert_eq!(attr.tie_breaker(), tb);
        assert_eq!(attr.length(), 8);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), IceControlled::TYPE);
        let mapped2 = IceControlled::try_from(&raw).unwrap();
        assert_eq!(mapped2.tie_breaker(), tb);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 8,
                actual: 7
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
