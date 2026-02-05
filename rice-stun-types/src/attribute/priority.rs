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

/// The Priority [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priority {
    priority: u32,
}

impl AttributeStaticType for Priority {
    const TYPE: AttributeType = AttributeType::new(0x0024);
}
impl Attribute for Priority {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}
impl AttributeWrite for Priority {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], self.priority);
        RawAttribute::new(Priority::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u32(&mut dest[4..8], self.priority);
    }
}

impl AttributeFromRaw<'_> for Priority {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Priority {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
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
    /// # use rice_stun_types::attribute::*;
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
    /// # use rice_stun_types::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl core::fmt::Display for Priority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::trace;

    use std::vec::Vec;

    #[test]
    fn priority() {
        let _log = crate::tests::test_init_log();
        let val = 100;
        let priority = Priority::new(val);
        trace!("{priority}");
        assert_eq!(priority.priority(), val);
        assert_eq!(priority.length(), 4);
        let raw = RawAttribute::from(&priority);
        trace!("{raw}");
        assert_eq!(raw.get_type(), Priority::TYPE);
        let mapped2 = Priority::try_from(&raw).unwrap();
        assert_eq!(mapped2.priority(), val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Priority::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Priority::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
