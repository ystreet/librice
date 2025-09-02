// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use stun_types::attribute::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite, RawAttribute,
};
use stun_types::message::StunParseError;
use stun_types::prelude::*;

/// The UseCandidate [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseCandidate {}

impl AttributeStaticType for UseCandidate {
    const TYPE: AttributeType = AttributeType::new(0x0025);
}
impl Attribute for UseCandidate {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        0
    }
}
impl AttributeWrite for UseCandidate {
    fn to_raw(&self) -> RawAttribute<'_> {
        static BUF: [u8; 0] = [0; 0];
        RawAttribute::new(UseCandidate::TYPE, &BUF)
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
    }
}

impl AttributeFromRaw<'_> for UseCandidate {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for UseCandidate {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 0..=0)?;
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
    /// # use rice_stun_types::attribute::*;
    /// let _use_candidate = UseCandidate::new();
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl core::fmt::Display for UseCandidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::trace;

    #[test]
    fn use_candidate() {
        let _log = crate::tests::test_init_log();
        let use_candidate = UseCandidate::default();
        trace!("{use_candidate}");
        assert_eq!(use_candidate.length(), 0);
        let raw = RawAttribute::from(&use_candidate);
        trace!("{raw}");
        assert_eq!(raw.get_type(), UseCandidate::TYPE);
        let mapped2 = UseCandidate::try_from(&raw).unwrap();
        let mut data = [0; 4];
        mapped2.write_into(&mut data).unwrap();
        assert_eq!(data.as_ref(), &raw.to_bytes());
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        data[1] = 0;
        assert!(matches!(
            UseCandidate::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
