// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Attributes
//!
//! The list of STUN attributes relevant for ICE as specified in [RFC8445], [RFC6544], and [RFC5245].
//!
//! [RFC5245]: <https://tools.ietf.org/html/rfc5245>
//! [RFC6544]: <https://tools.ietf.org/html/rfc6544>
//! [RFC8445]: <https://tools.ietf.org/html/rfc8445>

mod priority;
pub use priority::Priority;
mod use_candidate;
pub use use_candidate::UseCandidate;
mod tie_breaker;
pub use tie_breaker::{IceControlled, IceControlling};

pub(super) fn debug_init() {
    #[cfg(feature = "std")]
    {
        use stun_types::prelude::*;

        stun_types::attribute_display!(IceControlled);
        IceControlled::TYPE.add_name("IceControlled");
        stun_types::attribute_display!(IceControlling);
        IceControlling::TYPE.add_name("IceControlling");
        stun_types::attribute_display!(Priority);
        Priority::TYPE.add_name("Priority");
        stun_types::attribute_display!(UseCandidate);
        UseCandidate::TYPE.add_name("UseCandidate");
    }
}
