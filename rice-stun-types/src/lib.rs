// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # rice-stun-types
//!
//! Implementation of ICE-relevant STUN attributes based on [stun-types] as specified in [RFC8445],
//! [RFC6544], and [RFC5245].
//!
//! ## Relevant standards
//!
//! - [x] [RFC5245]: Interactive Connectivity Establishment (ICE): A Protocol for Network Address
//!   Translator (NAT) Traversal for Offer/Answer Protocols
//! - [x] [RFC6544]: TCP Candidates with Interactive Connectivity Establishment (ICE)
//! - [x] [RFC8445]: Interactive Connectivity Establishment (ICE): A Protocol
//!   for Network Address Translator (NAT) Traversal
//!
//! [RFC5245]: <https://tools.ietf.org/html/rfc5245>
//! [RFC6544]: <https://tools.ietf.org/html/rfc6544>
//! [RFC8445]: <https://tools.ietf.org/html/rfc8445>
//! [stun-types]: https://docs.rs/stun-types

#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod attribute;

/// Initialize some debugging functionality of the library.
///
/// It is not required to call this function, however doing so allows debug functionality of
/// stun-types to print much more human readable descriptions of attributes and messages.
pub fn debug_init() {
    attribute::debug_init();
}

#[cfg(test)]
pub(crate) mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    pub fn test_init_log() -> DefaultGuard {
        debug_init();
        let level_filter = std::env::var("RICE_LOG")
            .or(std::env::var("RUST_LOG"))
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        tracing::subscriber::set_default(registry)
    }
}
