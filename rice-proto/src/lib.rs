// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # rice-proto
//!
//! A sans-IO implementation of the ICE protocol as specified in [RFC8445].
//!
//! ## Why sans-io?
//!
//! A few reasons: reusability, testability, and composability.
//!
//! Without being bogged down in the details of how IO happens, the same sans-IO
//! implementation can be used without prescribing the IO pattern that an application
//! must follow. Instead, the application (or parent library) has much more freedom
//! in how bytes are transferred between peers. It is possible to use a sans-IO
//! library in either a synchronous environment or within an asynchronous runtime.
//!
//! A sans-IO design also allows easy testing of any specific state the sans-IO
//! implementation might find itself in. Combined with a comprehensive test-suite,
//! this provides assurance that the implementation behaves as expected under all
//! circumstances.
//!
//! For other examples of sans-IO implementations, take a look at:
//! - [stun-proto]: A sans-IO implementation of a STUN agent (client or server).
//! - [turn-proto]: A sans-IO implementation of a TURN client or server.
//! - <https://sans-io.readthedocs.io/>
//!
//! ## Relevant standards
//!
//! - [x] [RFC5245](https://tools.ietf.org/html/rfc5245):
//!   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
//!   Translator (NAT) Traversal for Offer/Answer Protocols
//! - [x] [RFC5389](https://tools.ietf.org/html/rfc5389):
//!   Session Traversal Utilities for NAT (STUN)
//! - [x] [RFC5766](https://tools.ietf.org/html/rfc5766):
//!   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
//!   Traversal Utilities for NAT (STUN)
//! - [x] [RFC5769](https://tools.ietf.org/html/rfc5769):
//!   Test Vectors for Session Traversal Utilities for NAT (STUN)
//! - [x] [RFC6062](https://tools.ietf.org/html/rfc6062):
//!   Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
//! - [x] [RFC6156](https://tools.ietf.org/html/rfc6156):
//!   Traversal Using Relays around NAT (TURN) Extension for IPv6
//! - [x] [RFC6544](https://tools.ietf.org/html/rfc6544):
//!   TCP Candidates with Interactive Connectivity Establishment (ICE)
//! - [ ] [RFC7675](https://tools.ietf.org/html/rfc7675):
//!   Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
//! - [x] [RFC8445]: Interactive Connectivity Establishment (ICE): A Protocol
//!   for Network Address Translator (NAT) Traversal
//! - [x] [RFC8489](https://tools.ietf.org/html/rfc8489):
//!   Session Traversal Utilities for NAT (STUN)
//! - [x] [RFC8656](https://tools.ietf.org/html/rfc8656):
//!   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
//!   Traversal Utilities for NAT (STUN)
//! - [x] [RFC8838](https://tools.ietf.org/html/rfc8838):
//!   Trickle ICE: Incremental Provisioning of Candidates for the Interactive
//!   Connectivity Establishment (ICE) Protocol
//!
//! ## Building a C library
//!
//! `rice-proto` uses [cargo-c] to build and install a compatible C library, headers and
//! pkg-config file.
//!
//! Once [cargo-c] has been installed (e.g. with `cargo install cargo-c`), then installation of
//! `rice-proto` can be achieved using:
//!
//! ```sh
//! cargo install cinstall --prefix $PREFIX
//! ```
//!
//! and can be used by any build sytem that can retrieve compilation flags from `pkg-config` files.
//!
//! [cargo-c]: https://crates.io/crates/cargo-c
//! [RFC8445]: <https://tools.ietf.org/html/rfc8445>
//! [stun-proto]: https://docs.rs/stun-proto
//! [turn-proto]: https://docs.rs/turn-proto

#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod agent;
pub mod candidate;
pub mod component;
mod conncheck;
mod gathering;
mod rand;
pub mod stream;
mod tcp;
pub mod turn;

#[cfg(feature = "capi")]
pub mod capi;

pub use stun_proto::types::AddressFamily;

use crate::rand::generate_random_ice_string;

/// Allowed characters within username fragment and password values.
static ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

/// Generate a random sequence of characters suitable for username fragments and passwords.
pub fn random_string(len: usize) -> alloc::string::String {
    generate_random_ice_string(ALPHABET.as_bytes(), len)
}

#[cfg(test)]
pub(crate) mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    pub fn test_init_log() -> DefaultGuard {
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
