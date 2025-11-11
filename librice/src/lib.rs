// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # librice
//!
//! An async implementation based on [rice-proto] using the [rice-c] bindings.
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
//! - [ ] [RFC6062](https://tools.ietf.org/html/rfc6062):
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
//! ## Building
//!
//! `librice` has the same build requirements as [rice-c] and the crate level documentation for
//! [rice-c] provides guidelines on how to build [rice-c] and projects that depend on [rice-c].
//!
//! [RFC8445]: <https://tools.ietf.org/html/rfc8445>
//! [rice-proto]: <https://docs.rs/rice-proto>
//! [rice-c]: <https://docs.rs/rice-c>

pub mod agent;
pub mod component;
mod gathering;
pub mod runtime;
pub mod socket;
pub mod stream;
mod utils;

pub use rice_c::candidate;
pub use rice_c::random_string;

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    static TRACING: Once = Once::new();

    pub fn test_init_log() {
        TRACING.call_once(|| {
            let level_filter = std::env::var("RICE_LOG")
                .or(std::env::var("RUST_LOG"))
                .ok()
                .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
                .unwrap_or(
                    tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR),
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
            tracing::subscriber::set_global_default(registry).unwrap();
        });
    }

    #[cfg(feature = "runtime-tokio")]
    pub fn tokio_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
}
