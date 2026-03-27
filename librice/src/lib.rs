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
//! ## Building
//!
//! `librice` has the same build requirements as [rice-c] and the crate level documentation for
//! [rice-c] provides guidelines on how to build [rice-c] and projects that depend on [rice-c].
//!
//! [RFC8445]: <https://tools.ietf.org/html/rfc8445>
//! [rice-proto]: <https://docs.rs/rice-proto>
//! [rice-c]: <https://docs.rs/rice-c>
//!
//! ## Example
//!
//! ```
//! # #[cfg(feature = "runtime-tokio")]
//! # let runtime = tokio::runtime::Builder::new_current_thread()
//! #     .enable_all()
//! #     .build()
//! #     .unwrap();
//! # #[cfg(feature = "runtime-tokio")]
//! # let _runtime = runtime.enter();
//! # let task = async move {
//! use core::net::SocketAddr;
//! use futures::stream::StreamExt;
//! use librice::agent::{Agent, AgentMessage};
//! use librice::stream::Credentials;
//! use librice::candidate::{Candidate, CandidateType, TransportType};
//!
//! let agent = Agent::default();
//! // Configure the agent as you wish.
//! // e.g. add a stun server.
//! // agent.add_stun_server(TransportType::Udp, SocketAddr::new([192, 168, 0, 1], 3478));
//!
//! // Add a stream and component within that stream for data flow.
//! let stream = agent.add_stream();
//! let local_credentials = Credentials::new("luser", "lpass");
//! stream.set_local_credentials(&local_credentials);
//! let component = stream.add_component().unwrap();
//!
//! // At some point you will also need the remote credentials to be able to successfully connect
//! // with the peer. If trickle-ice, then this can occur during candidate gathering, otherwise,
//! // should occur before the remote candidates are added to the agent.
//! let remote_credentials = Credentials::new("ruser", "rpass");
//! stream.set_local_credentials(&remote_credentials);
//!
//! // Retrieve the receive end of a message queue that indicates gathering state, component state,
//! // and other such messages.
//! let mut messages = agent.messages();
//!
//! // start gathering candidates.
//! stream.gather_candidates().await.unwrap();
//!
//! while let Some(msg) = messages.next().await {
//!    match msg {
//!        AgentMessage::GatheredCandidate(stream, gathered) => {
//!             // based on local policy, you can choose to never add the locally gathered
//!             // candidate to the stream to avoid using a candidate for connectivity checks later.
//!             stream.add_local_gathered_candidate(gathered);
//!             // For trickle-ice handling, you would send the gathered candidate to the peer.
//!         }
//!         AgentMessage::GatheringComplete(component) => {
//!             // For non trickle-ice handling, if all relevant components in a stream have
//!             // completed gathering, you would retrieve the list of local candidates
//!             // and send that to the peer along with any other setup information required.
//!             println!("component {} has completed gathering", component.id());
//!             let stream = component.stream();
//!             for cand in stream.local_candidates() {
//!                 println!(
//!                     "stream {} has gathered local candidate {}",
//!                     stream.id(),
//!                     cand.to_sdp_string()
//!                 );
//!             }
//!             break;
//!         }
//!         AgentMessage::ComponentStateChange(component, new_state) => {
//!             println!("component {} has changed state to {new_state:?}", component.id());
//!         },
//!    }
//! }
//!
//! // On receiving remote candidates from the peer you would add them to the agent in order to
//! // start connectivity checks.
//! # let remote_host_addr = SocketAddr::new([127, 0, 0, 1].into(), 54321);
//! # let remote_candidate = Candidate::builder(
//! #     1, // component id
//! #     CandidateType::Host,
//! #     TransportType::Udp,
//! #     "0", // foundation
//! #     remote_host_addr.into(),
//! # )
//! # .build();
//! stream.add_remote_candidate(&remote_candidate);
//!
//! // Once the complete set of remote candidates have been received, then notify the agent of
//! // this.
//! stream.end_of_remote_candidates();
//!
//! // connectivity checks will progress and either a successful pair (the selected pair) will be
//! // found, or failure will be signaled for the component's connection state.
//! // while let Some(msg) = messages.next().await {
//! //     match msg {
//! //         ...
//! //     }
//! // }
//!
//! // once a selected pair is chosen, data can be received.
//! let recv = component.recv();
//! // and sent
//! component.send([1, 2, 3, 4].as_slice()).await;
//! # };
//! # #[cfg(feature = "runtime-smol")]
//! # smol::block_on(task);
//! # #[cfg(all(not(feature = "runtime-smol"), feature = "runtime-tokio"))]
//! # runtime.block_on(task);
//! ```

pub mod agent;
pub mod component;
mod gathering;
pub mod runtime;
// TODO: 0.5.0 remove pub
pub mod socket;
pub mod stream;
mod utils;

pub use rice_c::candidate;
pub use rice_c::random_string;
pub use rice_c::{Address, AddressFamily, Feature, IntegrityAlgorithm};

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

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

    #[cfg(feature = "runtime-tokio")]
    pub fn tokio_multi_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }
}
