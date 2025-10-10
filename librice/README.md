[![Chat](https://img.shields.io/matrix/librice-general:matrix.org?logo=matrix)](https://matrix.to/#/#librice-general:matrix.org)
[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice.svg)](https://crates.io/crates/librice)
[![docs.rs](https://docs.rs/librice/badge.svg)](https://docs.rs/librice)

# librice

Repository containing an async implementation of the ICE (RFC8445) protocol
written in the [Rust programming language](https://www.rust-lang.org/).
This async implementation is based on the sans-IO crate `rice-proto` in
the same repository.  See the [rice-proto
README](https://github.com/ystreet/librice/tree/main/rice-proto) for some
details as to why use the sans-IO design.

## Current status

The current status is that there is enough of the implementation to sucessfully
communicate with STUN/TURN servers and/or a browser (Chrome or Firefox) in a WebRTC
scenario. The STUN implementation is relatively mature. More work is needed on
the ICE layer for efficiency and API experience. Initial TURN support has been
implemented and some TURN-related RFCs are currently in progress. Supporting
more scenarios is part of the near and long term future roadmap.

## Relevant standards

 - [x] [RFC5245](https://tools.ietf.org/html/rfc5245):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal for Offer/Answer Protocols
 - [x] [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [x] [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [x] [RFC5769](https://tools.ietf.org/html/rfc5769):
   Test Vectors for Session Traversal Utilities for NAT (STUN)
 - [ ] [RFC6062](https://tools.ietf.org/html/rfc6062):
   Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
 - [x] [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [x] [RFC6544](https://tools.ietf.org/html/rfc6544):
   TCP Candidates with Interactive Connectivity Establishment (ICE)
 - [ ] [RFC7675](https://tools.ietf.org/html/rfc7675):
   Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
 - [x] [RFC8445](https://tools.ietf.org/html/rfc8445):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal
 - [x] [RFC8489](https://tools.ietf.org/html/rfc8489):
   Session Traversal Utilities for NAT (STUN)
 - [x] [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [x] [RFC8838](https://tools.ietf.org/html/rfc8838):
   Trickle ICE: Incremental Provisioning of Candidates for the Interactive
   Connectivity Establishment (ICE) Protocol

## TODO

- RFC6062
- RFC7675

## Building

`librice` depends on `rice-c` and thus has the same build requirements as
outlined in [its README](https://github.com/ystreet/librice/tree/main/rice-c).

Specifically, that either `cargo-c` must be installed if building from source
using the `librice` repository for development, or the the `rice-proto` C API
must be available in the build environment through pkg-config.
