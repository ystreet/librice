[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice.svg)](https://crates.io/crates/librice)
[![docs.rs](https://docs.rs/librice/badge.svg)](https://docs.rs/librice)

# librice

Repository containing an async implementation of the ICE (RFC8445) protocol
written in the [Rust programming language](https://www.rust-lang.org/).
This async implementation is based on the sans-IO crate `librice-proto` in
the same repository.  See the [librice-proto
README](https://github.com/ystreet/librice/tree/main/librice-proto) for some
details as to why use the sans-IO design.

## Warning

This still very much WIP code and everything is still subject to change.

## Current status

The current status is that there is enough of the implementation to sucessfully
transfer data with an external browser (Chrome and Firefox) in a WebRTC
scenario.  The STUN implementation is relatively mature at this stage. More work
is needed on the ICE layer for efficiency and API experience. TURN support is
still currently a work in progress. Supporting more scenarios and is certainly
part of the near and long term future roadmap.

## Relevant standards

 - [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [RFC8445](https://tools.ietf.org/html/rfc8445):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal
 - [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC7675](https://tools.ietf.org/html/rfc7675):
   Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
 - [RFC6544](https://tools.ietf.org/html/rfc6544):
   TCP Candidates with Interactive Connectivity Establishment (ICE)
 - [RFC8838](https://tools.ietf.org/html/rfc8838):
   Trickle ICE: Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (ICE) Protocol

### TODO

- RFC5766
- RFC6554
- RFC7675
