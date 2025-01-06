[![Build status](https://github.com/ystreet/librice/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice.svg)](https://crates.io/crates/librice)
[![docs.rs](https://docs.rs/librice/badge.svg)](https://docs.rs/librice)

# librice

Repository containing an (sans-IO) implementation of ICE (RFC8445) protocol written in
the [Rust programming language](https://www.rust-lang.org/). A C interface is
currently also provided.

## Warning

This still very much WIP code and everything is still subject to change.

## Current status

The current status is that there is enough of the implementation to sucessfully
communicate with STUN servers or a browser (Chrome or Firefox) in a WebRTC
scenario.  The STUN implementation is relatively mature at this stage. More work
is needed on the ICE layer for efficiency and API experience. TURN support is
still currently a work in progress. Supporting more scenarios and is certainly
part of the near and long term future roadmap.

## Why sans-io?

A couple of reasons: reusability, and testability.

Without being bogged down in the details of how IO happens, the same sans-IO
implementation can be used without prescribing the IO pattern that an application
must follow. Instead, the application (or parent library) has much more freedom
in how bytes are transferred between peers. It's also possible to use a sans-IO
library in either a synchronous or within an asynchronous runtime.

sans-IO also allows easy testing of any specific state the sans-IO
implementation might find itself in. Combined with a comprehensive test-suite,
this provides assurance that the implementation behaves as expected under all
circumstances.

For other examples of sans-IO implementations, take a look at:
- [stun-proto](https://github.com/ystreet/stun-proto)
- [Quinn](https://github.com/quinn-rs/quinn/)
- https://sans-io.readthedocs.io/

## Relevant standards

 - [RFC5245](https://tools.ietf.org/html/rfc5245):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal for Offer/Answer Protocols
 - [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC5769](https://tools.ietf.org/html/rfc5769):
   Test Vectors for Session Traversal Utilities for NAT (STUN)
 - [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [RFC6544](https://tools.ietf.org/html/rfc6544):
   TCP Candidates with Interactive Connectivity Establishment (ICE)
 - [RFC7675](https://tools.ietf.org/html/rfc7675):
   Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
 - [RFC8445](https://tools.ietf.org/html/rfc8445):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal
 - [RFC8489](https://tools.ietf.org/html/rfc8489):
   Session Traversal Utilities for NAT (STUN)
 - [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC8838](https://tools.ietf.org/html/rfc8838):
   Trickle ICE: Incremental Provisioning of Candidates for the Interactive
   Connectivity Establishment (ICE) Protocol

## TODO

- RFC5766
- RFC6554
- RFC7675
