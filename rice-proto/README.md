[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/rice-proto.svg)](https://crates.io/crates/rice-proto)
[![docs.rs](https://docs.rs/rice-proto/badge.svg)](https://docs.rs/rice-proto)

# rice-proto

Repository containing an (sans-IO) implementation of ICE (RFC8445) protocol written in
the [Rust programming language](https://www.rust-lang.org/).

## Current status

The current status is that there is enough of the implementation to sucessfully
communicate with STUN/TURN servers and/or a browser (Chrome or Firefox) in a WebRTC
scenario. The STUN implementation is relatively mature. More work is needed on
the ICE layer for efficiency and API experience. Initial TURN support has been
implemented and some TURN-related RFCs are currently in progress. Supporting
more scenarios is part of the near and long term future roadmap.

## Why sans-io?

A few reasons: reusability, testability, and composability.

Without being bogged down in the details of how IO happens, the same sans-IO
implementation can be used without prescribing the IO pattern that an application
must follow. Instead, the application (or parent library) has much more freedom
in how bytes are transferred between peers. It is possible to use a sans-IO
library in either a synchronous environment or within an asynchronous runtime.

A sans-IO design also allows easy testing of any specific state the sans-IO
implementation might find itself in. Combined with a comprehensive test-suite,
this provides assurance that the implementation behaves as expected under all
circumstances.

For other examples of sans-IO implementations, take a look at:
- [stun-proto](https://github.com/ystreet/stun-proto): A sans-IO implementation
  of a STUN agent (client or server).
- [turn-proto](https://github.com/ystreet/turn-proto): A sans-IO implementation
  of a TURN client or server.
- [Quinn](https://github.com/quinn-rs/quinn/): A pure Rust async-compatible
  implementation of QUIC.
- https://sans-io.readthedocs.io/

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
 - [ ] [RFC6156](https://tools.ietf.org/html/rfc6156):
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
 - [ ] [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [x] [RFC8838](https://tools.ietf.org/html/rfc8838):
   Trickle ICE: Incremental Provisioning of Candidates for the Interactive
   Connectivity Establishment (ICE) Protocol

## TODO

- RFC6062
- RFC6156
- RFC7675
- RFC8656

## Building

In order to build a C API, we use [cargo-c](https://crates.io/crates/cargo-c)
to build and install to a relevant installation prefix.

Once `cargo-c` has been installed with:

```sh
cargo install cargo-c
```

Installation can be performed using:

```sh
cargo cinstall --prefix $PREFIX
```

And be used e.g. by `rice-c` for exposing a rust API of the C ABI.
