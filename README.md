[![Chat](https://img.shields.io/matrix/librice-general:matrix.org?logo=matrix)](https://matrix.to/#/#librice-general:matrix.org)
[![Build status](https://github.com/ystreet/librice/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice.svg)](https://crates.io/crates/librice)
[![docs.rs](https://docs.rs/librice/badge.svg)](https://docs.rs/librice)

# librice

Repository containing an (sans-IO) implementation of ICE (RFC8445) protocol written in
the [Rust programming language](https://www.rust-lang.org/). A C API interface is
currently also provided for `rice-proto` and `rice-io`. The C interface can
also be accessed from Rust using `rice-c`.

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

## Structure

### [rice-stun-types](https://github.com/ystreet/librice/tree/main/rice-stun-types)

Implementation of STUN attributes relevant for ICE (RFC8445).

### [rice-proto](https://github.com/ystreet/librice/tree/main/rice-proto)

The sans-IO implementation of the ICE (RFC8445) protocol. Contains no IO code
whatsover.

### [rice-c](https://github.com/ystreet/librice/tree/main/rice-c)

A library for accessing `rice-proto` using a C API interface.
Typically useful when exposing the ICE agent across library/application
boundaries for accessing the same ICE agent. If your application does not have
such a requirement (e.g. entirely in Rust), then `rice-c` is not needed.

### [librice](https://github.com/ystreet/librice/tree/main/librice)

An async implementation of ICE (RFC8445) built using `rice-proto` using the C
API through the `rice-c` crate. The async runtime used can be provided by the
application for `librice` to use or the provided `tokio` and `smol`
implementations can be used.

### [rice-io](https://github.com/ystreet/librice/tree/main/rice-io)

An optional library exposing a C interface for handling IO using Rust's network
primitives `UdpSocket`, and `TcpStream`. Uses a single dedicated thread for
handling IO wakeups. It is not required for implementation.

## TODO

- RFC6062
- RFC7675

## Building

All crates in the workspace can be built using a standard `cargo build`
invocation. However in order to successfully build the `rice-c` crate (and any
dependant crates, like `librice`), `cargo-c` must be installed and in the
environment.  The [rice-c README](https://github.com/ystreet/librice/tree/main/rice-c#building)
contains more details.
