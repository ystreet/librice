[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice-c.svg)](https://crates.io/crates/librice-c)
[![docs.rs](https://docs.rs/librice-c/badge.svg)](https://docs.rs/librice-c)

# librice-c

Repository containing Rust bindings to the C API version of librice-proto. This
would typically be needed when using librice-proto from multiple independent
libraries/application and shared access to the same `Agent` is required.

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

If building `librice-c` as part of this repository, then `cargo-c` is required
and can be installed using:
```sh
cargo install cargo-c
```
`librice-c` will then build a local copy of `librice-proto` for use.

Otherwise, this crate requires a pre-existing installation of the C library
`librice-proto` that can be found using `pkg-config` (through `system-deps`).
Running the following command will indicate whether your environment contains
`librice-proto`.
```
pkg-config --modversion librice-proto
```

If you need to build `librice-proto` with the C API, have a look at [the
README](https://github.com/ystreet/librice/tree/main/librice-proto).

Once the the prerequisite is handled, you can build `librice-c` using a
regular `cargo build` invocation.
