[![Chat](https://img.shields.io/matrix/librice-general:matrix.org?logo=matrix)](https://matrix.to/#/#librice-general:matrix.org)
[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/rice-c.svg)](https://crates.io/crates/rice-c)
[![docs.rs](https://docs.rs/rice-c/badge.svg)](https://docs.rs/rice-c)

# rice-c

Repository containing Rust bindings to the C API version of `rice-proto`. This
would be needed when using `rice-proto` from multiple independent
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
 - [x] [RFC6062](https://tools.ietf.org/html/rfc6062):
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

- RFC7675

## Building

If building `rice-c` as part of this repository, then `cargo-c` is required
and can be installed using:
```sh
cargo install cargo-c
```
`rice-c` will then build a local copy of `rice-proto` for use.

Otherwise, this crate requires a pre-existing installation of the C library
`rice-proto` that can be found using `pkg-config` (through `system-deps`).
Running the following command will indicate whether your environment contains
`rice-proto`.
```
pkg-config --modversion rice-proto
```

If you need to build `rice-proto` with the C API, have a look at [rice-proto's
README](https://github.com/ystreet/librice/tree/main/rice-proto).

Once this prerequisite is handled, you can build `rice-c` using a
regular `cargo build` invocation.
