[![Chat](https://img.shields.io/matrix/librice-general:matrix.org?logo=matrix)](https://matrix.to/#/#librice-general:matrix.org)
[![Build status](https://github.com/ystreet/librice/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/rice-stun-types.svg)](https://crates.io/crates/rice-stun-types)
[![docs.rs](https://docs.rs/rice-stun-types/badge.svg)](https://docs.rs/rice-stun-types)

# rice-stun-types

Implementation of ICE-relevant STUN attributes based on [stun-types] as specified in [RFC8445],
[RFC6544], and [RFC5245].

## Relevant standards

- [x] [RFC5245]: Interactive Connectivity Establishment (ICE): A Protocol for Network Address
  Translator (NAT) Traversal for Offer/Answer Protocols
- [x] [RFC6544]: TCP Candidates with Interactive Connectivity Establishment (ICE)
- [x] [RFC8445]: Interactive Connectivity Establishment (ICE): A Protocol
  for Network Address Translator (NAT) Traversal

[RFC5245]: <https://tools.ietf.org/html/rfc5245>
[RFC6544]: <https://tools.ietf.org/html/rfc6544>
[RFC8445]: <https://tools.ietf.org/html/rfc8445>
[stun-types]: https://docs.rs/stun-types
