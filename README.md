[![Build status](https://github.com/ystreet/librice/workflows/Build/badge.svg?branch=master)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/master/graph/badge.svg?token=7SP9REUN7L)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/librice.svg)](https://crates.io/crates/librice)
[![docs.rs](https://docs.rs/librice/badge.svg)](https://docs.rs/librice)

# librice

Repository containing an implementation of ICE (RFC8445) protocol writing in
the [Rust programming language](https://www.rust-lang.org/).

## Warning

This still very much WIP code and everything is still subject to change.

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

## Current status

The current status is that there is enough of the implementation to be able to
nominate pairs between a controlled and controlling agent in a static
stream configuration.  This means that there is a fairly robust STUN
implementation (RFC5389) and a large part of the state machine implemented for
the newest ICE specification (RFC8445).  Supporting more scenarios and is
certainly part of the near and long term future roadmap.

### TODO

- RFC5766
- RFC6554
- RFC7675
- Trickle ICE
