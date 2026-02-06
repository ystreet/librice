[![Chat](https://img.shields.io/matrix/librice-general:matrix.org?logo=matrix)](https://matrix.to/#/#librice-general:matrix.org)
[![Build status](https://github.com/ystreet/librice/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/librice/actions)
[![codecov](https://codecov.io/gh/ystreet/librice/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/librice)
[![Dependencies](https://deps.rs/repo/github/ystreet/librice/status.svg)](https://deps.rs/repo/github/ystreet/librice)
[![crates.io](https://img.shields.io/crates/v/rice-ctypes.svg)](https://crates.io/crates/rice-ctypes)
[![docs.rs](https://docs.rs/rice-stun-types/badge.svg)](https://docs.rs/rice-ctypes)

# rice-ctypes

Definitions of types shared between `rice-proto` and `rice-io`. Only necessary
so that `rice-proto`, and `rice-io` do not duplicate the same (potentially
incompatibile) definitions for the same types.
