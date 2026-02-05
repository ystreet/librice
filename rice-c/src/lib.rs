// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # rice-c
//!
//! Bindings for the [rice-proto] C API.
//!
//! ## When to use
//!
//! The `rice-c` crate is useful when you have two separate components written in different
//! languages that need to access and modify the same ICE resources. If your application stack is
//! entirely in rust, then using only [rice-proto] may be sufficient and `rice-c` may not be needed.
//!
//! ## Building
//!
//! `rice-c` requires a pre-existing installation of the [rice-proto] C API that can be found using
//! `pkg-config`. This detection is performed using [system-deps] and there are some environment
//! variables that [system-deps] can use to influence the detection of a [rice-proto]
//! installation.
//!
//! You can check if [rice-proto] is available in your build environment with:
//!
//! ```sh
//! pkg-config --modversion rice-proto
//! ```
//!
//! ## Interface
//!
//! `rice-c` provides a very similar interface as [rice-proto] in order to ease switching between
//! the two implementations (`rice-c` and [rice-proto]) as may be required.
//!
//! [rice-proto]: https://docs.rs/rice-proto
//! [system-deps]: https://docs.rs/system-deps

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod ffi;

pub mod agent;
pub mod candidate;
pub mod component;
pub mod stream;
pub mod turn;

pub use sans_io_time::Instant;

/// Prelude module.
pub mod prelude {
    pub use crate::candidate::CandidateApi;
}

/// A network address.
pub struct Address {
    ffi: *mut crate::ffi::RiceAddress,
}

unsafe impl Send for Address {}
unsafe impl Sync for Address {}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ffi.is_null() {
            f.debug_struct("Address").field("ffi", &self.ffi).finish()
        } else {
            f.debug_struct("Address")
                .field("ffi", &self.ffi)
                .field("value", &self.as_socket())
                .finish()
        }
    }
}

impl Clone for Address {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_address_copy(self.ffi) },
        }
    }
}

impl Drop for Address {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_address_free(self.ffi) }
    }
}

impl Address {
    pub(crate) fn as_c(&self) -> *mut crate::ffi::RiceAddress {
        self.ffi
    }

    pub(crate) fn into_c_full(self) -> *mut crate::ffi::RiceAddress {
        let ret = self.ffi;
        core::mem::forget(self);
        ret
    }

    pub(crate) fn from_c_none(ffi: *const crate::ffi::RiceAddress) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_address_copy(ffi) },
        }
    }

    pub(crate) fn from_c_full(ffi: *mut crate::ffi::RiceAddress) -> Self {
        Self { ffi }
    }

    /// Convert this [`Address`] into a `SocketAddr`.
    pub fn as_socket(&self) -> SocketAddr {
        self.into()
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(v4) => Self {
                ffi: unsafe {
                    crate::ffi::rice_address_new_from_bytes(
                        crate::ffi::RICE_ADDRESS_FAMILY_IPV4,
                        v4.octets().as_ptr(),
                        addr.port(),
                    )
                },
            },
            IpAddr::V6(v6) => Self {
                ffi: unsafe {
                    crate::ffi::rice_address_new_from_bytes(
                        crate::ffi::RICE_ADDRESS_FAMILY_IPV6,
                        v6.octets().as_ptr(),
                        addr.port(),
                    )
                },
            },
        }
    }
}

impl From<&Address> for SocketAddr {
    fn from(value: &Address) -> Self {
        unsafe {
            let port = crate::ffi::rice_address_get_port(value.ffi);
            let ip = match crate::ffi::rice_address_get_family(value.ffi) {
                crate::ffi::RICE_ADDRESS_FAMILY_IPV4 => {
                    let mut octets = [0; 4];
                    crate::ffi::rice_address_get_address_bytes(value.ffi, octets.as_mut_ptr());
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                crate::ffi::RICE_ADDRESS_FAMILY_IPV6 => {
                    let mut octets = [0; 16];
                    crate::ffi::rice_address_get_address_bytes(value.ffi, octets.as_mut_ptr());
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                val => panic!("Unknown address family value {val:x?}"),
            };
            SocketAddr::new(ip, port)
        }
    }
}

impl std::str::FromStr for Address {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: SocketAddr = s.parse()?;
        Ok(Self::from(addr))
    }
}

impl PartialEq<Address> for Address {
    fn eq(&self, other: &Address) -> bool {
        unsafe { crate::ffi::rice_address_cmp(self.ffi, other.ffi) == 0 }
    }
}

/// The family of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AddressFamily {
    /// Version 4 of the Internet Protocol.
    IPV4 = crate::ffi::RICE_ADDRESS_FAMILY_IPV4,
    /// Version 6 of the Internet Protocol.
    IPV6 = crate::ffi::RICE_ADDRESS_FAMILY_IPV6,
}

fn mut_override<T>(val: *const T) -> *mut T {
    val as *mut T
}

fn const_override<T>(val: *mut T) -> *const T {
    val as *const T
}

/// Generate a random sequence of characters suitable for username fragments and passwords.
pub fn random_string(len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    unsafe {
        let ptr = crate::ffi::rice_random_string(len);
        let s = core::ffi::CStr::from_ptr(ptr).to_str().unwrap();
        let ret = s.to_string();
        crate::ffi::rice_string_free(ptr);
        ret
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    pub fn test_init_log() -> DefaultGuard {
        let level_filter = std::env::var("RICE_LOG")
            .or(std::env::var("RUST_LOG"))
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        tracing::subscriber::set_default(registry)
    }

    #[test]
    fn random_string() {
        assert!(crate::random_string(0).is_empty());
        assert_eq!(crate::random_string(4).len(), 4);
        println!("{}", crate::random_string(128));
    }
}
