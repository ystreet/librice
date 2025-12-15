// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

//! # rice-ctypes
//!
//! Helper crate for providing C types for the rice API.

use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::net::SocketAddr;
use core::str::FromStr;

/// Errors when processing an operation.
#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RiceError {
    /// Not an error. The operation was completed successfully.
    Success = 0,
    /// The operation failed for an unspecified reason.
    Failed = -1,
    /// A required resource was not found.
    ResourceNotFound = -2,
    /// The operation is already in progress.
    AlreadyInProgress = -3,
}

/// A socket address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct RiceAddress(SocketAddr);

impl RiceAddress {
    /// Create a new `RiceAddress`.
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    /// Convert this `RiceAddress` into it's C API equivalent.
    ///
    /// The returned value should be converted back into the Rust equivalent using
    /// `RiceAddress::into_rust_full()` in order to free the resource.
    pub fn into_c_full(self) -> *const RiceAddress {
        const_override(Box::into_raw(Box::new(self)))
    }

    /// Consume a C representation of a `RiceAddress` into the Rust equivalent.
    pub unsafe fn into_rice_full(value: *const RiceAddress) -> Box<Self> {
        unsafe { Box::from_raw(mut_override(value)) }
    }

    /// Copy a C representation of a `RiceAddress` into the Rust equivalent.
    pub unsafe fn into_rice_none(value: *const RiceAddress) -> Self {
        unsafe {
            let boxed = Box::from_raw(mut_override(value));
            let ret = *boxed;
            core::mem::forget(boxed);
            ret
        }
    }

    /// The inner representation of the [`RiceAddress`].
    pub fn inner(self) -> SocketAddr {
        self.0
    }
}

impl core::ops::Deref for RiceAddress {
    type Target = SocketAddr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Create a `RiceAddress` from a string representation of the socket address.
pub unsafe fn rice_address_new_from_string(string: *const c_char) -> *mut RiceAddress {
    unsafe {
        let Ok(string) = CStr::from_ptr(string).to_str() else {
            return core::ptr::null_mut();
        };
        let Ok(saddr) = SocketAddr::from_str(string) else {
            return core::ptr::null_mut();
        };

        mut_override(RiceAddress::into_c_full(RiceAddress::new(saddr)))
    }
}

/// Compare whether two `RiceAddress`es are equal.
pub unsafe fn rice_address_cmp(addr: *const RiceAddress, other: *const RiceAddress) -> c_int {
    unsafe {
        match (addr.is_null(), other.is_null()) {
            (true, true) => 0,
            (true, false) => -1,
            (false, true) => 1,
            (false, false) => {
                let addr = RiceAddress::into_rice_none(addr);
                let other = RiceAddress::into_rice_none(other);
                addr.cmp(&other) as c_int
            }
        }
    }
}

/// Free a `RiceAddress`.
pub unsafe fn rice_address_free(addr: *mut RiceAddress) {
    unsafe {
        if !addr.is_null() {
            let _addr = Box::from_raw(addr);
        }
    }
}

/// The transport family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceTransportType {
    /// The UDP transport
    Udp,
    /// The TCP transport
    Tcp,
}

fn mut_override<T>(val: *const T) -> *mut T {
    val as *mut T
}

fn const_override<T>(val: *mut T) -> *const T {
    val as *const T
}
