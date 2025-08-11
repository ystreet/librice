// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FFI module for the raw `rice-proto` C API.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(unused)]
#![allow(missing_debug_implementations)]

use crate::mut_override;

include!("bindings.rs");

impl Default for RiceStreamIncomingData {
    fn default() -> Self {
        Self {
            handled: false,
            have_more_data: false,
            data: RiceDataImpl {
                ptr: core::ptr::null_mut(),
                size: 0,
            },
        }
    }
}

impl RiceDataImpl {
    pub(crate) fn to_c(slice: &[u8]) -> Self {
        Self {
            ptr: mut_override(slice.as_ptr()),
            size: slice.len(),
        }
    }
}

impl RiceData {
    pub(crate) fn to_c_owned(slice: &[u8]) -> Self {
        RiceData {
            tag: RICE_DATA_OWNED,
            field1: RiceData__bindgen_ty_1 {
                field2: core::mem::ManuallyDrop::new(RiceData__bindgen_ty_1__bindgen_ty_2 {
                    owned: RiceDataImpl::to_c(slice),
                }),
            },
        }
    }
}

impl RiceGatheredCandidate {
    pub(crate) unsafe fn zeroed() -> Self {
        RiceGatheredCandidate {
            candidate: RiceCandidate::zeroed(),
            turn_agent: core::ptr::null_mut(),
        }
    }
}

impl RiceCandidate {
    pub(crate) unsafe fn zeroed() -> Self {
        RiceCandidate {
            component_id: 1,
            candidate_type: RICE_CANDIDATE_TYPE_HOST,
            transport_type: RICE_TRANSPORT_TYPE_UDP,
            foundation: core::ptr::null_mut(),
            priority: 0,
            address: core::ptr::null(),
            base_address: core::ptr::null(),
            related_address: core::ptr::null(),
            tcp_type: RICE_TCP_TYPE_NONE,
            extensions: core::ptr::null_mut(),
            extensions_len: 0,
        }
    }
}
