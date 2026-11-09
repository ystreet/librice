// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::string::String;

use rand::prelude::*;

pub(crate) fn generate_random_ice_string(alphabet: &[u8], length: usize) -> String {
    #[cfg(not(feature = "std"))]
    {
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        String::from_iter((0..length).map(|_| *alphabet.choose(&mut rng).unwrap() as char))
    }
    #[cfg(feature = "std")]
    {
        let mut rng = rand::rng();
        String::from_iter((0..length).map(|_| *alphabet.choose(&mut rng).unwrap() as char))
    }
}

pub(crate) fn rand_u64() -> u64 {
    #[cfg(not(feature = "std"))]
    {
        use rand::RngExt;
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        rng.random()
    }
    #[cfg(feature = "std")]
    {
        use rand::RngExt;
        let mut rng = rand::rng();
        rng.random()
    }
}

pub(crate) fn rand_f64() -> f64 {
    #[cfg(not(feature = "std"))]
    {
        use rand::RngExt;
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        rng.random::<f64>()
    }
    #[cfg(feature = "std")]
    {
        use rand::RngExt;
        let mut rng = rand::rng();
        rng.random::<f64>()
    }
}
