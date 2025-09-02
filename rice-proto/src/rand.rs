// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::string::String;

use rand::prelude::*;

pub(crate) fn generate_random_ice_string(alphabet: &[u8], length: usize) -> String {
    #[cfg(not(feature = "std"))]
    {
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng.unwrap_err();
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
        use rand::Rng;
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        rng.random()
    }
    #[cfg(feature = "std")]
    {
        use rand::Rng;
        let mut rng = rand::rng();
        rng.random()
    }
}
