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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ice_string_length_and_alphabet() {
        let alphabet = *b"abcdefghijklmnopqrstuvwxyz0123456789";
        /* an empty length produces an empty string */
        assert!(generate_random_ice_string(&alphabet, 0).is_empty());
        let s = generate_random_ice_string(&alphabet, 32);
        assert_eq!(s.len(), 32);
        for c in s.bytes() {
            assert!(alphabet.contains(&c));
        }
        /* two draws of sufficient length differ */
        assert_ne!(
            generate_random_ice_string(&alphabet, 64),
            generate_random_ice_string(&alphabet, 64)
        );
    }

    #[test]
    fn rand_u64_and_f64() {
        /* distinct draws are (with overwhelming probability) different */
        assert_ne!(rand_u64(), rand_u64());
        let val = rand_f64();
        assert!(val.is_finite());
        assert!((0.0..1.0).contains(&val));
    }
}
