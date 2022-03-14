// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate tracing;

#[macro_use]
extern crate derivative;

pub mod agent;
pub mod candidate;
mod clock;
pub mod component;
mod conncheck;
pub mod gathering;
pub mod socket;
pub mod stream;
pub mod stun;
mod utils;

#[cfg(test)]
pub(crate) mod tests {
    use once_cell::sync::Lazy;
    use tracing_subscriber::EnvFilter;

    static TRACING: Lazy<()> = Lazy::new(|| {
        if let Ok(filter) = EnvFilter::try_from_default_env() {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    });

    pub fn test_init_log() {
        Lazy::force(&TRACING);
    }
}
