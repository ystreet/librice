// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate tracing;

pub mod agent;
pub mod component;
mod gathering;
pub mod socket;
pub mod stream;
mod utils;

pub use librice_proto::candidate;

pub use stun_proto::types as stun;

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::EnvFilter;

    static TRACING: Once = Once::new();

    pub fn test_init_log() {
        TRACING.call_once(|| {
            if let Ok(filter) = EnvFilter::try_from_default_env() {
                tracing_subscriber::fmt().with_env_filter(filter).init();
            }
        });
    }
}
