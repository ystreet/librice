// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]

#[macro_use]
extern crate tracing;

pub mod agent;
pub mod component;
mod gathering;
pub mod socket;
pub mod stream;
mod utils;

pub use rice_c::candidate;

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    static TRACING: Once = Once::new();

    pub fn test_init_log() {
        TRACING.call_once(|| {
            let level_filter = std::env::var("RICE_LOG")
                .or(std::env::var("RUST_LOG"))
                .ok()
                .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
                .unwrap_or(
                    tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR),
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
            tracing::subscriber::set_global_default(registry).unwrap();
        });
    }
}
