#![no_main]
use libfuzzer_sys::fuzz_target;

use once_cell::sync::Lazy;

#[macro_use]
extern crate tracing;
use tracing_subscriber::EnvFilter;

use librice_proto::candidate::*;

use std::str::FromStr;

#[derive(arbitrary::Arbitrary, Debug)]
struct Data<'data> {
    data: &'data str,
}

pub fn debug_init() {
    static TRACING: Lazy<()> = Lazy::new(|| {
        if let Ok(filter) = EnvFilter::try_from_default_env() {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    });

    Lazy::force(&TRACING);
}

fuzz_target!(|data: Data| {
    debug_init();
    let res = Candidate::from_str(data.data);
    debug!("candidate result {:?}", res);
});
