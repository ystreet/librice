// SPDX-FileCopyrightText: 2026 Matthew Waters <matthew@centricular.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn main() {
    use std::env;
    use std::io::Write;
    use std::path::PathBuf;

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let config_h = out_dir.join("rice-proto-config.h");

    if env::var("CARGO_FEATURE_CAPI").is_err() {
        return;
    }

    let rustls = env::var("CARGO_FEATURE_RUSTLS").is_ok();
    let openssl = env::var("CARGO_FEATURE_OPENSSL").is_ok();
    let dimpl = env::var("CARGO_FEATURE_DIMPL").is_ok();

    let mut output = String::new();
    output.push_str("/* Generated file. Do not edit. */\n\n");
    if rustls {
        output.push_str("#define RICE_PROTO_RUSTLS 1\n");
    }
    if openssl {
        output.push_str("#define RICE_PROTO_OPENSSL 1\n");
    }
    if dimpl {
        output.push_str("#define RICE_PROTO_DIMPL 1\n");
    }

    let mut f = std::fs::File::create(config_h).unwrap();
    f.write_all(output.as_bytes()).unwrap();
}
