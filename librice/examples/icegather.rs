// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::Parser;

use librice::agent::{Agent, AgentMessage, TurnConfig, TurnCredentials};
use rice_c::{turn::TurnTlsConfig, AddressFamily};

use std::{io, net::SocketAddr, str::FromStr};

use futures::prelude::*;

use librice::candidate::TransportType;

fn init_logs() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let level_filter = std::env::var("RICE_LOG")
        .ok()
        .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
        .unwrap_or(tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR));
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
}

#[derive(Clone, Debug)]
struct TurnServerConfig {
    addr: SocketAddr,
    client_transport: TransportType,
    user: String,
    pass: String,
    tls: Option<TlsConfig>,
}

#[derive(Clone, Debug)]
enum TlsConfig {
    Rustls(Option<String>),
    Openssl,
}

impl clap::builder::ValueParserFactory for TurnServerConfig {
    type Parser = TurnServerConfigParser;
    fn value_parser() -> Self::Parser {
        TurnServerConfigParser
    }
}

#[derive(Debug, Clone)]
struct TurnServerConfigParser;
impl clap::builder::TypedValueParser for TurnServerConfigParser {
    type Value = TurnServerConfig;
    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let split = value.to_str().ok_or_else(|| {
            clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd)
        })?;
        let mut split = split.splitn(6, ",");
        let Some(addr) = split.next() else {
            eprintln!("No TURN address");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Ok(addr) = SocketAddr::from_str(addr) else {
            eprintln!("Failed to parse TURN address");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Some(client_transport) = split.next() else {
            eprintln!("No TURN client transport");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Ok(client_transport) = TransportType::from_str(client_transport) else {
            eprintln!("Failed to parse TURN client transport");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Some(user) = split.next() else {
            eprintln!("No TURN user name");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Some(pass) = split.next() else {
            eprintln!("No TURN password");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let tls = if let Some(tls) = split.next() {
            match tls {
                "rustls" => Some(TlsConfig::Rustls(split.next().map(|s| s.to_string()))),
                "openssl" => Some(TlsConfig::Openssl),
                tls_name => {
                    eprintln!("Unknown TLS implementation: {tls_name}");
                    return Err(
                        clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd)
                    );
                }
            }
        } else {
            None
        };
        if split.next().is_some() {
            eprintln!("trailing unhandled options");
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        }

        Ok(TurnServerConfig {
            addr,
            client_transport,
            user: user.to_string(),
            pass: pass.to_string(),
            tls,
        })
    }
}

#[derive(Debug, Clone, Parser)]
struct StunServer {
    transport: TransportType,
    server: SocketAddr,
}

impl clap::builder::ValueParserFactory for StunServer {
    type Parser = StunServerParser;
    fn value_parser() -> Self::Parser {
        StunServerParser
    }
}
#[derive(Debug, Clone)]
struct StunServerParser;
impl clap::builder::TypedValueParser for StunServerParser {
    type Value = StunServer;
    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let split = value.to_str().ok_or_else(|| {
            clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd)
        })?;
        let mut split = split.splitn(2, ",");
        let Some(server) = split.next() else {
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let Ok(server) = SocketAddr::from_str(server) else {
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        };
        let transport = split
            .next()
            .and_then(|s| TransportType::from_str(s).ok())
            .unwrap_or(TransportType::Udp);
        if split.next().is_some() {
            return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd));
        }

        Ok(StunServer { transport, server })
    }
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, value_name = "ADDRESS[,udp|tcp]", action = clap::ArgAction::Append)]
    stun_server: Vec<StunServer>,
    #[arg(
        long,
        value_name = "ADDRESS,udp|tcp,USERNAME,PASSWORD[,openssl|rustls[,SERVER_IDENTITY]]",
        action = clap::ArgAction::Append,
    )]
    turn_server: Vec<TurnServerConfig>,
}

#[cfg(feature = "runtime-tokio")]
fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn run() -> io::Result<()> {
    init_logs();
    let cli = Cli::parse();
    eprintln!("command parameters: {cli:?}");
    let agent = Agent::builder().build();
    for server in cli.stun_server {
        agent.add_stun_server(server.transport, server.server);
    }
    for ts in cli.turn_server {
        let credentials = TurnCredentials::new(&ts.user, &ts.pass);
        let tls_config = ts.tls.and_then(|tls| match tls {
            TlsConfig::Openssl => Some(TurnTlsConfig::new_openssl(ts.client_transport)),
            TlsConfig::Rustls(server_name) => {
                if ts.client_transport != TransportType::Tcp {
                    eprintln!(
                        "rustls only supports TCP connections, {} was requested",
                        ts.client_transport
                    );
                    None
                } else if let Some(server_name) = server_name {
                    Some(TurnTlsConfig::new_rustls_with_dns(&server_name))
                } else {
                    Some(TurnTlsConfig::new_rustls_with_ip(&ts.addr.into()))
                }
            }
        });
        let turn_cfg = TurnConfig::new(
            ts.client_transport,
            ts.addr.into(),
            credentials.clone(),
            &[AddressFamily::IPV4, AddressFamily::IPV6],
            tls_config,
        );
        agent.add_turn_server(turn_cfg);
    }
    let stream = agent.add_stream();
    let _comp = stream.add_component();

    stream.gather_candidates().await.unwrap();
    let mut messages = agent.messages();
    while let Some(msg) = messages.next().await {
        match msg {
            AgentMessage::GatheredCandidate(_stream, candidate) => {
                println! {"{}", candidate.candidate().to_sdp_string()}
            }
            AgentMessage::GatheringComplete(_component) => break,
            _ => (),
        }
    }
    Ok(())
}

#[allow(unreachable_code)]
fn main() -> io::Result<()> {
    #[cfg(feature = "runtime-smol")]
    return smol::block_on(run());

    #[cfg(feature = "runtime-tokio")]
    return tokio_runtime().block_on(run());

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "No async runtime available",
    ))
}
