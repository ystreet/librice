// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use stun_proto::agent::HandleStunReply;
use stun_proto::agent::StunAgent;

use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::Instant;

use async_std::net::{TcpListener, UdpSocket};

use futures::StreamExt;

use librice::agent::*;
use librice::stun::attribute::*;
use librice::stun::message::*;

pub fn debug_init() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    static TRACING: Once = Once::new();
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

fn warn_on_err<T, E>(res: Result<T, E>, default: T) -> T
where
    E: Display,
{
    match res {
        Ok(v) => v,
        Err(e) => {
            warn!("{}", e);
            default
        }
    }
}

fn handle_binding_request<'a>(
    msg: &Message,
    from: SocketAddr,
) -> Result<MessageBuilder<'a>, AgentError> {
    if let Some(error_msg) = Message::check_attribute_types(msg, &[Fingerprint::TYPE], &[]) {
        return Ok(error_msg);
    }

    let mut response = Message::builder_success(msg);
    let xor_addr = XorMappedAddress::new(from, msg.transaction_id());
    response.add_attribute(&xor_addr).unwrap();
    response.add_fingerprint().unwrap();
    Ok(response.into_owned())
}

fn handle_incoming_data<'a>(
    data: &[u8],
    from: SocketAddr,
    stun_agent: &mut StunAgent,
) -> Option<(MessageBuilder<'a>, SocketAddr)> {
    let msg = Message::from_bytes(data).ok()?;
    match stun_agent.handle_stun(msg, from) {
        HandleStunReply::Drop => None,
        // we don't send any stun request so should never receive any responses
        HandleStunReply::StunResponse(_response) => {
            error!("Received STUN response from {from}!");
            None
        }
        HandleStunReply::IncomingStun(msg) => {
            info!("received from {from}: {}", msg);
            if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                match handle_binding_request(&msg, from) {
                    Ok(response) => {
                        info!("sending response to {from}: {:?}", response);
                        return Some((response, from));
                    }
                    Err(err) => warn!("error: {}", err),
                }
            } else {
                let mut response = Message::builder_error(&msg);
                let error = ErrorCode::new(400, "Bad Request").unwrap();
                response.add_attribute(&error).unwrap();
                return Some((response.into_owned(), from));
            }
            None
        }
    }
}

#[allow(dead_code)]
pub async fn stund_udp(udp_socket: UdpSocket) -> std::io::Result<()> {
    let local_addr = udp_socket.local_addr()?;
    let mut udp_stun_agent =
        StunAgent::builder(stun_proto::types::TransportType::Udp, local_addr).build();

    loop {
        let mut data = vec![0; 1500];
        let (len, from) = warn_on_err(udp_socket.recv_from(&mut data).await, (0, local_addr));
        if let Some((response, to)) = handle_incoming_data(&data[..len], from, &mut udp_stun_agent)
        {
            warn_on_err(udp_socket.send_to(&response.build(), to).await, 0);
        }
    }
}

#[allow(dead_code)]
pub async fn stund_tcp(listener: TcpListener) -> std::io::Result<()> {
    let mut incoming = listener.incoming();
    let local_addr = listener.local_addr()?;
    while let Some(Ok(mut stream)) = incoming.next().await {
        debug!("stund incoming tcp connection");
        async_std::task::spawn(async move {
            let remote_addr = stream.peer_addr().unwrap();
            let mut tcp_stun_agent =
                StunAgent::builder(stun_proto::types::TransportType::Tcp, local_addr)
                    .remote_addr(remote_addr)
                    .build();
            let mut data = vec![0; 1500];
            let size = warn_on_err(stream.read(&mut data).await, 0);
            if size == 0 {
                debug!("TCP connection with {remote_addr} closed");
                return;
            }
            debug!("stund tcp received {size} bytes");
            if let Some((response, to)) =
                handle_incoming_data(&data[..size], remote_addr, &mut tcp_stun_agent)
            {
                if let Ok(transmit) = tcp_stun_agent.send(response, to, Instant::now()) {
                    let data = transmit.data.build();
                    warn_on_err(stream.write_all(&data).await, ());
                }
            }
            // XXX: Assumes that the stun packet arrives in a single packet
            stream.shutdown(std::net::Shutdown::Read).unwrap();
        });
    }
    Ok(())
}
