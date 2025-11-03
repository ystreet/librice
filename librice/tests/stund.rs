// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::UdpSocket;

use futures::future::{AbortHandle, Abortable};

use librice::runtime::{AsyncTcpStreamReadExt, AsyncTcpStreamWriteExt, AsyncUdpSocketExt};
use stun_proto::types::message::*;

#[macro_use]
extern crate tracing;

mod common;

#[cfg(feature = "runtime-smol")]
#[test]
fn smol_udp_stund() {
    smol::block_on(udp_stund())
}

#[cfg(feature = "runtime-tokio")]
#[test]
fn tokio_udp_stund() {
    crate::common::tokio_runtime().block_on(udp_stund())
}

async fn udp_stund() {
    common::debug_init();
    let runtime = librice::runtime::default_runtime().unwrap();
    let stun_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let stun_socket = runtime.wrap_udp_socket(stun_socket).unwrap();
    let stun_addr = stun_socket.local_addr().unwrap();
    debug!("stun bound to {:?}", stun_addr);
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let stun_server = Abortable::new(common::stund_udp(stun_socket), abort_registration);
    runtime.spawn(Box::pin(async move {
        let _ = stun_server.await;
    }));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket = runtime.wrap_udp_socket(socket).unwrap();
    let msg = Message::builder_request(BINDING, MessageWriteVec::new());
    debug!("sent to {:?}, {:?}", stun_addr, msg);
    socket.send_to(&msg.finish(), stun_addr).await.unwrap();

    let mut buf = [0; 1500];
    let (size, _addr) = socket.recv_from(&mut buf).await.unwrap();
    let msg = Message::from_bytes(&buf[..size]).unwrap();
    debug!("received response {}", msg);
    abort_handle.abort();
    debug!("stun socket closed");
}

#[cfg(feature = "runtime-smol")]
#[test]
fn smol_tcp_stund() {
    smol::block_on(tcp_stund())
}

#[cfg(feature = "runtime-tokio")]
#[test]
fn tokio_tcp_stund() {
    crate::common::tokio_runtime().block_on(tcp_stund())
}

async fn tcp_stund() {
    common::debug_init();
    let runtime = librice::runtime::default_runtime().unwrap();
    let stun_socket = runtime
        .new_tcp_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let stun_addr = stun_socket.local_addr().unwrap();
    debug!("stun bound to {:?}", stun_addr);
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let stun_server = Abortable::new(
        common::stund_tcp(runtime.clone(), stun_socket),
        abort_registration,
    );
    runtime.spawn(Box::pin(async move {
        let _ = stun_server.await;
    }));

    let socket = runtime.tcp_connect(stun_addr).await.unwrap();
    let (mut read, mut write) = socket.split();
    let msg = Message::builder_request(BINDING, MessageWriteVec::new());
    debug!("sent to {:?}, {:?}", stun_addr, msg);
    let msg_bytes = msg.finish();
    write.write_all(&msg_bytes).await.unwrap();

    let mut buf = [0; 1500];
    let mut read_position = 0;
    loop {
        let read_amount = read.read(&mut buf[read_position..]).await.unwrap();
        read_position += read_amount;
        debug!(
            "got {} bytes, buffer contains {} bytes",
            read_amount, read_position
        );
        if read_position < 20 {
            continue;
        }
        match Message::from_bytes(&buf[..read_position]) {
            Ok(msg) => {
                debug!("received response {}", msg);
                break;
            }
            Err(_) => continue,
        }
    }

    abort_handle.abort();
    //assert!(matches!(stun_server.await, Err(Aborted)));
    debug!("stun socket closed");
}
