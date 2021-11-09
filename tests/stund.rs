// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::UdpSocket;
use async_std::net::{TcpListener, TcpStream};

use futures::future::{AbortHandle, Abortable, Aborted};
use futures::{AsyncReadExt, AsyncWriteExt};

use librice::stun::message::*;

#[macro_use]
extern crate tracing;

mod common;

#[test]
fn udp_stund() {
    common::debug_init();
    async_std::task::block_on(async move {
        let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_socket.local_addr().unwrap();
        debug!("stun bound to {:?}", stun_addr);
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let stun_server = Abortable::new(common::stund_udp(stun_socket), abort_registration);
        let stun_server = async_std::task::spawn(stun_server);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let msg = Message::new_request(BINDING);
        socket.send_to(&msg.to_bytes(), stun_addr).await.unwrap();
        debug!("sent to {:?}, {}", stun_addr, msg);

        let mut buf = [0; 1500];
        let size = socket.recv(&mut buf).await.unwrap();
        let msg = Message::from_bytes(&buf[..size]).unwrap();
        debug!("received response {}", msg);
        abort_handle.abort();
        assert!(matches!(stun_server.await, Err(Aborted)));
        debug!("stun socket closed");
    });
}

#[test]
fn tcp_stund() {
    common::debug_init();
    async_std::task::block_on(async move {
        let stun_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_socket.local_addr().unwrap();
        debug!("stun bound to {:?}", stun_addr);
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let stun_server = Abortable::new(common::stund_tcp(stun_socket), abort_registration);
        let stun_server = async_std::task::spawn(stun_server);

        let mut socket = TcpStream::connect(stun_addr).await.unwrap();
        let msg = Message::new_request(BINDING);
        socket.write(&msg.to_bytes()).await.unwrap();
        debug!("sent to {:?}, {}", stun_addr, msg);

        let mut buf = [0; 1500];
        socket.read(&mut buf).await.unwrap();
        let _ = Message::from_bytes(&buf).unwrap();
        debug!("received response {}", msg);
        abort_handle.abort();
        assert!(matches!(stun_server.await, Err(Aborted)));
        debug!("stun socket closed");
    });
}
