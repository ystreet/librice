// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::UdpSocket;

use futures::future::{AbortHandle, Abortable, Aborted};

use librice::stun::message::*;

#[macro_use]
extern crate log;

mod common;

#[test]
fn udp_stund() {
    common::debug_init();
    async_std::task::block_on(async move {
        let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_socket.local_addr().unwrap();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let stun_server = Abortable::new(common::stund_udp(stun_socket), abort_registration);
        let stun_server = async_std::task::spawn(stun_server);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let msg = Message::new_request(BINDING);
        socket.send_to(&msg.to_bytes(), stun_addr).await.unwrap();

        let mut buf = [0; 1500];
        socket.recv(&mut buf).await.unwrap();
        let _ = Message::from_bytes(&buf).unwrap();
        abort_handle.abort();
        assert!(matches!(stun_server.await, Err(Aborted)));
    });
}
