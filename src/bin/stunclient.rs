// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::UdpSocket;

#[macro_use]
extern crate log;

use librice::stun::message::*;

fn main() -> std::io::Result<()> {
    env_logger::init();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    //let to = "172.253.56.127:19302";
    let to = "127.0.0.1:3478";

    let out = Message::new_request(BINDING);

    info!("generated to {}", out);
    let buf = out.to_bytes();
    trace!("generated to {:?}", buf);
    socket.send_to(&buf, &to)?;
    let mut buf = [0; 1500];
    let (amt, src) = socket.recv_from(&mut buf)?;
    let buf = &buf[..amt];
    trace!("got {:?}", buf);
    let msg = Message::from_bytes(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;
    info!(
        "got from {:?} to {:?} {}",
        src,
        socket.local_addr().unwrap(),
        msg
    );
    Ok(())
}
