// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


use std::net::UdpSocket;

#[macro_use] extern crate log;
use env_logger;

use librice::stun::message::*;
use librice::stun::attribute::*;

fn main() -> std::io::Result<()> {
    env_logger::init();

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let to = "127.0.0.1:3478";

    let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    let mut out = Message::new(mtype, Message::generate_transaction());
    out.add_attribute(Username::new("hi stun person")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?
        .to_raw())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;
    info!("generated {}", out);
    socket.send_to(&out.to_bytes(), &to)?;
    let mut buf = [0; 1500];
    let (amt, _src) = socket.recv_from(&mut buf)?;
    let buf = &buf[..amt];
    let msg = Message::from_bytes(buf).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;
    info!("got {}", msg);
    Ok(())
}
