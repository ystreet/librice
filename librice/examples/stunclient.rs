// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::process::exit;
use std::str::FromStr;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use tracing_subscriber::EnvFilter;

#[macro_use]
extern crate tracing;

use librice::candidate::TransportType;
use librice::stun::attribute::*;
use librice::stun::message::*;

fn usage() {
    println!("stunclient [protocol] [address:port]");
    println!();
    println!("\tprotocol: can be either \'udp\' or \'tcp\'");
}

fn parse_response(response: Message) -> Result<(), std::io::Error> {
    if Message::check_attribute_types(
        &response,
        &[XorMappedAddress::TYPE, Fingerprint::TYPE],
        &[XorMappedAddress::TYPE],
    )
    .is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Required attributes not found in response",
        ));
    }
    if response.has_class(MessageClass::Success) {
        // presence checked by check_attribute_types() above
        let mapped_address = response.attribute::<XorMappedAddress>().unwrap();
        let visible_addr = mapped_address.addr(response.transaction_id());
        println!("found visible address {:?}", visible_addr);
        Ok(())
    } else if response.has_class(MessageClass::Error) {
        println!("got error response {:?}", response);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Error response",
        ))
    } else {
        println!("got unknown response {:?}", response);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown response",
        ))
    }
}

fn tcp_message(out: Message, to: SocketAddr) -> Result<(), std::io::Error> {
    let mut socket = TcpStream::connect(to).unwrap();

    info!("generated to {}", out);
    let buf = out.to_bytes();
    trace!("generated to {:?}", buf);
    socket.write_all(&buf)?;
    let mut buf = [0; 1500];
    let amt = socket.read(&mut buf)?;
    let buf = &buf[..amt];
    trace!("got {:?}", buf);
    let msg = Message::from_bytes(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;
    info!(
        "got from {:?} to {:?} {}",
        socket.peer_addr().unwrap(),
        socket.local_addr().unwrap(),
        msg
    );

    parse_response(msg)
}

fn udp_message(out: Message, to: SocketAddr) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    info!("generated to {}", out);
    let buf = out.to_bytes();
    trace!("generated to {:?}", buf);
    socket.send_to(&buf, to)?;
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

    parse_response(msg)
}

fn main() -> std::io::Result<()> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let args: Vec<String> = env::args().collect();
    let proto = if args.len() > 1 {
        if args[1] == "udp" {
            TransportType::Udp
        } else if args[1] == "tcp" {
            TransportType::Tcp
        } else {
            usage();
            exit(1);
        }
    } else {
        TransportType::Udp
    };

    let to: SocketAddr = SocketAddr::from_str(if args.len() > 2 {
        &args[2]
    } else {
        "127.0.0.1:3478"
    })
    .unwrap();

    println!("sending STUN message over {:?} to {}", proto, to);
    let mut msg = Message::new_request(BINDING);
    msg.add_fingerprint().unwrap();

    match proto {
        TransportType::Udp => udp_message(msg, to),
        TransportType::Tcp => tcp_message(msg, to),
    }
}
