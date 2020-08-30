// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::io;
use async_std::net::{UdpSocket, SocketAddr};
use async_std::task;
use async_std::sync::{Arc, Mutex};

use async_channel;

#[macro_use] extern crate log;
use env_logger;

use librice::stun::usage::Usage;
use librice::stun::usage::stun::StunUsage;

fn main() -> io::Result<()> {
    env_logger::init();

    task::block_on (async move {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:3478").await?);

        let (send_s, send_r) = async_channel::unbounded();
        let (recv_s, recv_r) = async_channel::unbounded();

        let socket_c = socket.clone();
        task::spawn(async move {
            let process = || async {
                let (buf, to): (Vec<_>, SocketAddr) = send_r.recv().await
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))?;
                trace!("sending to {:?} {:?}", to, buf);
                socket_c.send_to(&buf, &to).await
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))
            };

            loop {
                match process().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("{:?}", e);
                        continue;
                    },
                };
            }
        });

        let socket_c = socket.clone();
        task::spawn(async move {
            let process = || async {
                let (buf, src) = {
                    // receive data
                    let mut buf = [0; 1500];
                    let (amt, src) = socket_c.recv_from(&mut buf).await
                            .map_err(|e| std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e))?;
                    trace!("got from {:?}, {:?}", src, &buf[..amt]);
                    (buf[..amt].to_vec(), src)
                };
                recv_s.send((buf.to_vec(), src)).await
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))
            };
            loop {
                match process().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("{:?}", e);
                        continue;
                    },
                };
            }
        });

        /* echo server, return errors for all requests */
        let usage = Arc::new(Mutex::new(StunUsage::new()));
        let process = || async {
            let (buf, from): (Vec<_>, SocketAddr) = recv_r.recv().await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e))?;
            let mut usage = usage.lock().await;
            let messages = {
                // handle data
                let msg = usage.received_data(&buf, &from)
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))?;
                info!("got from {:?} {:?}", from, msg);
                usage.received_message (&msg, &from)
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))?;

                usage.take_messages_to_send()
            };

            for (out, to) in messages.iter().cloned() {
                usage.send_message(&out, &to);
                info!("sending to {:?}, {:?}", to, out);
                let buf = usage.write_message(&out)
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))?;
                send_s.send((buf.to_vec(), to)).await
                        .map_err(|e| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e))?;
            }
            Ok::<(),io::Error>(())
        };

        loop {
            match process().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("got error: {:?}", e);
                    continue;
                },
            };
        }
    })
}
