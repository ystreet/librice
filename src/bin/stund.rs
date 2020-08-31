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
use async_std::sync::Arc;

use async_channel;

#[macro_use] extern crate log;
use env_logger;

use librice::agent::AgentError;
use librice::stun::attribute::*;
use librice::stun::message::*;

struct StunServer {
    inner: Arc<std::sync::Mutex<StunServerInner>>,
    send_queue_receiver: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
}

impl StunServer {
    fn new() -> Self {
        let (sender, receiver) = async_channel::bounded(16);
        Self {
            inner: Arc::new(std::sync::Mutex::new(StunServerInner::new(sender))),
            send_queue_receiver: receiver,
        }
    }

    fn received_data(&self, data: &[u8]) -> Result<Message,AgentError> {
        Message::from_bytes(data)
    }

    async fn handle_message(&self, msg: Message, from: &SocketAddr) -> Result<(),AgentError> {
        let mut inner = self.inner.lock().unwrap();
        if msg.get_type().class().is_response() {
            inner.handle_response(&msg, from)?;
        } else if msg.get_type().class() == MessageClass::Request {
            inner.handle_request(&msg, from).await?;
        } else if msg.get_type().class() == MessageClass::Indication {
            inner.handle_indication(&msg, from)?;
        } else {
            // message class is not known
            return Err(AgentError::Malformed);
        }
        Ok(())
    }

    fn async_send_queue(&self) -> async_channel::Receiver<(Vec<u8>,SocketAddr)> {
        self.send_queue_receiver.clone()
    }
}

struct StunServerInner {
    send_queue_sender: async_channel::Sender<(Vec<u8>,SocketAddr)>,
}

impl StunServerInner {
    fn new(sender: async_channel::Sender<(Vec<u8>,SocketAddr)>) -> Self {
        Self {
            send_queue_sender: sender,
        }
    }

    fn write_message(&self, msg: &Message) -> Result<Vec<u8>,AgentError> {
        Ok(msg.to_bytes())
    }

    async fn handle_request(&mut self, msg: &Message, addr: &SocketAddr) -> Result<(),AgentError> {
        let out = if msg.get_type().method() == BINDING && false {
            Err(AgentError::WrongImplementation)
        } else {
            let mtype = MessageType::from_class_method(
                    MessageClass::Error, msg.get_type().method());
            let mut out = Message::new(mtype, msg.transaction_id());
            out.add_attribute(Software::new("stund - librice v0.1")?.to_raw())?;
            out.add_attribute(ErrorCode::new(400, "Bad Request")?.to_raw())?;
            let attr_types = msg.iter_attributes()
                    .map(|a| a.get_type()).collect::<Vec<_>>();
            if attr_types.len() > 0 {
                 out.add_attribute(UnknownAttributes::new(&attr_types)
                        .to_raw()).unwrap();
            }
            info!("sending to {:?} {}", addr, out);
            self.write_message(&out)
        }?;
        self.send_queue_sender.send((out, *addr)).await.map_err(|_| AgentError::ConnectionClosed)?;
        Ok(())
    }

    fn handle_indication(&mut self, _msg: &Message, _addr: &SocketAddr) -> Result<(),AgentError> {
        Ok(())
    }

    fn handle_response(&mut self, _msg: &Message, _from: &SocketAddr) -> Result<(),AgentError> {
        return Err(AgentError::ResourceNotFound);
    }
}

async fn send_task(socket: Arc<UdpSocket>, recv_channel: async_channel::Receiver<(Vec<u8>,SocketAddr)>) -> io::Result<()> {
    let (buf, to) = recv_channel.recv().await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))?;
    trace!("sending to {:?} {:?}", to, buf);
    socket.send_to(&buf, &to).await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))?;
    Ok(())
}

async fn receive_task(socket: Arc<UdpSocket>, send_channel: async_channel::Sender<(Vec<u8>,SocketAddr)>) -> io::Result<()> {
    let (buf, src) = {
        // receive data
        let mut buf = [0; 1500];
        let (amt, src) = socket.recv_from(&mut buf).await
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e))?;
        trace!("got from {:?}, {:?}", src, &buf[..amt]);
        (buf[..amt].to_vec(), src)
    };
    send_channel.send((buf, src)).await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))?;
    Ok(())
}

async fn handle_data(server: &StunServer, receive_channel: async_channel::Receiver<(Vec<u8>,SocketAddr)>) -> io::Result<()> {
    let (buf, from): (Vec<_>, SocketAddr) = receive_channel.recv().await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))?;
    // handle data
    let msg = server.received_data(&buf)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))?;
    info!("got from {:?} {}", from, msg);
    server.handle_message (msg, &from).await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e))
}

fn main() -> io::Result<()> {
    env_logger::init();

    task::block_on (async move {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:3478").await?);
        let server = Arc::new(StunServer::new());
        let send_r = server.async_send_queue();

        let (recv_s, recv_r) = async_channel::bounded(16);

        let socket_c = socket.clone();
        task::spawn(async move {
            loop {
                match send_task(socket_c.clone(), send_r.clone()).await {
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
            loop {
                match receive_task(socket_c.clone(), recv_s.clone()).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("{:?}", e);
                        continue;
                    },
                };
            }
        });

        loop {
            match handle_data(&server, recv_r.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("got error: {:?}", e);
                    continue;
                },
            };
        }
    })
}
