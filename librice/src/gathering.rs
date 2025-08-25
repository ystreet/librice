// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utilities for gathering potential sockets to send/receive data to/from.

use smol::net::{SocketAddr, TcpListener, UdpSocket};
use tracing::info;

use std::net::IpAddr;
use std::sync::Arc;

use futures::prelude::*;
use futures::StreamExt;

use get_if_addrs::get_if_addrs;

use crate::agent::AgentError;
use crate::candidate::TransportType;
use crate::socket::UdpSocketChannel;

/// A gathered socket
#[derive(Debug, Clone)]
pub enum GatherSocket {
    Udp(UdpSocketChannel),
    Tcp(Arc<TcpListener>),
}

impl GatherSocket {
    /// The [`TransportType`] of this socket
    pub fn transport(&self) -> TransportType {
        match self {
            GatherSocket::Udp(_) => TransportType::Udp,
            GatherSocket::Tcp(_) => TransportType::Tcp,
        }
    }

    /// The address of the local end of this socket
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            GatherSocket::Udp(s) => s.local_addr().unwrap(),
            GatherSocket::Tcp(s) => s.local_addr().unwrap(),
        }
    }
}

fn address_is_ignorable(ip: IpAddr) -> bool {
    // TODO: add is_benchmarking() and is_documentation() when they become stable
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_broadcast() || ipv4.is_link_local(),
        IpAddr::V6(_ipv6) => false,
    }
}

/// Returns a stream of sockets corresponding to the available network interfaces
pub fn iface_sockets(
) -> Result<impl Stream<Item = Result<GatherSocket, std::io::Error>>, AgentError> {
    let mut ifaces = get_if_addrs()?;
    // We only care about non-loopback interfaces for now
    // TODO: remove 'Deprecated IPv4-compatible IPv6 addresses [RFC4291]'
    // TODO: remove 'IPv6 site-local unicast addresses [RFC3879]'
    // TODO: remove 'IPv4-mapped IPv6 addresses unless ipv6 only'
    // TODO: location tracking Ipv6 address mismatches
    ifaces.retain(|e| !address_is_ignorable(e.ip()));

    for _f in ifaces.iter().inspect(|iface| {
        info!("Found interface {} address {:?}", iface.name, iface.ip());
    }) {}

    Ok(futures::stream::iter(ifaces.clone())
        .then(|iface| async move {
            Ok(GatherSocket::Udp(UdpSocketChannel::new(
                UdpSocket::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
            )))
        })
        .chain(futures::stream::iter(ifaces).then(|iface| async move {
            Ok(GatherSocket::Tcp(Arc::new(
                TcpListener::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
            )))
        })))
}
