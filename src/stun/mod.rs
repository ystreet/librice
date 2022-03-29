// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error;
use std::str::FromStr;

pub mod agent;
pub mod attribute;
pub mod message;
pub mod socket;
//mod pacer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Udp,
    Tcp,
    #[cfg(test)]
    AsyncChannel,
}

#[derive(Debug)]
pub enum ParseTransportTypeError {
    UnknownTransport,
}

impl Error for ParseTransportTypeError {}

impl std::fmt::Display for ParseTransportTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for TransportType {
    type Err = ParseTransportTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(TransportType::Udp),
            "TCP" => Ok(TransportType::Tcp),
            #[cfg(test)]
            "AsyncChannel" => Ok(TransportType::AsyncChannel),
            _ => Err(ParseTransportTypeError::UnknownTransport),
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            TransportType::Udp => write!(f, "UDP"),
            TransportType::Tcp => write!(f, "TCP"),
            #[cfg(test)]
            TransportType::AsyncChannel => write!(f, "AsyncChannel"),
        }
    }
}
