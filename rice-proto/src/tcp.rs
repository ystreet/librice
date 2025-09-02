// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::vec::Vec;

use byteorder::{BigEndian, ByteOrder};

use tracing::trace;

/// A buffer object for handling STUN data received over a TCP connection that requires framing as
/// specified in RFC 4571.  This framing is required for ICE usage of TCP candidates.
#[derive(Debug)]
pub struct TcpBuffer {
    buf: Vec<u8>,
}

impl core::fmt::Display for TcpBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpBuffer")
            .field("buf", &alloc::format!("{} bytes", self.buf.len()))
            .finish()
    }
}

impl TcpBuffer {
    /// Construct a new [`TcpBuffer`]
    pub fn new() -> Self {
        Vec::new().into()
    }

    /// Push a chunk of received data into the buffer.
    pub fn push_data(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }

    /// Pull the next chunk of data from the buffer.  If no buffer is available, then None is
    /// returned.
    pub fn pull_data(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            trace!(
                "running buffer is currently too small ({} bytes) to provide data",
                self.buf.len()
            );
            return None;
        }

        let data_length = BigEndian::read_u16(&self.buf[..2]) as usize;
        if self.buf.len() < data_length {
            trace!(
                "not enough data, buf length {} data specifies length {}",
                self.buf.len(),
                data_length
            );
            return None;
        }

        let bytes = self.take(data_length);
        trace!("return {} bytes", data_length);
        Some(bytes)
    }

    fn take(&mut self, data_length: usize) -> Vec<u8> {
        let offset = data_length + 2;
        if offset > self.buf.len() {
            return Vec::new();
        }
        let mut data = self.buf.split_off(offset);
        core::mem::swap(&mut data, &mut self.buf);
        data[2..].to_vec()
    }
}

impl Default for TcpBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for TcpBuffer {
    fn from(value: Vec<u8>) -> Self {
        Self { buf: value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_buffer_split_recv() {
        let _log = crate::tests::test_init_log();

        let mut tcp_buffer = TcpBuffer::default();

        let mut len = [0; 2];
        let data = [0, 1, 2, 4, 3];
        BigEndian::write_u16(&mut len, data.len() as u16);

        tcp_buffer.push_data(&len);
        assert!(tcp_buffer.pull_data().is_none());
        tcp_buffer.push_data(&data);
        assert_eq!(tcp_buffer.pull_data().unwrap(), &data);
    }
}
