// Copyright (C) 2023 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// The value of the Allocate message type.  Can be used in either a request or an indication
/// message.
pub const ALLOCATE: u16 = 0x0003;

/// The value of the Refresh message type.  Can be used in either a request or an indication
/// message.
pub const REFRESH: u16 = 0x0004;

/// The value of the Send message type.  Can only be used in an indication message.
pub const SEND: u16 = 0x0006;

/// The value of the Data message type.  Can only be used in an indication message.
pub const DATA: u16 = 0x0007;

/// The value of the CreatePermission message type.  Can be used in either a request or an indication
/// message.
pub const CREATE_PERMISSION: u16 = 0x0008;

/// The value of the ChannelBind message type.  Can be used in either a request or an indication
/// message.
pub const CHANNEL_BIND: u16 = 0x0009;

