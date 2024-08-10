// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// everything will be unsafe since this is a FFI
#![allow(clippy::missing_safety_doc)]
#![deny(improper_ctypes_definitions)]

use core::ffi::c_void;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::{panic, thread};

use tracing::warn;

use get_if_addrs::get_if_addrs;

use async_io::Async;
use async_task::{Runnable, Task};
use futures_lite::stream::StreamExt;

use librice_proto::capi::{RiceAddress, RiceError, RiceTransportType};

static TRACING: Once = Once::new();

fn init_logs() {
    TRACING.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Layer;

        let level_filter = std::env::var("RICE_LOG")
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        let _ = tracing::subscriber::set_global_default(registry);
    });
}

static RUNNABLE_QUEUE: OnceLock<flume::Sender<Runnable>> = OnceLock::new();

fn sender() -> &'static flume::Sender<Runnable> {
    RUNNABLE_QUEUE.get_or_init(|| {
        let (sender, receiver) = flume::unbounded::<Runnable>();
        thread::spawn(|| {
            async_io::block_on(async move {
                let mut stream = receiver.into_stream();
                while let Some(runnable) = stream.next().await {
                    if let Err(panic) = panic::catch_unwind(|| runnable.run()) {
                        warn!("task panic: {panic:?}");
                    }
                }
            });
        });
        sender
    })
}

fn schedule(runnable: Runnable) {
    sender().send(runnable).unwrap();
}

/*
/// Connect from the specified interface to the specified address.  Reply (success or failure)
/// should be notified using [`rice_agent_handle_tcp_connect`] with the same parameters.
#[derive(Debug)]
#[repr(C)]
pub struct RiceIoTcpConnect {
    pub stream_id: usize,
    pub component_id: usize,
    pub from: *const RiceAddress,
    pub to: *const RiceAddress,
}

impl From<librice_proto::agent::AgentTcpConnect> for RiceIoTcpConnect {
    fn from(value: librice_proto::agent::AgentTcpConnect) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            from: Box::into_raw(Box::new(RiceAddress(value.from))),
            to: Box::into_raw(Box::new(RiceAddress(value.to))),
        }
    }
}

impl From<RiceIoTcpConnect> for librice_proto::agent::AgentTcpConnect {
    fn from(value: RiceIoTcpConnect) -> Self {
        unsafe {
            Self {
                stream_id: value.stream_id,
                component_id: value.component_id,
                from: RiceAddress::from_c(value.from).0,
                to: RiceAddress::from_c(value.to).0,
            }
        }
    }
}
*/

#[derive(Debug)]
pub struct RiceUdpSocket {
    socket: Async<UdpSocket>,
}

#[no_mangle]
pub unsafe extern "C" fn rice_udp_socket_new(local_addr: *const RiceAddress) -> *mut RiceUdpSocket {
    init_logs();

    let local_addr = Box::from_raw(mut_override(local_addr));

    let ret = if let Ok(socket) = Async::<UdpSocket>::bind(**local_addr) {
        mut_override(Arc::into_raw(Arc::new(RiceUdpSocket { socket })))
    } else {
        core::ptr::null_mut::<RiceUdpSocket>()
    };

    core::mem::forget(local_addr);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn rice_udp_socket_ref(udp: *mut RiceUdpSocket) -> *mut RiceUdpSocket {
    Arc::increment_strong_count(udp);
    udp
}

#[no_mangle]
pub unsafe extern "C" fn rice_udp_socket_unref(udp: *mut RiceUdpSocket) {
    Arc::decrement_strong_count(udp);
}

#[no_mangle]
pub unsafe extern "C" fn rice_udp_socket_local_addr(udp: *const RiceUdpSocket) -> *mut RiceAddress {
    let udp = Arc::from_raw(udp);
    let ret = match udp.socket.get_ref().local_addr() {
        Ok(addr) => mut_override(RiceAddress::new(addr).to_c()),
        Err(_) => core::ptr::null_mut(),
    };
    core::mem::forget(udp);
    ret
}

#[derive(Debug, Copy, Clone)]
struct IoNotifyData {
    io_notify: RiceIoNotify,
    io_notify_data: SendPtr,
    io_destroy: RiceIoNotify,
}

#[derive(Debug)]
struct UdpSocketTask {
    inner: Arc<RiceUdpSocket>,
    // dropping this stops polling for readable
    #[allow(dead_code)]
    poll_task: Task<()>,
    // blocks the poll task until recv() is called for this socket
    semaphore_guard: Arc<Mutex<Option<async_lock::SemaphoreGuardArc>>>,
    io_notify_data: Option<Arc<Mutex<IoNotifyData>>>,
}

#[derive(Debug)]
pub struct RiceSockets {
    inner: Mutex<RiceSocketsInner>,
    notify_data: Arc<Mutex<Option<IoNotifyData>>>,
}

impl RiceSockets {
    fn set_notify(&self, notify_data: Option<IoNotifyData>) {
        let removed_notify = {
            let mut our_notify_data = self.notify_data.lock().unwrap();
            let mut notify_data = notify_data.clone();
            std::mem::swap(&mut *our_notify_data, &mut notify_data);
            notify_data
        };

        {
            let mut inner = self.inner.lock().unwrap();
            let notify_data = notify_data.map(|notify| Arc::new(Mutex::new(notify.clone())));
            for udp in inner.udp_sockets.values_mut() {
                let mut notify_data = notify_data.clone();
                std::mem::swap(&mut udp.io_notify_data, &mut notify_data);
            }
        }

        if let Some(notify_data) = removed_notify {
            if let Some(destroy) = notify_data.io_destroy {
                destroy(notify_data.io_notify_data.ptr);
            }
        }
    }
}

impl Drop for RiceSockets {
    fn drop(&mut self) {
        self.set_notify(None);
    }
}

#[derive(Debug)]
struct RiceSocketsInner {
    udp_sockets: HashMap<SocketAddr, UdpSocketTask>,
    tcp_sockets: HashMap<(SocketAddr, SocketAddr), TcpStream>,
}

pub type RiceIoNotify = Option<extern "C" fn(data: *mut c_void)>;
pub type RiceIoDestroy = Option<extern "C" fn(data: *mut c_void)>;

#[derive(Debug, Copy, Clone)]
struct SendPtr {
    ptr: *mut c_void,
}

unsafe impl Send for SendPtr {}

impl SendPtr {
    fn new(val: *mut c_void) -> Self {
        Self { ptr: val }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_new_with_notify(
    io_notify: RiceIoNotify,
    io_data: *mut c_void,
    io_destroy: RiceIoDestroy,
) -> *mut RiceSockets {
    init_logs();
    let notify_data = io_notify.map(|io_notify| IoNotifyData {
        io_notify: Some(io_notify),
        io_notify_data: SendPtr::new(io_data),
        io_destroy,
    });
    let ret = Arc::new(RiceSockets {
        inner: Mutex::new(RiceSocketsInner {
            udp_sockets: Default::default(),
            tcp_sockets: Default::default(),
        }),
        notify_data: Arc::new(Mutex::new(notify_data)),
    });

    mut_override(Arc::into_raw(ret))
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_new() -> *mut RiceSockets {
    rice_sockets_new_with_notify(None, core::ptr::null_mut(), None)
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_ref(sockets: *mut RiceSockets) -> *mut RiceSockets {
    Arc::increment_strong_count(sockets);
    sockets
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_unref(sockets: *mut RiceSockets) {
    Arc::decrement_strong_count(sockets)
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_set_notify(
    sockets: *mut RiceSockets,
    io_notify: RiceIoNotify,
    io_data: *mut c_void,
    io_destroy: RiceIoDestroy,
) {
    let sockets = Arc::from_raw(sockets);
    let notify_data = io_notify.map(|io_notify| IoNotifyData {
        io_notify: Some(io_notify),
        io_notify_data: SendPtr::new(io_data),
        io_destroy,
    });

    sockets.set_notify(notify_data);

    core::mem::forget(sockets);
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_add_udp(
    sockets: *mut RiceSockets,
    udp: *mut RiceUdpSocket,
) -> bool {
    let sockets = Arc::from_raw(sockets);
    let udp = Arc::from_raw(udp);
    let notify_data = sockets.notify_data.clone();
    let mut inner = sockets.inner.lock().unwrap();

    let local_addr = udp.socket.get_ref().local_addr().unwrap();
    let entry = inner.udp_sockets.entry(local_addr);
    let ret = match entry {
        std::collections::hash_map::Entry::Occupied(_) => false,
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let udp_clone = udp.clone();
            let semaphore = Arc::new(async_lock::Semaphore::new(1));
            let poll_guard = Arc::new(Mutex::new(None));
            let io_notify_data = notify_data
                .lock()
                .unwrap()
                .map(|notify| Arc::new(Mutex::new(notify.clone())));
            let (runnable, task) = async_task::spawn(
                {
                    let poll_guard = poll_guard.clone();
                    let semaphore = semaphore.clone();
                    let io_notify_data = io_notify_data.clone();
                    async move {
                        loop {
                            // Some poll implementations will return readable whenever there is any
                            // data to read on the socket.  However if `rice_sockets_recv()` occurs on
                            // a different thread, then the notification to the application may take a
                            // while for the read to be processed and thus cause the IO thread to busy
                            // loop.  This Semaphore is designed to mitigate this by only allowing a
                            // single poll() and recv() combination for a particular socket to occur
                            // in lockstep.
                            let guard = semaphore.acquire_arc().await;
                            *poll_guard.lock().unwrap() = Some(guard);
                            if let Err(e) = futures_lite::future::poll_fn(|cx| {
                                udp_clone.socket.poll_readable(cx)
                            })
                            .await
                            {
                                warn!("Failed to poll udp socket: {e}");
                                break;
                            }
                            if let Some(ref notify_data) = io_notify_data {
                                let notify_data = notify_data.lock().unwrap();
                                if let Some(notify) = notify_data.io_notify.as_ref() {
                                    notify(notify_data.io_notify_data.ptr);
                                }
                            }
                        }
                    }
                },
                schedule,
            );
            runnable.run();
            vacant.insert(UdpSocketTask {
                inner: udp,
                poll_task: task,
                semaphore_guard: poll_guard,
                io_notify_data,
            });
            true
        }
    };
    drop(inner);

    core::mem::forget(sockets);
    ret
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

#[no_mangle]
pub unsafe extern "C" fn rice_interfaces(ret_len: *mut usize) -> *mut *mut RiceAddress {
    init_logs();

    let Ok(mut ifaces) = get_if_addrs() else {
        return mut_override(std::ptr::null());
    };
    // We only care about non-loopback interfaces for now
    // TODO: remove 'Deprecated IPv4-compatible IPv6 addresses [RFC4291]'
    // TODO: remove 'IPv6 site-local unicast addresses [RFC3879]'
    // TODO: remove 'IPv4-mapped IPv6 addresses unless ipv6 only'
    // TODO: location tracking Ipv6 address mismatches
    ifaces.retain(|e| !address_is_ignorable(e.ip()));

    let ret = ifaces
        .iter()
        .map(|iface| RiceAddress::to_c(RiceAddress::new(SocketAddr::new(iface.ip(), 0))))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    *ret_len = ret.len();
    Box::into_raw(ret) as *mut _
}

#[no_mangle]
pub unsafe extern "C" fn rice_addresses_free(addresses: *mut *mut RiceAddress, len: usize) {
    let addresses = Box::from_raw(core::slice::from_raw_parts_mut(addresses, len));
    for i in 0..len {
        let _addr = RiceAddress::from_c(addresses[i]);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_send(
    sockets: *mut RiceSockets,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    data: *const u8,
    len: usize,
) -> RiceError {
    let sockets = Arc::from_raw(sockets);
    let from = RiceAddress::from_c(mut_override(from));
    let to = RiceAddress::from_c(mut_override(to));
    let data = core::slice::from_raw_parts(data, len);
    let inner = sockets.inner.lock().unwrap();
    let ret = match transport {
        RiceTransportType::Udp => {
            if let Some(udp) = inner.udp_sockets.get(&**from) {
                if udp.inner.socket.get_ref().send_to(data, **to).is_err() {
                    RiceError::Failed
                } else {
                    RiceError::Success
                }
            } else {
                RiceError::NotFound
            }
        }
        RiceTransportType::Tcp => RiceError::NotFound, // FIXME
    };

    drop(inner);
    core::mem::forget(sockets);
    core::mem::forget(from);
    core::mem::forget(to);
    ret
}

#[repr(C)]
pub struct RiceIoData {
    transport: RiceTransportType,
    from: *mut RiceAddress,
    to: *mut RiceAddress,
    len: usize,
}

#[repr(C)]
pub struct RiceIoClosed {
    transport: RiceTransportType,
    from: *mut RiceAddress,
    to: *mut RiceAddress,
}

#[repr(C)]
pub enum RiceIoRecv {
    WouldBlock,
    Data(RiceIoData),
    Closed(RiceIoClosed),
}

#[no_mangle]
pub unsafe extern "C" fn rice_recv_clear(recv: *mut RiceIoRecv) {
    if recv.is_null() {
        return;
    }
    match &*recv {
        RiceIoRecv::Data(data) => {
            let _from = RiceAddress::from_c(data.from);
            let _to = RiceAddress::from_c(data.to);
        }
        RiceIoRecv::Closed(closed) => {
            let _from = RiceAddress::from_c(closed.from);
            let _to = RiceAddress::from_c(closed.to);
        }
        RiceIoRecv::WouldBlock => (),
    }
    *recv = RiceIoRecv::WouldBlock
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_recv(
    sockets: *mut RiceSockets,
    data: *mut u8,
    len: usize,
    ret: *mut RiceIoRecv,
) {
    let sockets = Arc::from_raw(sockets);
    *ret = RiceIoRecv::WouldBlock;
    let mut inner = sockets.inner.lock().unwrap();
    let mut data = core::slice::from_raw_parts_mut(data, len);
    for (&local_addr, udp) in inner.udp_sockets.iter_mut() {
        match udp.inner.socket.get_ref().recv_from(&mut data) {
            Ok((len, from)) => {
                udp.semaphore_guard.lock().unwrap().take();
                *ret = RiceIoRecv::Data(RiceIoData {
                    transport: RiceTransportType::Udp,
                    from: mut_override(RiceAddress::new(from).to_c()),
                    to: mut_override(RiceAddress::new(local_addr).to_c()),
                    len,
                });
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                warn!("Failed to receive data for UDP socket {local_addr:?}: {e}");
            }
        }
    }

    drop(inner);
    core::mem::forget(sockets);
}

fn mut_override<T>(val: *const T) -> *mut T {
    val as *mut T
}

fn const_override<T>(val: *mut T) -> *const T {
    val as *const T
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rice_address() {
        unsafe {
            let s = CString::new("127.0.0.1:2000").unwrap();
            let addr = rice_address_new_from_string(s.as_ptr());
            let addr2 = rice_address_copy(addr);
            rice_address_free(addr);
            rice_address_free(addr2);
        }
    }
}
