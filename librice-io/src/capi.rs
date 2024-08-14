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
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::{panic, thread};

use tracing::{debug, trace, warn};

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
                    trace!("running: {runnable:?}");
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

#[derive(Debug)]
pub struct RiceTcpSocket {
    socket: Async<TcpStream>,
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_socket_local_addr(tcp: *mut RiceTcpSocket) -> *mut RiceAddress {
    let tcp = Arc::from_raw(tcp);
    let addr = match tcp.socket.get_ref().local_addr() {
        Ok(addr) => mut_override(RiceAddress::new(addr).to_c()),
        Err(_e) => core::ptr::null_mut(),
    };
    core::mem::forget(tcp);
    addr
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_socket_remote_addr(tcp: *mut RiceTcpSocket) -> *mut RiceAddress {
    let tcp = Arc::from_raw(tcp);
    let addr = match tcp.socket.get_ref().peer_addr() {
        Ok(addr) => mut_override(RiceAddress::new(addr).to_c()),
        Err(_e) => core::ptr::null_mut(),
    };
    core::mem::forget(tcp);
    addr
}

#[derive(Debug)]
pub struct RiceIoCancel {
    task: Option<Task<()>>,
}

#[no_mangle]
pub unsafe extern "C" fn rice_io_cancel_new() -> *mut RiceIoCancel {
    Box::into_raw(Box::new(RiceIoCancel { task: None }))
}

#[no_mangle]
pub unsafe extern "C" fn rice_io_cancel_free(cancel: *mut RiceIoCancel) {
    let _ = Box::from_raw(cancel);
}

#[no_mangle]
pub unsafe extern "C" fn rice_io_cancel_cancel(cancel: *mut RiceIoCancel) {
    let cancel = unsafe { &mut *cancel };
    if let Some(task) = cancel.task.take() {
        async_io::block_on(task.cancel());
    }
}

pub type RiceIoOnTcpConnect = Option<extern "C" fn(*mut RiceTcpSocket, data: *mut c_void)>;

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_connect(
    remote_addr: *const RiceAddress,
    on_connect: RiceIoOnTcpConnect,
    data: *mut c_void,
    cancel: *mut RiceIoCancel,
) {
    init_logs();
    if on_connect.is_none() {
        return;
    }

    let remote_addr = Box::from_raw(mut_override(remote_addr));
    let addr = **remote_addr;
    core::mem::forget(remote_addr);
    let ptr = Some(SendPtr::new(data));

    let (runnable, task) = async_task::spawn(
        async move {
            debug!("connecting to {addr:?}");
            let stream = match Async::<TcpStream>::connect(addr).await {
                Ok(socket) => {
                    debug!("connected to {addr:?}");
                    mut_override(Arc::into_raw(Arc::new(RiceTcpSocket { socket })))
                }
                Err(e) => {
                    warn!("tcp connect to {addr:?} failed: {e:?}");
                    core::ptr::null_mut::<RiceTcpSocket>()
                }
            };
            let on_connect = on_connect.unwrap();
            on_connect(stream, ptr.unwrap().ptr);
        },
        schedule,
    );

    if !cancel.is_null() {
        let cancel = unsafe { &mut *cancel };
        cancel.task = Some(task);
    } else {
        task.detach();
    }

    runnable.run();
}

pub type RiceIoOnTcpListen = Option<extern "C" fn(*mut RiceTcpSocket, data: *mut c_void)>;

struct DestroyOnDrop {
    on_destroy: RiceIoDestroy,
    ptr: SendPtr,
}

impl Drop for DestroyOnDrop {
    fn drop(&mut self) {
        if let Some(destroy) = self.on_destroy {
            destroy(self.ptr.ptr);
        }
    }
}

#[derive(Debug)]
pub struct RiceTcpListener {
    listener: Arc<Async<TcpListener>>,
    cancel: RiceIoCancel,
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_listen(
    local_addr: *const RiceAddress,
    on_listen: RiceIoOnTcpListen,
    data: *mut c_void,
    destroy: RiceIoDestroy,
) -> *mut RiceTcpListener {
    init_logs();

    if on_listen.is_none() {
        return core::ptr::null_mut();
    }
    let local_addr = Box::from_raw(mut_override(local_addr));
    let addr = **local_addr;
    core::mem::forget(local_addr);
    let Ok(listener) = Async::<TcpListener>::bind(addr) else {
        warn!("tcp bind failed for {addr:?}");
        return core::ptr::null_mut();
    };
    let listener = Arc::new(listener);

    let ptr = Some(SendPtr::new(data));

    let (runnable, task) = async_task::spawn(
        {
            let listener = listener.clone();
            async move {
                let _drop_destroy = DestroyOnDrop {
                    on_destroy: destroy,
                    ptr: ptr.clone().unwrap(),
                };
                let incoming = listener.incoming();
                futures_lite::pin!(incoming);
                let on_listen = on_listen.unwrap();
                while let Some(stream) = incoming.next().await {
                    trace!("tcp incoming stream {stream:?}");
                    match stream {
                        Ok(stream) => {
                            let socket = mut_override(Arc::into_raw(Arc::new(RiceTcpSocket {
                                socket: stream,
                            })));
                            on_listen(socket, ptr.unwrap().ptr);
                        }
                        Err(e) => {
                            warn!("Failed to accept incoming stream for listener {addr:?}: {e:?}");
                        }
                    }
                }
            }
        },
        schedule,
    );
    runnable.run();

    mut_override(Arc::into_raw(Arc::new(RiceTcpListener {
        listener,
        cancel: RiceIoCancel { task: Some(task) },
    })))
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_listener_ref(
    listener: *mut RiceTcpListener,
) -> *mut RiceTcpListener {
    Arc::increment_strong_count(listener);
    listener
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_listener_unref(listener: *mut RiceTcpListener) {
    Arc::decrement_strong_count(listener);
}

#[no_mangle]
pub unsafe extern "C" fn rice_tcp_listener_local_addr(
    listener: *mut RiceTcpListener,
) -> *mut RiceAddress {
    let listener = Arc::from_raw(listener);
    let ret = match listener.listener.get_ref().local_addr() {
        Ok(addr) => mut_override(RiceAddress::new(addr).to_c()),
        Err(_e) => core::ptr::null_mut(),
    };
    core::mem::forget(listener);
    ret
}

#[derive(Debug, Copy, Clone)]
struct IoNotifyData {
    io_notify: RiceIoNotify,
    io_notify_data: SendPtr,
    io_destroy: RiceIoNotify,
}

#[derive(Debug)]
struct PollReadableTask {
    // dropping this stops polling for readable
    #[allow(dead_code)]
    poll_task: Task<()>,
    // blocks the poll task until recv() is called for this socket
    semaphore_guard: Arc<Mutex<Option<async_lock::SemaphoreGuardArc>>>,
    io_notify_data: Option<Arc<Mutex<IoNotifyData>>>,
}

#[derive(Debug)]
struct UdpSocketTask {
    inner: Arc<RiceUdpSocket>,
    readable: PollReadableTask,
}

#[derive(Debug)]
struct TcpSocketTask {
    inner: Arc<RiceTcpSocket>,
    readable: PollReadableTask,
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
                std::mem::swap(&mut udp.readable.io_notify_data, &mut notify_data);
            }
            for tcp in inner.tcp_sockets.values_mut() {
                let mut notify_data = notify_data.clone();
                std::mem::swap(&mut tcp.readable.io_notify_data, &mut notify_data);
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
    tcp_sockets: HashMap<(SocketAddr, SocketAddr), TcpSocketTask>,
}

pub type RiceIoNotify = Option<extern "C" fn(data: *mut c_void)>;
pub type RiceIoDestroy = Option<extern "C" fn(data: *mut c_void)>;

#[derive(Debug, Copy, Clone)]
struct SendPtr {
    ptr: *mut c_void,
}

unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

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
                readable: PollReadableTask {
                    poll_task: task,
                    semaphore_guard: poll_guard,
                    io_notify_data,
                },
            });
            true
        }
    };
    drop(inner);

    core::mem::forget(sockets);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn rice_sockets_add_tcp(
    sockets: *mut RiceSockets,
    tcp: *mut RiceTcpSocket,
) -> bool {
    let sockets = Arc::from_raw(sockets);
    let tcp = Arc::from_raw(tcp);
    let notify_data = sockets.notify_data.clone();
    let mut inner = sockets.inner.lock().unwrap();

    let local_addr = tcp.socket.get_ref().local_addr().unwrap();
    let remote_addr = tcp.socket.get_ref().peer_addr().unwrap();
    let entry = inner.tcp_sockets.entry((local_addr, remote_addr));
    let ret = match entry {
        std::collections::hash_map::Entry::Occupied(_) => false,
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let tcp_clone = tcp.clone();
            let semaphore = Arc::new(async_lock::Semaphore::new(1));
            let poll_guard = Arc::new(Mutex::new(None));
            let io_notify_data = notify_data
                .lock()
                .unwrap()
                .map(|notify| Arc::new(Mutex::new(notify.clone())));
            let (runnable, task) = async_task::spawn(
                {
                    debug!("staring tcp recv task for {local_addr:?} -> {remote_addr:?}");
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
                                tcp_clone.socket.poll_readable(cx)
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
            vacant.insert(TcpSocketTask {
                inner: tcp,
                readable: PollReadableTask {
                    poll_task: task,
                    semaphore_guard: poll_guard,
                    io_notify_data,
                },
            });
            runnable.run();
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
    let from_addr = RiceAddress::from_c(mut_override(from));
    let from = **from_addr;
    core::mem::forget(from_addr);
    let to_addr = RiceAddress::from_c(mut_override(to));
    let to = **to_addr;
    core::mem::forget(to_addr);
    let data = core::slice::from_raw_parts(data, len);
    let inner = sockets.inner.lock().unwrap();
    let ret = match transport {
        RiceTransportType::Udp => {
            if let Some(udp) = inner.udp_sockets.get(&from) {
                if udp.inner.socket.get_ref().send_to(data, to).is_err() {
                    RiceError::Failed
                } else {
                    RiceError::Success
                }
            } else {
                RiceError::NotFound
            }
        }
        RiceTransportType::Tcp => {
            use std::io::Write;
            if let Some(tcp) = inner.tcp_sockets.get(&(from, to)) {
                if tcp.inner.socket.get_ref().write_all(data).is_err() {
                    RiceError::Failed
                } else {
                    RiceError::Success
                }
            } else {
                RiceError::NotFound
            }
        }
    };

    drop(inner);
    core::mem::forget(sockets);
    ret
}

#[repr(C)]
pub struct RiceIoData {
    transport: RiceTransportType,
    from: *mut RiceAddress,
    to: *mut RiceAddress,
    len: usize,
}

unsafe fn rice_io_data_clear(data: &mut RiceIoData) {
    let _from = RiceAddress::from_c(data.from);
    data.from = core::ptr::null_mut();
    let _to = RiceAddress::from_c(data.to);
    data.to = core::ptr::null_mut();
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
    match &mut *recv {
        RiceIoRecv::Data(ref mut data) => {
            rice_io_data_clear(data);
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
                udp.readable.semaphore_guard.lock().unwrap().take();
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

    for (&(local_addr, remote_addr), tcp) in inner.tcp_sockets.iter_mut() {
        use std::io::Read;
        match tcp.inner.socket.get_ref().read(&mut data) {
            Ok(len) => {
                tcp.readable.semaphore_guard.lock().unwrap().take();
                *ret = RiceIoRecv::Data(RiceIoData {
                    transport: RiceTransportType::Tcp,
                    from: mut_override(RiceAddress::new(remote_addr).to_c()),
                    to: mut_override(RiceAddress::new(local_addr).to_c()),
                    len,
                });
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                warn!(
                    "Failed to receive data for TCP socket {local_addr:?} -> {remote_addr:?}: {e}"
                );
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
    use librice_proto::capi::*;
    use tracing::debug;

    #[test]
    fn rice_sockets_empty() {
        unsafe {
            // an emtpy list of sockets always returns WouldBlock
            let sockets = rice_sockets_new();
            let mut io_recv = RiceIoRecv::WouldBlock;
            let mut recv_buf = [0; 1500];
            rice_sockets_recv(sockets, recv_buf.as_mut_ptr(), recv_buf.len(), &mut io_recv);
            assert!(matches!(io_recv, RiceIoRecv::WouldBlock));
            rice_recv_clear(&mut io_recv);
            rice_sockets_unref(sockets);
        }
    }

    fn rice_sockets_new_with_io_notify_callback<F>(callback: F) -> *mut RiceSockets
    where
        F: FnMut() + Send + Sync + 'static,
    {
        extern "C" fn io_notify_trampoline<F: FnMut() + Send + Sync + 'static>(f: *mut c_void) {
            let f: &mut F = unsafe { &mut *(f as *mut F) };
            f();
        }
        unsafe {
            let callback = Box::into_raw(Box::new(callback));
            rice_sockets_new_with_notify(
                Some(io_notify_trampoline::<F>),
                callback as *mut _,
                Some(drop_box_fn::<F>),
            )
        }
    }

    extern "C" fn drop_box_fn<T>(data: *mut c_void) {
        unsafe {
            let _ = Box::from_raw(data as *mut T);
        }
    }

    #[test]
    fn udp_socket_send_recv() {
        unsafe {
            // send a receive data over UDP using our wrappers
            let (send, recv) = flume::unbounded::<()>();
            let addr = mut_override(RiceAddress::new("127.0.0.1:0".parse().unwrap()).to_c());
            let udp1 = rice_udp_socket_new(addr);
            let udp2 = rice_udp_socket_new(addr);
            rice_address_free(addr);

            let local_addr1 = rice_udp_socket_local_addr(udp1);
            let local_addr2 = rice_udp_socket_local_addr(udp2);

            let sockets = rice_sockets_new_with_io_notify_callback(move || {
                let _ = send.send(());
            });

            rice_sockets_add_udp(sockets, udp1);
            rice_sockets_add_udp(sockets, udp2);

            let data = [4; 6];
            assert_eq!(
                RiceError::Success,
                rice_sockets_send(
                    sockets,
                    RiceTransportType::Udp,
                    local_addr1,
                    local_addr2,
                    data.as_ptr(),
                    data.len()
                )
            );

            let _ = recv.recv().unwrap();

            let mut io_recv = RiceIoRecv::WouldBlock;
            let mut recv_buf = [0; 1500];
            rice_sockets_recv(sockets, recv_buf.as_mut_ptr(), recv_buf.len(), &mut io_recv);
            let RiceIoRecv::Data(mut io_data) = io_recv else {
                unreachable!();
            };
            assert_eq!(io_data.transport, RiceTransportType::Udp);
            assert_eq!(io_data.len, data.len());
            assert_eq!(&recv_buf[..io_data.len], data);
            assert_eq!(rice_address_cmp(io_data.from, local_addr1), 0);
            assert_eq!(rice_address_cmp(io_data.to, local_addr2), 0);
            rice_io_data_clear(&mut io_data);

            rice_address_free(local_addr1);
            rice_address_free(local_addr2);
            rice_sockets_unref(sockets);
        }
    }

    fn rice_tcp_listen_with_callback<F>(
        local_addr: *mut RiceAddress,
        callback: F,
    ) -> *mut RiceTcpListener
    where
        F: Fn(Option<Arc<RiceTcpSocket>>) + Send + Sync + 'static,
    {
        extern "C" fn listen_trampoline<
            F: Fn(Option<Arc<RiceTcpSocket>>) + Send + Sync + 'static,
        >(
            socket: *mut RiceTcpSocket,
            f: *mut c_void,
        ) {
            let socket = if socket.is_null() {
                None
            } else {
                unsafe { Some(Arc::from_raw(socket)) }
            };
            let f: &mut F = unsafe { &mut *(f as *mut F) };
            f(socket);
        }

        unsafe {
            let callback = Box::into_raw(Box::new(callback));
            rice_tcp_listen(
                local_addr,
                Some(listen_trampoline::<F>),
                callback as *mut _,
                Some(drop_box_fn::<F>),
            )
        }
    }

    fn rice_tcp_connect_with_callback<F>(
        remote_addr: *mut RiceAddress,
        callback: F,
        cancel: *mut RiceIoCancel,
    ) where
        F: Fn(Option<Arc<RiceTcpSocket>>) + Send + Sync + 'static,
    {
        extern "C" fn connect_trampoline<
            F: Fn(Option<Arc<RiceTcpSocket>>) + Send + Sync + 'static,
        >(
            socket: *mut RiceTcpSocket,
            f: *mut c_void,
        ) {
            let socket = if socket.is_null() {
                None
            } else {
                unsafe { Some(Arc::from_raw(socket)) }
            };
            let f = unsafe { Box::from_raw(f as *mut F) };
            f(socket);
        }

        unsafe {
            let callback = Box::into_raw(Box::new(callback));
            rice_tcp_connect(
                remote_addr,
                Some(connect_trampoline::<F>),
                callback as *mut _,
                cancel,
            )
        }
    }

    #[test]
    fn tcp_socket_send_recv() {
        #[derive(Debug)]
        enum Event {
            Io,
            Address(*mut RiceAddress),
        }
        unsafe impl Send for Event {}
        unsafe {
            // send a receive data over TCP using our wrappers
            let (send, recv) = flume::unbounded::<Event>();
            let sockets = Some(SendPtr::new(rice_sockets_new_with_io_notify_callback({
                let send = send.clone();
                move || {
                    trace!("send io event");
                    let _ = send.send(Event::Io);
                }
            }) as *mut c_void));

            let addr = mut_override(RiceAddress::new("127.0.0.1:0".parse().unwrap()).to_c());
            let listener = rice_tcp_listen_with_callback(addr, {
                let sockets = sockets.clone();
                move |tcp| {
                    if let Some(tcp) = tcp {
                        debug!("listener has incoming stream");
                        rice_sockets_add_tcp(
                            sockets.unwrap().ptr as *mut RiceSockets,
                            mut_override(Arc::into_raw(tcp)),
                        );
                    }
                }
            });
            rice_address_free(addr);

            let local_addr = rice_tcp_listener_local_addr(listener);

            rice_tcp_connect_with_callback(
                mut_override(local_addr),
                {
                    let sockets = sockets.clone();
                    move |tcp| {
                        if let Some(tcp) = tcp {
                            debug!("tcp connect created connection");
                            let tcp = mut_override(Arc::into_raw(tcp));
                            let addr = rice_tcp_socket_local_addr(tcp);
                            send.send(Event::Address(addr)).unwrap();
                            rice_sockets_add_tcp(
                                sockets.unwrap().ptr as *mut RiceSockets,
                                mut_override(tcp),
                            );
                        }
                    }
                },
                core::ptr::null_mut(),
            );
            let remote_addr;
            loop {
                let event = recv.recv().unwrap();
                debug!("{event:?}");
                let Event::Address(addr) = event else {
                    continue;
                };
                remote_addr = addr;
                break;
            }
            rice_tcp_listener_unref(listener);

            let data = [4; 6];
            assert_eq!(
                RiceError::Success,
                rice_sockets_send(
                    sockets.unwrap().ptr as *mut RiceSockets,
                    RiceTransportType::Tcp,
                    local_addr,
                    remote_addr,
                    data.as_ptr(),
                    data.len()
                )
            );

            let mut io_recv = RiceIoRecv::WouldBlock;
            let mut recv_buf = [0; 1500];
            rice_sockets_recv(
                sockets.unwrap().ptr as *mut RiceSockets,
                recv_buf.as_mut_ptr(),
                recv_buf.len(),
                &mut io_recv,
            );
            let RiceIoRecv::Data(mut io_data) = io_recv else {
                unreachable!();
            };
            assert_eq!(io_data.transport, RiceTransportType::Tcp);
            assert_eq!(io_data.len, data.len());
            assert_eq!(&recv_buf[..io_data.len], data);
            assert_eq!(rice_address_cmp(io_data.from, local_addr), 0);
            assert_eq!(rice_address_cmp(io_data.to, remote_addr), 0);
            rice_io_data_clear(&mut io_data);

            rice_address_free(local_addr);
            rice_address_free(remote_addr);
            rice_sockets_unref(sockets.unwrap().ptr as *mut RiceSockets);
        }
    }
}
