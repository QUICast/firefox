use crate::error::McrxError;
use crate::raw::{RawPacket, RawSubscriptionConfig};
use crate::subscription::SubscriptionId;
use socket2::Socket;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::config::SubscriptionAddressFamily;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::packet::ReceiveMetadata;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use bytes::Bytes;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use socket2::{Domain, Protocol, SockAddr, Type};
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::io::ErrorKind;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::net::{SocketAddrV4, SocketAddrV6};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
#[cfg(target_os = "macos")]
use std::sync::Mutex;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    IPPROTO_IP, IPPROTO_UDP, RCVALL_ON, SIO_RCVALL, SIO_RCVALL_MCAST, SOCKET, SOCKET_ERROR,
    WSAGetLastError, WSAIoctl,
};

pub(crate) struct RawReceiveSocket {
    receive_socket: Socket,
    membership_socket: Option<Socket>,
    #[cfg(windows)]
    windows_udp_receive_socket: Option<Socket>,
    #[cfg(target_os = "macos")]
    apple_bpf_buffer_len: usize,
    #[cfg(target_os = "macos")]
    apple_bpf_buffer: Mutex<Vec<u8>>,
    #[cfg(target_os = "macos")]
    apple_bpf_datalink: u32,
    #[cfg(target_os = "macos")]
    apple_interface_index: Option<u32>,
}

impl std::fmt::Debug for RawReceiveSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawReceiveSocket").finish_non_exhaustive()
    }
}

impl RawReceiveSocket {
    pub(crate) fn socket(&self) -> &Socket {
        &self.receive_socket
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedIpDatagram {
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: u8,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const MAX_RAW_FILTERED_READS_PER_RECV: usize = 256;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn raw_filter_budget_exhausted(filtered_reads: &mut usize) -> bool {
    // Raw capture sockets can see unrelated interface traffic. Keep one
    // non-blocking receive call bounded even when the interface is noisy.
    *filtered_reads += 1;
    *filtered_reads >= MAX_RAW_FILTERED_READS_PER_RECV
}

#[cfg(target_os = "linux")]
pub(crate) fn open_raw_socket(
    config: &RawSubscriptionConfig,
) -> Result<RawReceiveSocket, McrxError> {
    config.validate()?;

    let packet_socket = open_linux_packet_socket(config)?;
    let membership_socket = open_membership_socket(config.family())?;

    Ok(RawReceiveSocket {
        receive_socket: packet_socket,
        membership_socket: Some(membership_socket),
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn open_raw_socket(
    config: &RawSubscriptionConfig,
) -> Result<RawReceiveSocket, McrxError> {
    config.validate()?;

    let interface_index = resolve_packet_interface_index(config)?.ok_or_else(|| {
        McrxError::RawPacketReceiveUnsupported(
            "macOS raw multicast receive requires an explicit interface address or index"
                .to_string(),
        )
    })?;

    let bpf_socket = open_apple_bpf_socket(interface_index)?;
    let membership_socket = open_membership_socket(config.family())?;

    Ok(RawReceiveSocket {
        receive_socket: bpf_socket.socket,
        membership_socket: Some(membership_socket),
        apple_bpf_buffer_len: bpf_socket.buffer_len,
        apple_bpf_buffer: Mutex::new(vec![0u8; bpf_socket.buffer_len]),
        apple_bpf_datalink: bpf_socket.datalink,
        apple_interface_index: Some(interface_index),
    })
}

#[cfg(windows)]
pub(crate) fn open_raw_socket(
    config: &RawSubscriptionConfig,
) -> Result<RawReceiveSocket, McrxError> {
    config.validate()?;

    if config.is_ipv6() {
        return Err(McrxError::RawPacketReceiveUnsupported(
            "Windows raw multicast receive currently supports IPv4 only".to_string(),
        ));
    }

    let interface = match config.interface {
        Some(IpAddr::V4(interface)) if !interface.is_unspecified() => interface,
        _ => {
            return Err(McrxError::RawPacketReceiveUnsupported(
                "Windows raw IPv4 receive requires an explicit local IPv4 interface address"
                    .to_string(),
            ));
        }
    };

    let raw_socket = open_windows_raw_socket(interface)?;
    let udp_raw_socket = open_windows_udp_raw_socket(interface).ok();
    let membership_socket = open_membership_socket(config.family())?;

    Ok(RawReceiveSocket {
        receive_socket: raw_socket,
        membership_socket: Some(membership_socket),
        windows_udp_receive_socket: udp_raw_socket,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn open_raw_socket(
    _config: &RawSubscriptionConfig,
) -> Result<RawReceiveSocket, McrxError> {
    Err(McrxError::RawPacketReceiveUnsupported(
        "raw multicast receive is currently implemented on Linux, macOS, and Windows".to_string(),
    ))
}

pub(crate) fn join_raw_multicast_group(
    socket: &RawReceiveSocket,
    config: &RawSubscriptionConfig,
) -> Result<(), McrxError> {
    let membership_socket = socket.membership_socket.as_ref().ok_or_else(|| {
        McrxError::RawPacketReceiveUnsupported(
            "raw multicast membership sockets are not available on this platform".to_string(),
        )
    })?;

    let compat_config = config.membership_compat_config();
    super::join_multicast_group(membership_socket, &compat_config)?;

    #[cfg(windows)]
    join_windows_raw_receive_sockets(socket, &compat_config);

    Ok(())
}

pub(crate) fn leave_raw_multicast_group(
    socket: &RawReceiveSocket,
    config: &RawSubscriptionConfig,
) -> Result<(), McrxError> {
    let membership_socket = socket.membership_socket.as_ref().ok_or_else(|| {
        McrxError::RawPacketReceiveUnsupported(
            "raw multicast membership sockets are not available on this platform".to_string(),
        )
    })?;

    let compat_config = config.membership_compat_config();
    super::leave_multicast_group(membership_socket, &compat_config)?;

    #[cfg(windows)]
    leave_windows_raw_receive_sockets(socket, &compat_config);

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn recv_raw_packet(
    socket: &RawReceiveSocket,
    subscription_id: SubscriptionId,
    config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 65535];
    let mut filtered_reads = 0usize;

    loop {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let len = unsafe {
            libc::recvfrom(
                socket.socket().as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut addr as *mut libc::sockaddr_ll).cast(),
                &mut addr_len,
            )
        };

        if len == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(McrxError::ReceiveFailed(err));
        }

        let len = len as usize;
        // SAFETY: `recvfrom` initialized exactly the first `len` bytes of `buf`.
        let datagram = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };

        let Some(parsed) = parse_ip_datagram(datagram) else {
            if raw_filter_budget_exhausted(&mut filtered_reads) {
                return Ok(None);
            }
            continue;
        };

        if !packet_matches_config(parsed, config) {
            if raw_filter_budget_exhausted(&mut filtered_reads) {
                return Ok(None);
            }
            continue;
        }

        let mut metadata = ReceiveMetadata::empty();
        metadata.configured_interface = config.interface;
        metadata.configured_interface_index = config.interface_index;
        metadata.destination_local_ip = Some(parsed.destination_ip);
        if addr.sll_ifindex > 0 {
            metadata.ingress_interface_index = Some(addr.sll_ifindex as u32);
        }

        return Ok(Some(raw_packet_from_parts(
            subscription_id,
            datagram,
            parsed,
            metadata,
        )));
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn recv_raw_packet(
    socket: &RawReceiveSocket,
    subscription_id: SubscriptionId,
    config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    let mut filtered_reads = 0usize;

    loop {
        let mut buf = socket.apple_bpf_buffer.lock().map_err(|_| {
            McrxError::ReceiveFailed(std::io::Error::other("macOS BPF buffer mutex is poisoned"))
        })?;
        debug_assert_eq!(buf.len(), socket.apple_bpf_buffer_len);

        let len = unsafe {
            libc::read(
                socket.socket().as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };

        if len == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(McrxError::ReceiveFailed(err));
        }

        let packet_block = &buf[..len as usize];
        let Some(packet) = first_matching_apple_bpf_packet(
            packet_block,
            socket.apple_bpf_datalink,
            socket.apple_interface_index,
            subscription_id,
            config,
        )?
        else {
            if raw_filter_budget_exhausted(&mut filtered_reads) {
                return Ok(None);
            }
            continue;
        };

        return Ok(Some(packet));
    }
}

#[cfg(windows)]
pub(crate) fn recv_raw_packet(
    socket: &RawReceiveSocket,
    subscription_id: SubscriptionId,
    config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    if let Some(packet) =
        recv_raw_packet_from_windows_socket(&socket.receive_socket, subscription_id, config)?
    {
        return Ok(Some(packet));
    }

    if let Some(udp_socket) = &socket.windows_udp_receive_socket {
        return recv_raw_packet_from_windows_socket(udp_socket, subscription_id, config);
    }

    Ok(None)
}

#[cfg(windows)]
fn recv_raw_packet_from_windows_socket(
    receive_socket: &Socket,
    subscription_id: SubscriptionId,
    config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 65535];
    let mut filtered_reads = 0usize;

    loop {
        let len = unsafe {
            windows_sys::Win32::Networking::WinSock::recv(
                windows_raw_socket(receive_socket),
                buf.as_mut_ptr().cast(),
                buf.len() as i32,
                0,
            )
        };

        if len == SOCKET_ERROR {
            let err = last_wsa_error();
            if err.kind() == ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(McrxError::ReceiveFailed(err));
        }

        let len = len as usize;
        // SAFETY: `recv` initialized exactly the first `len` bytes of `buf`.
        let datagram = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };

        let Some(parsed) = parse_ip_datagram(datagram) else {
            if raw_filter_budget_exhausted(&mut filtered_reads) {
                return Ok(None);
            }
            continue;
        };

        if !packet_matches_config(parsed, config) {
            if raw_filter_budget_exhausted(&mut filtered_reads) {
                return Ok(None);
            }
            continue;
        }

        let mut metadata = ReceiveMetadata::empty();
        metadata.configured_interface = config.interface;
        metadata.configured_interface_index = config.interface_index;
        metadata.destination_local_ip = Some(parsed.destination_ip);

        return Ok(Some(raw_packet_from_parts(
            subscription_id,
            datagram,
            parsed,
            metadata,
        )));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn recv_raw_packet(
    _socket: &RawReceiveSocket,
    _subscription_id: SubscriptionId,
    _config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    Err(McrxError::RawPacketReceiveUnsupported(
        "raw multicast receive is currently implemented on Linux, macOS, and Windows".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn open_linux_packet_socket(config: &RawSubscriptionConfig) -> Result<Socket, McrxError> {
    let protocol = linux_packet_socket_protocol();
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol as i32,
        )
    };

    if raw_fd == -1 {
        return Err(McrxError::RawSocketCreateFailed(
            std::io::Error::last_os_error(),
        ));
    }

    let socket = unsafe { Socket::from_raw_fd(raw_fd) };
    let interface_index = resolve_linux_packet_interface_index(config)?;

    let bind_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol,
        sll_ifindex: interface_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&bind_addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    if result == -1 {
        return Err(McrxError::RawSocketBindFailed(
            std::io::Error::last_os_error(),
        ));
    }

    Ok(socket)
}

#[cfg(target_os = "linux")]
fn linux_packet_socket_protocol() -> u16 {
    (libc::ETH_P_ALL as u16).to_be()
}

#[cfg(target_os = "macos")]
struct AppleBpfSocket {
    socket: Socket,
    buffer_len: usize,
    datalink: u32,
}

#[cfg(target_os = "macos")]
fn open_apple_bpf_socket(interface_index: u32) -> Result<AppleBpfSocket, McrxError> {
    let interface_name = interface_name_from_index(interface_index)?;
    let socket = open_available_bpf_device()?;

    set_fd_nonblocking(socket.as_raw_fd())?;
    bind_bpf_to_interface(&socket, &interface_name)?;
    set_bpf_u32(&socket, libc::BIOCIMMEDIATE, 1)?;
    set_bpf_u32(&socket, libc::BIOCSSEESENT, 1)?;

    let buffer_len = get_bpf_u32(&socket, libc::BIOCGBLEN)? as usize;
    let datalink = get_bpf_u32(&socket, libc::BIOCGDLT)?;

    Ok(AppleBpfSocket {
        socket,
        buffer_len,
        datalink,
    })
}

#[cfg(target_os = "macos")]
fn open_available_bpf_device() -> Result<Socket, McrxError> {
    for index in 0..256 {
        let path = CString::new(format!("/dev/bpf{index}")).expect("BPF path has no nul bytes");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };

        if fd != -1 {
            return Ok(unsafe { Socket::from_raw_fd(fd) });
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            return Err(McrxError::RawSocketCreateFailed(err));
        }

        if err.raw_os_error() != Some(libc::EBUSY) && err.kind() != ErrorKind::NotFound {
            return Err(McrxError::RawSocketCreateFailed(err));
        }
    }

    Err(McrxError::RawSocketCreateFailed(std::io::Error::new(
        ErrorKind::NotFound,
        "no available /dev/bpf device found",
    )))
}

#[cfg(target_os = "macos")]
fn bind_bpf_to_interface(socket: &Socket, interface_name: &CStr) -> Result<(), McrxError> {
    let mut request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    let bytes = interface_name.to_bytes_with_nul();

    if bytes.len() > request.ifr_name.len() {
        return Err(McrxError::InterfaceDiscoveryFailed(format!(
            "interface name {} is too long for BPF",
            interface_name.to_string_lossy()
        )));
    }

    for (dst, src) in request.ifr_name.iter_mut().zip(bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }

    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::BIOCSETIF,
            (&mut request as *mut libc::ifreq).cast::<libc::c_void>(),
        )
    };

    if result == -1 {
        Err(McrxError::RawSocketBindFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn set_bpf_u32(socket: &Socket, request: libc::c_ulong, value: u32) -> Result<(), McrxError> {
    let mut value = value as libc::c_uint;
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            request,
            (&mut value as *mut libc::c_uint).cast::<libc::c_void>(),
        )
    };

    if result == -1 {
        Err(McrxError::SocketOptionFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn get_bpf_u32(socket: &Socket, request: libc::c_ulong) -> Result<u32, McrxError> {
    let mut value = 0 as libc::c_uint;
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            request,
            (&mut value as *mut libc::c_uint).cast::<libc::c_void>(),
        )
    };

    if result == -1 {
        Err(McrxError::SocketOptionFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(value)
    }
}

#[cfg(target_os = "macos")]
fn set_fd_nonblocking(fd: std::os::fd::RawFd) -> Result<(), McrxError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(McrxError::SocketOptionFailed(
            std::io::Error::last_os_error(),
        ));
    }

    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result == -1 {
        Err(McrxError::SocketOptionFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn interface_name_from_index(interface_index: u32) -> Result<CString, McrxError> {
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let ptr = unsafe { libc::if_indextoname(interface_index, name.as_mut_ptr()) };

    if ptr.is_null() {
        return Err(McrxError::InterfaceDiscoveryFailed(format!(
            "failed to resolve interface index {interface_index} to an interface name"
        )));
    }

    Ok(unsafe { CStr::from_ptr(ptr) }.to_owned())
}

#[cfg(windows)]
fn open_windows_raw_socket(interface: Ipv4Addr) -> Result<Socket, McrxError> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(IPPROTO_IP as i32)),
    )
    .map_err(McrxError::RawSocketCreateFailed)?;

    socket
        .bind(&SockAddr::from(SocketAddrV4::new(interface, 0)))
        .map_err(McrxError::RawSocketBindFailed)?;

    socket
        .set_nonblocking(true)
        .map_err(McrxError::SocketOptionFailed)?;

    enable_windows_raw_capture(&socket)?;
    Ok(socket)
}

#[cfg(windows)]
fn open_windows_udp_raw_socket(interface: Ipv4Addr) -> Result<Socket, McrxError> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(IPPROTO_UDP as i32)),
    )
    .map_err(McrxError::RawSocketCreateFailed)?;

    socket
        .bind(&SockAddr::from(SocketAddrV4::new(interface, 0)))
        .map_err(McrxError::RawSocketBindFailed)?;

    socket
        .set_nonblocking(true)
        .map_err(McrxError::SocketOptionFailed)?;

    Ok(socket)
}

#[cfg(windows)]
fn join_windows_raw_receive_sockets(socket: &RawReceiveSocket, config: &crate::SubscriptionConfig) {
    if !matches!(config.family(), SubscriptionAddressFamily::Ipv4) {
        return;
    }

    let _ = super::join_multicast_group(&socket.receive_socket, config);

    if let Some(udp_socket) = &socket.windows_udp_receive_socket {
        let _ = super::join_multicast_group(udp_socket, config);
    }
}

#[cfg(windows)]
fn leave_windows_raw_receive_sockets(
    socket: &RawReceiveSocket,
    config: &crate::SubscriptionConfig,
) {
    if !matches!(config.family(), SubscriptionAddressFamily::Ipv4) {
        return;
    }

    let _ = super::leave_multicast_group(&socket.receive_socket, config);

    if let Some(udp_socket) = &socket.windows_udp_receive_socket {
        let _ = super::leave_multicast_group(udp_socket, config);
    }
}

#[cfg(windows)]
fn enable_windows_raw_capture(socket: &Socket) -> Result<(), McrxError> {
    match windows_raw_capture_ioctl(socket, SIO_RCVALL_MCAST) {
        Ok(()) => Ok(()),
        Err(_) => windows_raw_capture_ioctl(socket, SIO_RCVALL),
    }
}

#[cfg(windows)]
fn windows_raw_capture_ioctl(socket: &Socket, code: u32) -> Result<(), McrxError> {
    let mode = RCVALL_ON;
    let mut bytes_returned = 0u32;
    let result = unsafe {
        WSAIoctl(
            windows_raw_socket(socket),
            code,
            (&mode as *const i32).cast(),
            std::mem::size_of_val(&mode) as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };

    if result == SOCKET_ERROR {
        Err(McrxError::SocketIoctlFailed(last_wsa_error()))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn windows_raw_socket(socket: &Socket) -> SOCKET {
    socket.as_raw_socket() as RawSocket as SOCKET
}

#[cfg(windows)]
fn last_wsa_error() -> std::io::Error {
    std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn open_membership_socket(family: SubscriptionAddressFamily) -> Result<Socket, McrxError> {
    let socket = match family {
        SubscriptionAddressFamily::Ipv4 => {
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .map_err(McrxError::SocketCreateFailed)?
        }
        SubscriptionAddressFamily::Ipv6 => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                .map_err(McrxError::SocketCreateFailed)?;
            socket
                .set_only_v6(true)
                .map_err(McrxError::SocketOptionFailed)?;
            socket
        }
    };

    socket
        .set_nonblocking(true)
        .map_err(McrxError::SocketOptionFailed)?;

    match family {
        SubscriptionAddressFamily::Ipv4 => socket
            .bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(McrxError::SocketBindFailed)?,
        SubscriptionAddressFamily::Ipv6 => socket
            .bind(&SockAddr::from(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            )))
            .map_err(McrxError::SocketBindFailed)?,
    }

    Ok(socket)
}

#[cfg(target_os = "linux")]
fn resolve_linux_packet_interface_index(config: &RawSubscriptionConfig) -> Result<u32, McrxError> {
    Ok(resolve_packet_interface_index(config)?.unwrap_or(0))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_packet_interface_index(
    config: &RawSubscriptionConfig,
) -> Result<Option<u32>, McrxError> {
    match (config.interface_index, config.interface) {
        (Some(interface_index), _) => Ok(Some(interface_index)),
        (None, Some(IpAddr::V6(interface))) if !interface.is_unspecified() => {
            super::resolve_ipv6_interface_index(interface).map(Some)
        }
        (None, Some(IpAddr::V4(interface))) if !interface.is_unspecified() => {
            resolve_ipv4_interface_index(interface).map(Some)
        }
        _ => Ok(None),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_ipv4_interface_index(interface: Ipv4Addr) -> Result<u32, McrxError> {
    unsafe {
        let mut ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Err(McrxError::InterfaceDiscoveryFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let mut cursor = ifaddrs;
        let mut matched_index = None;

        while !cursor.is_null() {
            let addr = (*cursor).ifa_addr;

            if !addr.is_null() && (*addr).sa_family as libc::c_int == libc::AF_INET {
                let sockaddr = &*(addr as *const libc::sockaddr_in);
                let candidate = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
                if candidate == interface {
                    let index = libc::if_nametoindex((*cursor).ifa_name);
                    if index != 0 {
                        matched_index = Some(index);
                        break;
                    }
                }
            }

            cursor = (*cursor).ifa_next;
        }

        libc::freeifaddrs(ifaddrs);

        matched_index.ok_or_else(|| {
            McrxError::InterfaceDiscoveryFailed(format!(
                "failed to resolve IPv4 interface address {interface} to an interface index"
            ))
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn packet_matches_config(parsed: ParsedIpDatagram, config: &RawSubscriptionConfig) -> bool {
    if !matches!(
        (config.family(), parsed.destination_ip),
        (SubscriptionAddressFamily::Ipv4, IpAddr::V4(_))
            | (SubscriptionAddressFamily::Ipv6, IpAddr::V6(_))
    ) {
        return false;
    }

    if parsed.destination_ip != config.group {
        return false;
    }

    match config.source {
        crate::SourceFilter::Any => true,
        crate::SourceFilter::Source(source) => parsed.source_ip == source,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn raw_packet_from_parts(
    subscription_id: SubscriptionId,
    datagram: &[u8],
    parsed: ParsedIpDatagram,
    metadata: ReceiveMetadata,
) -> RawPacket {
    RawPacket {
        subscription_id,
        datagram: Bytes::copy_from_slice(datagram),
        source_ip: Some(parsed.source_ip),
        group: Some(parsed.destination_ip),
        ip_protocol: Some(parsed.protocol),
        metadata,
    }
}

#[cfg(target_os = "macos")]
fn first_matching_apple_bpf_packet(
    packet_block: &[u8],
    datalink: u32,
    interface_index: Option<u32>,
    subscription_id: SubscriptionId,
    config: &RawSubscriptionConfig,
) -> Result<Option<RawPacket>, McrxError> {
    let mut offset = 0;
    let header_len = std::mem::size_of::<libc::bpf_hdr>();

    while offset + header_len <= packet_block.len() {
        let header = unsafe {
            std::ptr::read_unaligned(packet_block[offset..].as_ptr().cast::<libc::bpf_hdr>())
        };
        let data_start = offset + header.bh_hdrlen as usize;
        let data_end = data_start + header.bh_caplen as usize;

        if data_end > packet_block.len() {
            break;
        }

        let frame = &packet_block[data_start..data_end];
        let Some(datagram) = strip_apple_link_layer(frame, datalink)? else {
            offset += bpf_word_align(header.bh_hdrlen as usize + header.bh_caplen as usize);
            continue;
        };

        let Some(parsed) = parse_ip_datagram(datagram) else {
            offset += bpf_word_align(header.bh_hdrlen as usize + header.bh_caplen as usize);
            continue;
        };

        if packet_matches_config(parsed, config) {
            let mut metadata = ReceiveMetadata::empty();
            metadata.configured_interface = config.interface;
            metadata.configured_interface_index = config.interface_index;
            metadata.destination_local_ip = Some(parsed.destination_ip);
            metadata.ingress_interface_index = interface_index;

            return Ok(Some(raw_packet_from_parts(
                subscription_id,
                datagram,
                parsed,
                metadata,
            )));
        }

        offset += bpf_word_align(header.bh_hdrlen as usize + header.bh_caplen as usize);
    }

    Ok(None)
}

#[cfg(target_os = "macos")]
fn strip_apple_link_layer(frame: &[u8], datalink: u32) -> Result<Option<&[u8]>, McrxError> {
    match datalink {
        libc::DLT_RAW => Ok(Some(frame)),
        libc::DLT_NULL | libc::DLT_LOOP => Ok(frame.get(4..)),
        libc::DLT_EN10MB => Ok(strip_ethernet_link_layer(frame)),
        other => Err(McrxError::RawPacketReceiveUnsupported(format!(
            "macOS BPF datalink type {other} is not supported yet"
        ))),
    }
}

#[cfg(any(target_os = "macos", test))]
fn strip_ethernet_link_layer(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }

    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut payload_offset = 14;

    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < payload_offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[payload_offset + 2], frame[payload_offset + 3]]);
        payload_offset += 4;
    }

    match ethertype {
        0x0800 | 0x86dd => frame.get(payload_offset..),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn bpf_word_align(value: usize) -> usize {
    let alignment = libc::BPF_ALIGNMENT as usize;
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
fn parse_ip_datagram(datagram: &[u8]) -> Option<ParsedIpDatagram> {
    let version = datagram.first().map(|byte| byte >> 4)?;
    match version {
        4 => parse_ipv4_datagram(datagram),
        6 => parse_ipv6_datagram(datagram),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
fn parse_ipv4_datagram(datagram: &[u8]) -> Option<ParsedIpDatagram> {
    if datagram.len() < 20 {
        return None;
    }

    let ihl = ((datagram[0] & 0x0f) as usize) * 4;
    if ihl < 20 || datagram.len() < ihl {
        return None;
    }

    Some(ParsedIpDatagram {
        source_ip: IpAddr::V4(Ipv4Addr::new(
            datagram[12],
            datagram[13],
            datagram[14],
            datagram[15],
        )),
        destination_ip: IpAddr::V4(Ipv4Addr::new(
            datagram[16],
            datagram[17],
            datagram[18],
            datagram[19],
        )),
        protocol: datagram[9],
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
fn parse_ipv6_datagram(datagram: &[u8]) -> Option<ParsedIpDatagram> {
    if datagram.len() < 40 {
        return None;
    }

    let source = <[u8; 16]>::try_from(&datagram[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&datagram[24..40]).ok()?;

    Some(ParsedIpDatagram {
        source_ip: IpAddr::V6(Ipv6Addr::from(source)),
        destination_ip: IpAddr::V6(Ipv6Addr::from(destination)),
        protocol: datagram[6],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_datagram_fields() {
        let datagram = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 10, 1, 2, 3,
            239, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8,
        ];

        let parsed = parse_ip_datagram(&datagram).unwrap();
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))
        );
        assert_eq!(parsed.protocol, 17);
    }

    #[test]
    fn parses_ipv6_datagram_fields() {
        let mut datagram = [0u8; 40];
        datagram[0] = 0x60;
        datagram[6] = 17;
        datagram[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        datagram[24..40].copy_from_slice(&"ff3e::8000:1234".parse::<Ipv6Addr>().unwrap().octets());

        let parsed = parse_ip_datagram(&datagram).unwrap();
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6("ff3e::8000:1234".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parsed.protocol, 17);
    }

    #[test]
    fn malformed_datagram_is_rejected() {
        assert!(parse_ip_datagram(&[0x45, 0x00, 0x00]).is_none());
        assert!(parse_ip_datagram(&[0x70; 8]).is_none());
    }

    #[test]
    fn packet_filter_rejects_ipv6_for_ipv4_subscription() {
        let parsed = ParsedIpDatagram {
            source_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination_ip: IpAddr::V6("ff3e::8000:1234".parse().unwrap()),
            protocol: 17,
        };
        let config = RawSubscriptionConfig::asm(Ipv4Addr::new(239, 1, 2, 3));

        assert!(!packet_matches_config(parsed, &config));
    }

    #[test]
    fn packet_filter_rejects_ipv4_for_ipv6_subscription() {
        let parsed = ParsedIpDatagram {
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            protocol: 17,
        };
        let config = RawSubscriptionConfig::asm_v6("ff3e::8000:1234".parse().unwrap());

        assert!(!packet_matches_config(parsed, &config));
    }

    #[test]
    fn strips_ethernet_ipv4_frame() {
        let frame = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 20, 0, 0, 0, 0, 1, 17, 0,
            0, 10, 1, 2, 3, 239, 1, 2, 3,
        ];

        let datagram = strip_ethernet_link_layer(&frame).unwrap();
        let parsed = parse_ip_datagram(datagram).unwrap();

        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))
        );
    }

    #[test]
    fn strips_vlan_ethernet_ipv6_frame() {
        let mut frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0, 1, 0x86, 0xdd,
        ];
        let mut datagram = [0u8; 40];
        datagram[0] = 0x60;
        datagram[6] = 17;
        datagram[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        datagram[24..40].copy_from_slice(&"ff3e::8000:1234".parse::<Ipv6Addr>().unwrap().octets());
        frame.extend_from_slice(&datagram);

        let stripped = strip_ethernet_link_layer(&frame).unwrap();
        let parsed = parse_ip_datagram(stripped).unwrap();

        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6("ff3e::8000:1234".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn ignores_non_ip_ethernet_frame() {
        let frame = [0u8; 14];
        assert!(strip_ethernet_link_layer(&frame).is_none());
    }
}
