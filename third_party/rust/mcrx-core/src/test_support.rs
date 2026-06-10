#![cfg(test)]

use crate::{Context, Packet, SourceFilter, SubscriptionConfig};
use socket2::SockRef;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

/// Creates a standard ASM test subscription configuration on the given port.
pub(crate) fn sample_config(port: u16) -> SubscriptionConfig {
    SubscriptionConfig {
        group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
        source: SourceFilter::Any,
        dst_port: port,
        interface: None,
        interface_index: None,
    }
}

/// Returns an unused IPv4 UDP port for tests that need to bind a receive socket.
pub(crate) fn unused_udp_port_v4() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Returns an unused IPv6 UDP port for tests that need to bind a receive socket.
pub(crate) fn unused_udp_port_v6() -> u16 {
    UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Creates a standard ASM test subscription configuration on an unused IPv4
/// UDP port. The port is only reserved long enough to discover it, so callers
/// should bind the actual receive socket immediately.
pub(crate) fn sample_config_on_unused_port() -> SubscriptionConfig {
    sample_config(unused_udp_port_v4())
}

/// Creates a standard IPv6 ASM test subscription configuration on an unused
/// IPv6 UDP port.
pub(crate) fn sample_config_v6_on_unused_port() -> SubscriptionConfig {
    sample_config_v6(unused_udp_port_v6())
}

/// Creates a standard IPv6 ASM test subscription configuration on the given port.
pub(crate) fn sample_config_v6(port: u16) -> SubscriptionConfig {
    let mut config = SubscriptionConfig::asm_v6("ff01::1234".parse().unwrap(), port);
    config.interface = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    config
}

/// Creates a standard IPv6 SSM test subscription configuration on the given port.
pub(crate) fn sample_ssm_config_v6(port: u16) -> Option<SubscriptionConfig> {
    let interface = ssm_test_interface_v6()?;
    #[cfg(target_vendor = "apple")]
    let source = ssm_test_routable_source_v6(interface);
    #[cfg(not(target_vendor = "apple"))]
    let source = interface;

    let group = if interface == Ipv6Addr::LOCALHOST {
        "ff31::1234"
    } else {
        "ff3e::1234"
    };

    let mut config = SubscriptionConfig::ssm_v6(group.parse().unwrap(), source, port);
    config.interface = Some(IpAddr::V6(interface));
    Some(config)
}

/// Creates an IPv6 SSM configuration that can be exercised end-to-end with a
/// same-host sender. macOS returns `None` here because its SSM join path wants
/// a routable source distinct from the host-local loopback source.
pub(crate) fn sample_ssm_receive_config_v6(port: u16) -> Option<SubscriptionConfig> {
    #[cfg(target_vendor = "apple")]
    {
        let _ = port;
        None
    }

    #[cfg(not(target_vendor = "apple"))]
    {
        sample_ssm_config_v6(port)
    }
}

/// Creates an IPv6 SSM receive test configuration on an unused IPv6 UDP port.
pub(crate) fn sample_ssm_receive_config_v6_on_unused_port() -> Option<SubscriptionConfig> {
    sample_ssm_receive_config_v6(unused_udp_port_v6())
}

/// Receives the next packet from the context before the given deadline.
pub(crate) fn recv_next_packet(context: &mut Context, deadline: Instant) -> Packet {
    loop {
        match context.try_recv_any().unwrap() {
            Some(packet) => return packet,
            None if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            None => panic!("timed out waiting for packet from context"),
        }
    }
}

/// Creates a multicast-capable UDP sender socket for tests.
pub(crate) fn make_multicast_sender() -> UdpSocket {
    let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    sender.set_multicast_loop_v4(true).unwrap();
    sender.set_multicast_ttl_v4(1).unwrap();
    sender
}

/// Creates an IPv6 multicast-capable UDP sender socket for tests.
pub(crate) fn make_multicast_sender_v6(interface: Ipv6Addr) -> UdpSocket {
    let sender = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).unwrap();
    sender.set_multicast_loop_v6(true).unwrap();

    let socket = SockRef::from(&sender);
    socket.set_multicast_hops_v6(1).unwrap();

    let ifindex = crate::platform::resolve_ipv6_interface_index(interface).unwrap();
    socket.set_multicast_if_v6(ifindex).unwrap();

    sender
}

/// Creates an IPv6 multicast-capable UDP sender socket bound to the expected
/// SSM source address for tests.
pub(crate) fn make_multicast_sender_v6_for_source(source: Ipv6Addr) -> UdpSocket {
    let ifindex = crate::platform::resolve_ipv6_interface_index(source).unwrap();
    let scope_id = if source.is_unicast_link_local() {
        ifindex
    } else {
        0
    };

    let sender = UdpSocket::bind(SocketAddrV6::new(source, 0, 0, scope_id)).unwrap();
    sender.set_multicast_loop_v6(true).unwrap();

    let socket = SockRef::from(&sender);
    socket.set_multicast_hops_v6(1).unwrap();
    socket.set_multicast_if_v6(ifindex).unwrap();

    sender
}

pub(crate) fn ipv6_group(config: &SubscriptionConfig) -> Ipv6Addr {
    config.ipv6_membership().unwrap().group
}

pub(crate) fn ipv6_group_socket_addr(config: &SubscriptionConfig) -> SocketAddrV6 {
    let ifindex = match config.interface_index {
        Some(interface_index) => interface_index,
        None => {
            let interface = match config.interface {
                Some(IpAddr::V6(interface)) => interface,
                _ => Ipv6Addr::LOCALHOST,
            };
            crate::platform::resolve_ipv6_interface_index(interface).unwrap()
        }
    };
    SocketAddrV6::new(ipv6_group(config), config.dst_port, 0, ifindex)
}

#[cfg(target_vendor = "apple")]
fn ssm_test_interface_v6() -> Option<Ipv6Addr> {
    unsafe {
        let mut ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return None;
        }

        let mut cursor = ifaddrs;
        let mut fallback = None;

        while !cursor.is_null() {
            let addr = (*cursor).ifa_addr;
            let flags = (*cursor).ifa_flags as libc::c_int;

            if !addr.is_null()
                && (*addr).sa_family as libc::c_int == libc::AF_INET6
                && (flags & libc::IFF_LOOPBACK) == 0
            {
                let sockaddr = &*(addr as *const libc::sockaddr_in6);
                let candidate = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);

                if candidate.is_unspecified() || candidate.is_multicast() {
                    cursor = (*cursor).ifa_next;
                    continue;
                }

                if !candidate.is_unicast_link_local() {
                    libc::freeifaddrs(ifaddrs);
                    return Some(candidate);
                }

                fallback.get_or_insert(candidate);
            }

            cursor = (*cursor).ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
        fallback
    }
}

#[cfg(not(target_vendor = "apple"))]
fn ssm_test_interface_v6() -> Option<Ipv6Addr> {
    Some(Ipv6Addr::LOCALHOST)
}

#[cfg(target_vendor = "apple")]
fn ssm_test_routable_source_v6(interface: Ipv6Addr) -> Ipv6Addr {
    let mut octets = interface.octets();
    octets[15] ^= 1;
    let candidate = Ipv6Addr::from(octets);
    if candidate.is_multicast() || candidate.is_unspecified() {
        interface
    } else {
        candidate
    }
}
