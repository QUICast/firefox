use std::ffi::CString;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ReceiveCliArgs {
    pub(crate) group: IpAddr,
    pub(crate) dst_port: u16,
    pub(crate) source: Option<IpAddr>,
    pub(crate) interface: Option<IpAddr>,
    pub(crate) interface_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct RawReceiveCliArgs {
    pub(crate) group: IpAddr,
    pub(crate) source: Option<IpAddr>,
    pub(crate) interface: Option<IpAddr>,
    pub(crate) interface_index: Option<u32>,
}

type ParsedInterface = (Option<IpAddr>, Option<u32>);
type ParsedSourceAndInterface = (Option<IpAddr>, Option<IpAddr>, Option<u32>);

#[allow(dead_code)]
pub(crate) fn parse_receive_cli_args(args: &[String]) -> Result<ReceiveCliArgs, String> {
    if args.len() < 3 {
        return Err("invalid arguments".to_string());
    }

    let group = parse_ip("group", &args[1])?;
    let dst_port = parse_port(&args[2])?;
    let remainder = &args[3..];

    let (source, interface, interface_index) = parse_mixed_args(group, remainder)?;

    if !group.is_multicast() {
        return Err(format!("group address {group} is not multicast"));
    }

    Ok(ReceiveCliArgs {
        group,
        dst_port,
        source,
        interface,
        interface_index,
    })
}

#[allow(dead_code)]
pub(crate) fn parse_raw_receive_cli_args(args: &[String]) -> Result<RawReceiveCliArgs, String> {
    if args.len() < 2 {
        return Err("invalid arguments".to_string());
    }

    let group = parse_ip("group", &args[1])?;
    let remainder = &args[2..];

    let (source, interface, interface_index) = parse_mixed_args(group, remainder)?;

    if !group.is_multicast() {
        return Err(format!("group address {group} is not multicast"));
    }

    Ok(RawReceiveCliArgs {
        group,
        source,
        interface,
        interface_index,
    })
}

fn parse_flag_args(
    group: IpAddr,
    remainder: &[String],
) -> Result<ParsedSourceAndInterface, String> {
    let mut source = None;
    let mut interface = None;
    let mut interface_index = None;
    let mut index = 0usize;

    while index < remainder.len() {
        match remainder[index].as_str() {
            "--source" => {
                let value = remainder
                    .get(index + 1)
                    .ok_or_else(|| "missing value after --source".to_string())?;
                source = Some(parse_ip("source", value)?);
                index += 2;
            }
            "--interface" => {
                let value = remainder
                    .get(index + 1)
                    .ok_or_else(|| "missing value after --interface".to_string())?;
                let parsed = parse_interface_value(group, value)?;
                interface = parsed.0;
                interface_index = parsed.1;
                index += 2;
            }
            other => {
                return Err(format!("unexpected argument '{other}'"));
            }
        }
    }

    Ok((source, interface, interface_index))
}

fn parse_mixed_args(
    group: IpAddr,
    remainder: &[String],
) -> Result<ParsedSourceAndInterface, String> {
    let mut positional = Vec::new();
    let mut flagged = Vec::new();
    let mut index = 0usize;

    while index < remainder.len() {
        if remainder[index].starts_with("--") {
            flagged.push(remainder[index].clone());
            let value = remainder
                .get(index + 1)
                .ok_or_else(|| format!("missing value after {}", remainder[index]))?;
            flagged.push(value.clone());
            index += 2;
        } else {
            positional.push(remainder[index].clone());
            index += 1;
        }
    }

    let (mut source, mut interface, mut interface_index) = parse_flag_args(group, &flagged)?;

    let mut positional = positional.into_iter();

    if source.is_none()
        && let Some(value) = positional.next()
    {
        source = Some(parse_ip("source", &value)?);
    }

    if interface.is_none()
        && let Some(value) = positional.next()
    {
        let parsed = parse_interface_value(group, &value)?;
        interface = parsed.0;
        interface_index = parsed.1;
    }

    if positional.next().is_some() {
        return Err("invalid arguments".to_string());
    }

    Ok((source, interface, interface_index))
}

fn parse_ip(name: &str, value: &str) -> Result<IpAddr, String> {
    value
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid {name} '{value}': {err}"))
}

fn parse_interface_value(group: IpAddr, value: &str) -> Result<ParsedInterface, String> {
    if group.is_ipv6() {
        if let Some((addr, scope)) = value.rsplit_once('%') {
            let addr = addr
                .parse::<std::net::Ipv6Addr>()
                .map_err(|err| format!("invalid interface '{value}': {err}"))?;
            let scope = parse_interface_scope(scope)?;
            return Ok((Some(IpAddr::V6(addr)), Some(scope)));
        }

        if value.chars().all(|ch| ch.is_ascii_digit()) {
            let scope = parse_interface_scope(value)?;
            return Ok((None, Some(scope)));
        }
    }

    Ok((Some(parse_ip("interface", value)?), None))
}

fn parse_interface_scope(value: &str) -> Result<u32, String> {
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        let scope = value
            .parse::<u32>()
            .map_err(|err| format!("invalid interface index '{value}': {err}"))?;
        if scope == 0 {
            return Err("interface index must not be 0".to_string());
        }
        return Ok(scope);
    }

    interface_name_to_index(value)
        .map_err(|err| format!("invalid interface scope '{value}': {err}"))
}

fn interface_name_to_index(name: &str) -> Result<u32, String> {
    let name =
        CString::new(name).map_err(|_| "interface name must not contain NUL bytes".to_string())?;

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex;

        let index = if_nametoindex(name.as_ptr().cast());
        if index == 0 {
            return Err("unknown interface name".to_string());
        }
        Ok(index)
    }

    #[cfg(not(windows))]
    unsafe {
        let index = libc::if_nametoindex(name.as_ptr());
        if index == 0 {
            return Err("unknown interface name".to_string());
        }
        Ok(index)
    }
}

#[allow(dead_code)]
fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|err| format!("invalid dst_port '{value}': {err}"))?;

    if port == 0 {
        return Err("dst_port must not be 0".to_string());
    }

    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn parses_legacy_positional_asm_args() {
        let args = argv(&["mcrx-recv", "239.1.2.3", "5000"]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(parsed.group, IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)));
        assert_eq!(parsed.dst_port, 5000);
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.interface, None);
        assert_eq!(parsed.interface_index, None);
    }

    #[test]
    fn parses_flagged_interface_for_ipv6_asm() {
        let args = argv(&["mcrx-recv-meta", "ff01::1234", "5000", "--interface", "::1"]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.group,
            IpAddr::V6("ff01::1234".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parsed.dst_port, 5000);
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.interface, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(parsed.interface_index, None);
    }

    #[test]
    fn parses_flagged_source_and_interface() {
        let args = argv(&[
            "mcrx-recv",
            "232.1.2.3",
            "5000",
            "--source",
            "192.168.1.10",
            "--interface",
            "192.168.1.20",
        ]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.source,
            Some(IpAddr::V4("192.168.1.10".parse::<Ipv4Addr>().unwrap()))
        );
        assert_eq!(
            parsed.interface,
            Some(IpAddr::V4("192.168.1.20".parse::<Ipv4Addr>().unwrap()))
        );
        assert_eq!(parsed.interface_index, None);
    }

    #[test]
    fn parses_positional_source_with_flagged_interface() {
        let args = argv(&[
            "mcrx-recv-meta",
            "ff12::1234",
            "5000",
            "fd06:ba51:f296:0:1caf:6b66:e6f7:4b10",
            "--interface",
            "fd06:ba51:f296:0:1caf:6b66:e6f7:4b10",
        ]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.source,
            Some(IpAddr::V6(
                "fd06:ba51:f296:0:1caf:6b66:e6f7:4b10"
                    .parse::<Ipv6Addr>()
                    .unwrap()
            ))
        );
        assert_eq!(
            parsed.interface,
            Some(IpAddr::V6(
                "fd06:ba51:f296:0:1caf:6b66:e6f7:4b10"
                    .parse::<Ipv6Addr>()
                    .unwrap()
            ))
        );
        assert_eq!(parsed.interface_index, None);
    }

    #[test]
    fn parses_scoped_ipv6_interface() {
        let args = argv(&[
            "mcrx-recv-meta",
            "ff32::8000:1234",
            "5000",
            "--interface",
            "fe80::1%7",
        ]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.interface,
            Some(IpAddr::V6("fe80::1".parse().unwrap()))
        );
        assert_eq!(parsed.interface_index, Some(7));
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn parses_scoped_ipv6_interface_with_name() {
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const LOOPBACK_INTERFACE: &str = "lo0";
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const LOOPBACK_INTERFACE: &str = "lo";

        let scoped_interface = format!("fe80::1%{LOOPBACK_INTERFACE}");
        let args = argv(&[
            "mcrx-recv-meta",
            "ff32::8000:1234",
            "5000",
            "--interface",
            &scoped_interface,
        ]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.interface,
            Some(IpAddr::V6("fe80::1".parse().unwrap()))
        );
        assert!(parsed.interface_index.unwrap() > 0);
    }

    #[test]
    fn parses_numeric_ipv6_interface_index() {
        let args = argv(&[
            "mcrx-recv-meta",
            "ff3e::8000:1234",
            "5000",
            "--interface",
            "9",
        ]);

        let parsed = parse_receive_cli_args(&args).unwrap();

        assert_eq!(parsed.interface, None);
        assert_eq!(parsed.interface_index, Some(9));
    }

    #[test]
    fn parses_raw_receive_args_without_port() {
        let args = argv(&[
            "mcrx-raw-recv",
            "ff3e::8000:1234",
            "2001:db8::10",
            "--interface",
            "7",
        ]);

        let parsed = parse_raw_receive_cli_args(&args).unwrap();

        assert_eq!(
            parsed.group,
            IpAddr::V6("ff3e::8000:1234".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(
            parsed.source,
            Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(parsed.interface, None);
        assert_eq!(parsed.interface_index, Some(7));
    }
}
