#[path = "common/recv_args.rs"]
mod recv_args;

use mcrx_core::{RawContext, RawSubscriptionConfig};
use std::env;
use std::process;
use std::thread;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_PREVIEW_LEN: usize = 64;

fn main() {
    if let Err(err) = run() {
        eprintln!("mcrx-raw-recv: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Err("invalid arguments".to_string());
    }

    let parsed = match recv_args::parse_raw_receive_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            print_usage(&args[0]);
            return Err(err);
        }
    };

    let mut config = match parsed.source {
        Some(source) => RawSubscriptionConfig::ssm_ip(parsed.group, source),
        None => RawSubscriptionConfig::asm_ip(parsed.group),
    };
    config.interface = parsed.interface;
    config.interface_index = parsed.interface_index;

    let mut ctx = RawContext::new();
    let id = ctx
        .add_subscription(config)
        .map_err(|err| format!("failed to add raw subscription: {err}"))?;
    ctx.join_subscription(id)
        .map_err(|err| format!("failed to join raw subscription: {err}"))?;

    println!("mcrx-raw-recv ready");
    println!("  group:      {}", parsed.group);
    println!(
        "  source:     {}",
        parsed
            .source
            .map(|source| source.to_string())
            .unwrap_or_else(|| "any".to_string())
    );
    println!(
        "  interface:  {}",
        match (parsed.interface, parsed.interface_index) {
            (Some(interface), Some(index)) => format!("{interface}%{index}"),
            (Some(interface), None) => interface.to_string(),
            (None, Some(index)) => index.to_string(),
            (None, None) => "default".to_string(),
        }
    );
    println!("  sub_id:     {}", id.0);
    println!();
    println!("waiting for raw multicast IP datagrams ...");

    loop {
        match ctx.try_recv_any() {
            Ok(Some(packet)) => {
                println!(
                    "received {} raw bytes source={:?} group={:?} protocol={:?} ingress_if={:?}",
                    packet.datagram_len(),
                    packet.source_ip,
                    packet.group,
                    packet.ip_protocol,
                    packet.metadata.ingress_interface_index,
                );

                let preview_len = packet.datagram_len().min(MAX_PREVIEW_LEN);
                println!("  first bytes: {:02x?}", &packet.datagram()[..preview_len]);
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(err) => return Err(format!("failed to receive raw packet: {err}")),
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("usage: {program} <group> [source] [interface]");
    eprintln!("       {program} <group> [--source <source>] [--interface <interface>]");
    eprintln!("  group      multicast group, e.g. 239.1.2.3 or ff3e::8000:1234");
    eprintln!("  source     optional source for SSM");
    eprintln!("  interface  optional local interface address or IPv6 interface index");
    eprintln!("examples:");
    eprintln!("  {program} 239.1.2.3 --interface 192.168.1.20");
    eprintln!("  {program} ff3e::8000:1234 --interface 7");
    eprintln!("  {program} ff3e::8000:1234 2001:db8::10 --interface 2001:db8::20");
    eprintln!("notes:");
    eprintln!("  - for IPv4 SSM, use 232.0.0.0/8 groups such as 232.1.2.3");
    eprintln!("  - for IPv6 SSM, use ff3x::/32 groups such as ff3e::8000:1234");
}
