#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use common::PacketLog;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS_EGRESS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match try_tc_flow_track(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_flow_track(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4_destination = u32::from_be(ipv4hdr.dst_addr);
    let ipv4_source = u32::from_be(ipv4hdr.src_addr);

    let source_port;
    let destination_port;
    match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = u16::from_be(tcphdr.source);
            destination_port = u16::from_be(tcphdr.dest);
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = u16::from_be(udphdr.source);
            destination_port = u16::from_be(udphdr.dest);
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let flow = PacketLog {
        ipv4_destination: ipv4_destination,
        ipv4_source: ipv4_source,
        port_destination: destination_port,
        port_source: source_port,
    };

    // the zero value is a flag
    EVENTS_EGRESS.output(&ctx, &flow, 0);

    Ok(TC_ACT_PIPE)
}
