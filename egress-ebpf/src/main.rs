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
use core::mem;

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

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
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
    let protocol = ipv4hdr.proto as u8;

    let mut fin_flag_count = 0 as u8;

    let header_length: u32;
    let data_length: usize = ctx.data_end() - ctx.data();
    let length: u32;
    
    match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            let tcphdr_ptr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;

            // Cast the `TcpHdr` pointer to a `*const u8` to read individual bytes
            let tcphdr_u8 = tcphdr_ptr as *const u8;
            // Read the 12th byte (offset 12 from the TCP header start)
            let data_offset_byte = unsafe { *tcphdr_u8.add(12) } as u8;
            // Extract the high-order 4 bits and shift right by 4 to get the 'data offset' value
            let data_offset = (data_offset_byte >> 4) as u32;
            // Calculate the TCP header size in bytes
            header_length = data_offset * 4;

            length = data_length as u32
                + header_length as u32
                + Ipv4Hdr::LEN as u32
                + EthHdr::LEN as u32;

            source_port = u16::from_be(tcphdr.source);
            destination_port = u16::from_be(tcphdr.dest);

            fin_flag_count = (tcphdr.fin() != 0) as u8;
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = u16::from_be(udphdr.source);
            destination_port = u16::from_be(udphdr.dest);

            header_length = UdpHdr::LEN as u32;
            
            length = data_length as u32
                + header_length as u32
                + Ipv4Hdr::LEN as u32
                + EthHdr::LEN as u32;
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let flow = PacketLog {
        ipv4_destination: ipv4_destination,
        ipv4_source: ipv4_source,
        port_destination: destination_port,
        port_source: source_port,
        protocol: protocol,
        header_length: header_length,
        data_length: data_length as u32,
        length: length,
        fin_flag: fin_flag_count,
    };

    // the zero value is a flag
    EVENTS_EGRESS.output(&ctx, &flow, 0);

    Ok(TC_ACT_PIPE)
}
