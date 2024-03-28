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
    let ipv4_destination = ipv4hdr.dst_addr;
    let ipv4_source = ipv4hdr.src_addr;

    let source_port;
    let destination_port;

    let combined_flags: u8;

    let header_length: u8;
    let data_length: u16 = (ctx.data_end() - ctx.data()) as u16;
    let length: u16;
    let protocol = ipv4hdr.proto as u8;
    let window_size: u8;
    
    match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            let tcphdr_ptr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;

            let tcphdr_u8 = tcphdr_ptr as *const u8;
            let data_offset_byte = unsafe { *tcphdr_u8.add(12) } as u8;
            let data_offset = (data_offset_byte >> 4) as u8;
            header_length = data_offset * 4;

            length = data_length as u16
                + header_length as u16
                + Ipv4Hdr::LEN as u16
                + EthHdr::LEN as u16;

            source_port = tcphdr.source;
            destination_port = tcphdr.dest;

            combined_flags = ((tcphdr.fin() as u8) << 0) | ((tcphdr.syn() as u8) << 1) | ((tcphdr.rst() as u8) << 2) | 
                         ((tcphdr.psh() as u8) << 3) | ((tcphdr.ack() as u8) << 4) | ((tcphdr.urg() as u8) << 5) | 
                         ((tcphdr.ece() as u8) << 6) | ((tcphdr.cwr() as u8) << 7);
            
            window_size = tcphdr.window as u8;

        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = udphdr.source;
            destination_port = udphdr.dest;

            header_length = UdpHdr::LEN as u8;
            length = data_length as u16
                + header_length as u16
                + Ipv4Hdr::LEN as u16
                + EthHdr::LEN as u16;

            combined_flags = 0;
            window_size = 0;
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let flow = PacketLog {
        ipv4_destination: ipv4_destination,
        ipv4_source: ipv4_source,
        port_destination: destination_port,
        port_source: source_port,
        combined_flags: combined_flags,
        length: length,
        protocol: protocol,
        header_length: header_length,
        data_length: data_length,
        window_size: window_size,
    };

    EVENTS_EGRESS.output(&ctx, &flow, 0);

    Ok(TC_ACT_PIPE)
}
