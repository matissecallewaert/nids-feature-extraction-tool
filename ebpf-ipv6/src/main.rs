#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use common::BasicFeaturesIpv6;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS_IPV6: PerfEventArray<BasicFeaturesIpv6> = PerfEventArray::with_max_entries(1024, 0);

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
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv6 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let bytes_ipv6_source = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
    let bytes_ipv6_destination = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr8 };

    let ipv6_source = u128::from_be_bytes(bytes_ipv6_source);
    let ipv6_destination = u128::from_be_bytes(bytes_ipv6_destination);

    let source_port: u16;
    let destination_port: u16;

    let protocol: u8;

    let mut fin_flag_count = 0 as u8;
    let mut syn_flag_count = 0 as u8;
    let mut rst_flag_count = 0 as u8;
    let mut psh_flag_count = 0 as u8;
    let mut ack_flag_count = 0 as u8;
    let mut urg_flag_count = 0 as u8;
    let mut cwe_flag_count = 0 as u8;
    let mut ece_flag_count = 0 as u8;

    let header_length: u32;
    let data_length: usize = ctx.data_end() - ctx.data();
    let length: u32;
    let mut window_size: u16 = 0;

    match unsafe { *ipv6hdr }.next_hdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;

            // Cast the `TcpHdr` pointer to a `*const u8` to read individual bytes
            let tcphdr_u8 = tcphdr as *const u8;
            // Read the 12th byte (offset 12 from the TCP header start)
            let data_offset_byte = unsafe { *tcphdr_u8.add(12) } as u8;
            // Extract the high-order 4 bits and shift right by 4 to get the 'data offset' value
            let data_offset = (data_offset_byte >> 4) as u32;
            // Calculate the TCP header size in bytes
            header_length = data_offset * 4;

            length = data_length as u32
                + header_length as u32
                + Ipv6Hdr::LEN as u32
                + EthHdr::LEN as u32;

            source_port = u16::from_be(unsafe { *tcphdr }.source);
            destination_port = u16::from_be(unsafe { *tcphdr }.dest);

            fin_flag_count = (unsafe { *tcphdr }.fin() != 0) as u8;
            syn_flag_count = (unsafe { *tcphdr }.syn() != 0) as u8;
            rst_flag_count = (unsafe { *tcphdr }.rst() != 0) as u8;
            psh_flag_count = (unsafe { *tcphdr }.psh() != 0) as u8;
            ack_flag_count = (unsafe { *tcphdr }.ack() != 0) as u8;
            urg_flag_count = (unsafe { *tcphdr }.urg() != 0) as u8;
            cwe_flag_count = (unsafe { *tcphdr }.cwr() != 0) as u8;
            ece_flag_count = (unsafe { *tcphdr }.ece() != 0) as u8;

            protocol = IpProto::Tcp as u8;
            window_size = u16::from_be(unsafe { *tcphdr }.window);
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
            source_port = u16::from_be(unsafe { *udphdr }.source);
            destination_port = u16::from_be(unsafe { *udphdr }.dest);

            header_length = UdpHdr::LEN as u32;
            length = data_length as u32
                + header_length as u32
                + Ipv6Hdr::LEN as u32
                + EthHdr::LEN as u32;
            protocol = IpProto::Udp as u8;
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let flow = BasicFeaturesIpv6 {
        ipv6_destination: ipv6_destination,
        ipv6_source: ipv6_source,
        port_destination: destination_port,
        port_source: source_port,
        protocol: protocol,
        fin_flag: fin_flag_count,
        syn_flag: syn_flag_count,
        rst_flag: rst_flag_count,
        psh_flag: psh_flag_count,
        ack_flag: ack_flag_count,
        urg_flag: urg_flag_count,
        cwe_flag: cwe_flag_count,
        ece_flag: ece_flag_count,
        data_length: data_length as u32,
        header_length: header_length,
        length: length,
        window_size: window_size,
    };

    // the zero value is a flag
    EVENTS_IPV6.output(&ctx, &flow, 0);

    Ok(TC_ACT_PIPE)
}
