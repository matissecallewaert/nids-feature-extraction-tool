#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
    pub header_length: u32,
    pub data_length: u32,
    //pub length: u32,
    pub fin_flag: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
