#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
