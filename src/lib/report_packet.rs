use std::fmt::{Debug, Formatter};
use pktparse::ethernet::{EtherType};
use pktparse::ip::IPProtocol;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::lib::report_packet::Address::{IPv4Addr, IPv6Addr, MacAddr};

//struct used to represent packet structure
#[derive(Debug, Clone)]
pub struct ReportPacket {
    pub l3_protocol: EtherType,
    pub source_ip: Address,
    pub dest_ip: Address,
    pub l4_protocol: IPProtocol,
    pub source_port: u16,
    pub dest_port: u16,
    pub bytes_exchanged : u32,
    pub timestamp : f64
    //time : pcap::timeval
}

#[derive(Debug, Clone)]
pub enum Address{
    IPv4Addr(Ipv4Addr),
    IPv6Addr(Ipv6Addr),
    MacAddr(MACAddress)
}

#[derive(Clone)]
pub struct MACAddress{
    first : u8,
    second : u8,
    third : u8,
    fourth : u8,
    fifth : u8,
    sixth : u8
}

pub struct Report {
    pub l3_protocol: EtherType,
    pub source_ip: Address,
    pub dest_ip: Address,
    pub l4_protocol: IPProtocol,
    pub source_port: u16,
    pub dest_port: u16,
    pub bytes_exchanged : u32,
    pub timestamp_first : f64,
    pub timestamp_last : f64
}

//implementation of methods
impl ReportPacket {
    pub fn new(
        l3_protocol: EtherType,
        source_ip: Address,
        dest_ip: Address,
        l4_protocol: IPProtocol,
        source_port: u16,
        dest_port: u16,
        bytes_exchanged: u32,
        timestamp: f64
    ) -> Self {
        ReportPacket {
            l3_protocol,
            source_ip,
            dest_ip,
            l4_protocol,
            source_port,
            dest_port,
            bytes_exchanged,
            timestamp
        }
    }
}
impl Report {
    pub fn new(
        l3_protocol: EtherType,
        source_ip: Address,
        dest_ip: Address,
        l4_protocol: IPProtocol,
        source_port: u16,
        dest_port: u16,
        bytes_exchanged: u32,
        timestamp_first: f64,
        timestamp_last: f64
    ) -> Self {
        Report {
            l3_protocol,
            source_ip,
            dest_ip,
            l4_protocol,
            source_port,
            dest_port,
            bytes_exchanged,
            timestamp_first,
            timestamp_last
        }
    }
}
impl PartialEq for Address{
    fn eq(&self, other: &Self) -> bool {
        match (self.clone(), other.clone()){
            (IPv4Addr(ref a), IPv4Addr(ref b)) => a == b,
            (IPv6Addr(ref a), IPv6Addr(ref b)) => a == b,
            (MacAddr(ref a), MacAddr(ref b)) => a == b,
            _ => false,
        }
    }
}

impl MACAddress{
    pub fn new (first : u8, second : u8, third : u8, fourth : u8, fifth : u8, sixth : u8) -> Self{
        MACAddress{first, second, third, fourth, fifth, sixth}
    }
}

impl PartialEq for MACAddress{
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first && self.second == other.second && self.third == other.third && self.fourth == other.fourth && self.fifth == other.fifth && self.sixth == other.sixth
    }
}

impl Debug for MACAddress{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", self.first, self.second, self.third, self.fourth, self.fifth, self.sixth)
    }
}
