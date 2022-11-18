#![allow(non_snake_case)]
pub mod report_packet {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use pktparse::ethernet::{EtherType, MacAddress};
    use pktparse::ip::IPProtocol;

    //struct used to represent packet structure
    #[derive(Debug, Clone, Copy)]
    pub struct ReportPacket {
        pub source_mac: MacAddress,
        pub dest_mac: MacAddress,
        pub l3_protocol: EtherType,
        pub source_ip: Ipv4Addr,
        pub dest_ip: Ipv4Addr,
        pub source_ipv6: Ipv6Addr,
        pub dest_ipv6: Ipv6Addr,
        pub l4_protocol: IPProtocol,
        pub source_port: u16,
        pub dest_port: u16,
        //time : pcap::timeval
    }

    //implementation of methods
    impl ReportPacket {
        pub fn new(source_mac: MacAddress,
                   dest_mac: MacAddress,
                   l3_protocol: EtherType,
                   source_ip: Ipv4Addr,
                   dest_ip: Ipv4Addr,
                   source_ipv6: Ipv6Addr,
                   dest_ipv6: Ipv6Addr,
                   l4_protocol: IPProtocol,
                   source_port: u16,
                   dest_port: u16) -> Self {
            ReportPacket { source_mac,
                            dest_mac,
                            l3_protocol,
                            source_ip,
                            dest_ip,
                            source_ipv6,
                            dest_ipv6,
                            l4_protocol,
                            source_port,
                            dest_port }
        }
    }
}