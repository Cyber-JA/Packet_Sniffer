use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;

pub struct ReportPacket{
    source_mac : MacAddress,
    dest_mac : MacAddress,
    l3_protocol : EtherType,
    source_ip : IPAddr,
    dest_ip : IPAddr,
    l4_protocol : IPProtocol,
    source_port : u16,
    dest_port : u16,
    time : pcap::timeval
}

impl ReportPacket{
    pub fn new() -> ReportPacket{
        ReportPacket
    }
}

pub enum IPAddr{
    Ipv4Addr,
    Ipv6Addr
}


pub fn packet_parser() -> () {
    let mut cap2 = pcap::Capture::from_device(list[2].clone()).unwrap()
        .promisc(true)
        .open()
        .unwrap();

    while let Ok(packet) = cap2.next_packet() {
        let p = ReportPacket::new();
        if let Ok((payload, frame)) = pktparse::ethernet::parse_ethernet_frame(packet.data) {
            println!("{:?}", frame.ethertype);
            match frame.ethertype {
                IPv4 => if let Ok((payload, datagram)) = pktparse::ipv4::parse_ipv4_header(payload) {
                    println!("{:?}", datagram.protocol);
                    match datagram.protocol {
                        TCP => {
                            if let Ok((payload, segment)) = pktparse::tcp::parse_tcp_header(payload) {
                                println!("source port : {}, dest port : {}", segment.source_port, segment.dest_port);
                            }
                        }
                    }
                }
                IPv6 => if let Ok((payload, datagram)) = pktparse::ipv6::parse_ipv6_header(payload) {
                    println!("{:?}", datagram.next_header);
                }
                _ => println!("Unknown protocol")
            }
        }
    }
}
