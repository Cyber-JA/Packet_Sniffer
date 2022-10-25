/******PARSING MODULE******/

use std::net::{Ipv4Addr, Ipv6Addr};
use pcap::Packet;
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;
use crate::report_packet::report_packet::{ReportPacket};
use hex;

pub fn parse(packet: Packet)->ReportPacket{
    let mut report = ReportPacket::new(pktparse::ethernet::MacAddress { 0: [1, 1, 1, 1, 1, 1] }, MacAddress { 0: [1, 1, 1, 1, 1, 1] }, EtherType::ARP, Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),IPProtocol::Other(0), packet.data[0] as u16, 0);
    if let Ok((payload, frame)) = pktparse::ethernet::parse_ethernet_frame(packet.data)
    {
        report.source_mac = frame.source_mac;
        report.dest_mac = frame.dest_mac;
        report.l3_protocol = frame.ethertype;
        match frame.ethertype {
            EtherType::IPv4 => { if let Ok((payload, datagram)) = pktparse::ipv4::parse_ipv4_header(payload){report.l3_protocol = EtherType::IPv4; report.source_ip = datagram.source_addr; report.dest_ip = datagram.dest_addr; report.l4_protocol = datagram.protocol;}}
            EtherType::ARP => { if let Ok((payload, header)) = pktparse::arp::parse_arp_pkt(payload){report.l3_protocol = EtherType::ARP;  report.source_mac = header.src_mac; report.dest_mac = header.dest_mac }}
            EtherType::IPv6 => { if let Ok((payload, datagram)) = pktparse::ipv6::parse_ipv6_header(payload){report.l3_protocol = EtherType::IPv6; report.source_ipv6 = datagram.source_addr; report.dest_ipv6 = datagram.dest_addr; report.l4_protocol = datagram.next_header;}}
            EtherType::Other(_) => {}
            _ => {}
        }
    }
    report
}

