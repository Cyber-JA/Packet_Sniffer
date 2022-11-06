/******PARSING MODULE******/

use std::net::{Ipv4Addr, Ipv6Addr};
use pcap::Packet;
use pktparse::arp;
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ethernet::EtherType::IPv4;
use pktparse::ip::IPProtocol;
use crate::report_packet::report_packet::{ReportPacket};
use pktparse::ip::IPProtocol::{ICMP, Other, TCP, UDP};
use pktparse::ipv4::IPv4Header;

//main general function used by the sniffing thread
pub fn parse(packet: Packet)->ReportPacket{
    let mut report = parse_ether(packet.data);
    report
}

/***********PARSING EACH PROTOCOL**********/
fn parse_ether(packet: &[u8]) -> ReportPacket {
    let mut report = ReportPacket::new(pktparse::ethernet::MacAddress { 0: [1, 1, 1, 1, 1, 1] }, MacAddress { 0: [1, 1, 1, 1, 1, 1] }, EtherType::ARP, Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),IPProtocol::Other(0), 0, 0);
    if let Ok((payload, frame)) = pktparse::ethernet::parse_ethernet_frame(packet)
    {
        report.source_mac = frame.source_mac;
        report.dest_mac = frame.dest_mac;
        report.l3_protocol = frame.ethertype;
        //parsing ether frame to get l3 protocol
        match frame.ethertype {
            EtherType::IPv4 => { report = parse_ipv4(payload, report) }
            EtherType::ARP =>  { report = parse_arp(payload, report) }
            EtherType::IPv6 => { report = parse_ipv6(payload, report) }
            _ => {report.l3_protocol = EtherType::Other(0);}
        }
    }
    report
}

//IPV4 PARSING
fn parse_ipv4(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let Ok((payload, datagram)) = pktparse::ipv4::parse_ipv4_header(payload)
    {
        report.l3_protocol = EtherType::IPv4;
        report.source_ip = datagram.source_addr;
        report.dest_ip = datagram.dest_addr;
        report.l4_protocol = datagram.protocol;
        match datagram.protocol {
            IPProtocol::TCP => {report = parse_tcp(payload, report);}
            IPProtocol::UDP => {report = parse_udp(payload, report); }
            IPProtocol::ICMP => {report = parse_icmp(payload, report); }
            _ => {report.l4_protocol = Other(0); }
        }
    }
    report
}

//IPV6 PARSING, TO COMPLETE
fn parse_ipv6(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let Ok((payload, datagram)) = pktparse::ipv6::parse_ipv6_header(payload)
    {
        report.l3_protocol = EtherType::IPv6;
        report.source_ipv6 = datagram.source_addr;
        report.dest_ipv6 = datagram.dest_addr;
        report.l4_protocol = datagram.next_header;
        match datagram.next_header {
            IPProtocol::TCP => {report = parse_tcp(payload, report);}
            IPProtocol::UDP => {report = parse_udp(payload, report); }
            IPProtocol::ICMP => {report = parse_icmp(payload, report); }
            _ => {report.l4_protocol = Other(0); }
        }
    }
    report
}

//ARP PARSING, TO COMPLETE
fn parse_arp(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let Ok((payload, header)) = pktparse::arp::parse_arp_pkt(payload)
    {
        report.l3_protocol = EtherType::ARP;
        report.source_mac = header.src_mac;
        report.dest_mac = header.dest_mac;
        report.source_ip = header.src_addr;
        report.dest_ip = header.dest_addr;
    }
    report
}

//TCP PARSING, TO COMPLETE
fn parse_tcp(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let (Ok((payload, header))) = pktparse::tcp::parse_tcp_header(payload)
    {
        report.source_port = header.source_port;
        report.dest_port = header.dest_port;
        report.l4_protocol = TCP;
    }
    report
}

//UDP PARSING, TO COMPLETE
fn parse_udp(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let (Ok((udp_datagram, header))) = pktparse::udp::parse_udp_header(payload)
    {
        report.source_port = header.source_port;
        report.dest_port = header.dest_port;
        report.l4_protocol = UDP;
    }
    report
}

//ICMP PARSING, TO COMPLETE
fn parse_icmp(payload: &[u8], mut report: ReportPacket) -> ReportPacket{
    if let (Ok((icmp_payload, header))) = pktparse::icmp::parse_icmp_header(payload)
    {   println!("{:?}", header);
        //report.source_port = header.source_port;
        //report.dest_port = header.dest_port;
        report.l3_protocol = IPv4;
        println!("{:?}", header)
    }
    report
}

/**************************************************/
