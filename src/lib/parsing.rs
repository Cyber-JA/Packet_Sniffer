use crate::lib::report_packet::{Address, MACAddress, ReportPacket};
use pcap::Packet;
use pktparse::ethernet::EtherType;
use pktparse::ethernet::EtherType::IPv4;
use pktparse::ip::IPProtocol;
use pktparse::ip::IPProtocol::{Other, TCP, UDP};
use std::net::Ipv4Addr;
use std::time::Instant;

//main general function used by the sniffing thread
pub fn parse(packet: Packet, time: Instant, start_time: u128) -> ReportPacket {
    let report = parse_ether(packet, time, start_time);
    report
}

/***********PARSING EACH PROTOCOL**********/
fn parse_ether(packet: Packet, time: Instant, start_time: u128) -> ReportPacket {
    let mut report = ReportPacket::new(
        EtherType::ARP,
        Address::IPv4Addr(Ipv4Addr::new(0, 0, 0, 0)),
        Address::IPv4Addr(Ipv4Addr::new(0, 0, 0, 0)),
        IPProtocol::Other(0),
        "".to_string(),
        0,
        0,
        0,
        0.0,
    );
    report.bytes_exchanged = packet.header.len;
    report.timestamp = (time.elapsed().as_millis() + start_time) as f64 / 1000.0;
    if let Ok((payload, frame)) = pktparse::ethernet::parse_ethernet_frame(packet.data) {
        report.l3_protocol = frame.ethertype;
        //parsing ether frame to get l3 protocol
        match frame.ethertype {
            EtherType::IPv4 => report = parse_ipv4(payload, report),
            EtherType::ARP => report = parse_arp(payload, report),
            EtherType::IPv6 => report = parse_ipv6(payload, report),
            _ => {
                report.l3_protocol = EtherType::Other(0);
            }
        }
    }
    report
}

//IPV4 PARSING
fn parse_ipv4(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((payload, datagram)) = pktparse::ipv4::parse_ipv4_header(payload) {
        report.l3_protocol = EtherType::IPv4;
        report.source_ip = Address::IPv4Addr(datagram.source_addr);
        report.dest_ip = Address::IPv4Addr(datagram.dest_addr);
        report.l4_protocol = datagram.protocol;
        match datagram.protocol {
            IPProtocol::TCP => {
                report = parse_tcp(payload, report);
            }
            IPProtocol::UDP => {
                report = parse_udp(payload, report);
            }
            IPProtocol::ICMP => {
                report = parse_icmp(payload, report);
            }
            _ => {
                report.l4_protocol = Other(0);
            }
        }
    }
    report
}

//IPV6 PARSING, TO COMPLETE
fn parse_ipv6(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((payload, datagram)) = pktparse::ipv6::parse_ipv6_header(payload) {
        report.l3_protocol = EtherType::IPv6;
        report.source_ip = Address::IPv6Addr(datagram.source_addr);
        report.dest_ip = Address::IPv6Addr(datagram.dest_addr);
        report.l4_protocol = datagram.next_header;
        match datagram.next_header {
            IPProtocol::TCP => {
                report = parse_tcp(payload, report);
            }
            IPProtocol::UDP => {
                report = parse_udp(payload, report);
            }
            IPProtocol::ICMP => {
                report = parse_icmp(payload, report);
            }
            _ => {
                report.l4_protocol = Other(0);
            }
        }
    }
    report
}

//ARP PARSING, TO COMPLETE
fn parse_arp(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((_payload, header)) = pktparse::arp::parse_arp_pkt(payload) {
        report.l3_protocol = EtherType::ARP;
        report.source_ip = Address::MacAddr(MACAddress::new(
            header.src_mac.0[0],
            header.src_mac.0[1],
            header.src_mac.0[2],
            header.src_mac.0[3],
            header.src_mac.0[4],
            header.src_mac.0[5],
        ));
        report.dest_ip = Address::MacAddr(MACAddress::new(
            header.dest_mac.0[0],
            header.dest_mac.0[1],
            header.dest_mac.0[2],
            header.dest_mac.0[3],
            header.dest_mac.0[4],
            header.dest_mac.0[5],
        ));
    }
    report
}

//TCP PARSING, TO COMPLETE
fn parse_tcp(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((p, header)) = pktparse::tcp::parse_tcp_header(payload) {
        report.source_port = header.source_port;
        report.dest_port = header.dest_port;
        report.l4_protocol = TCP;
        if let Ok(_dns) = dns_parser::Packet::parse(p) {
            report.l7_protocol = "DNS".to_string();
        } else if let Ok(_tls) = tls_parser::parse_tls_encrypted(p) {
            report.l7_protocol = "TLS".to_string();
        } else if let Ok(_dhcp4) = dhcp4r::packet::Packet::from(p) {
            report.l7_protocol = "DHCP".to_string();
        }
    }
    report
}

//UDP PARSING, TO COMPLETE
fn parse_udp(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((udp_datagram, header)) = pktparse::udp::parse_udp_header(payload) {
        report.source_port = header.source_port;
        report.dest_port = header.dest_port;
        report.l4_protocol = UDP;
        if let Ok(_dns) = dns_parser::Packet::parse(udp_datagram) {
            report.l7_protocol = "DNS".to_string();
        } else if let Ok(_dhcp4) = dhcp4r::packet::Packet::from(udp_datagram) {
            report.l7_protocol = "DHCP".to_string();
        }
    }
    report
}

//ICMP PARSING, TO COMPLETE
fn parse_icmp(payload: &[u8], mut report: ReportPacket) -> ReportPacket {
    if let Ok((_icmp_payload, _header)) = pktparse::icmp::parse_icmp_header(payload) {
        //report.source_port = header.source_port;
        //report.dest_port = header.dest_port;
        report.l3_protocol = IPv4;
    }
    report
}

/**************************************************/
