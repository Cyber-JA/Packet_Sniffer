use crate::lib::report_packet::Report;
use pktparse::ethernet::EtherType;
use pktparse::ip::IPProtocol;
use std::fs::File;
use std::io::Write;

pub fn fmt_for_file(packet: &Report, file: &mut File) {
    let string;
    if packet.l3_protocol == EtherType::Other(0) {
        return;
    }
    if packet.l4_protocol == IPProtocol::Other(0) {
        string = format!(
            "{:?} -> {:?} | {:?} | bytes : {} | first_exchange : {:.3} | last_exchange : {:.3}\n\n",
            packet.source_ip,
            packet.dest_ip,
            packet.l3_protocol,
            packet.bytes_exchanged,
            packet.timestamp_first,
            packet.timestamp_last
        );
    }else if packet.l4_protocol == IPProtocol::IGMP || packet.l4_protocol == IPProtocol::ICMP {
        string = format!(
            "{:?} -> {:?} | {:?} | bytes : {} | first_exchange : {:.3} | last_exchange : {:.3}\n\n",
            packet.source_ip,
            packet.dest_ip,
            packet.l4_protocol,
            packet.bytes_exchanged,
            packet.timestamp_first,
            packet.timestamp_last
        );
    }
        else if packet.l7_protocol != "".to_string() {
        string = format!(
            "{:?} -> {:?} | {:?} ({:?} -> {:?}) | {} | bytes : {} | first_exchange : {:.3} | last_exchange : {:.3}\n\n",
            packet.source_ip, packet.dest_ip, packet.l4_protocol, packet.source_port, packet.dest_port, packet.l7_protocol, packet.bytes_exchanged, packet.timestamp_first, packet.timestamp_last
        )
    } else {
        string = format!(
            "{:?} -> {:?} | {:?} ({:?} -> {:?}) | bytes : {} | first_exchange : {:.3} | last_exchange : {:.3}\n\n",
            packet.source_ip, packet.dest_ip, packet.l4_protocol, packet.source_port, packet.dest_port, packet.bytes_exchanged, packet.timestamp_first, packet.timestamp_last
        )
    }

    let res = file.write_all(string.as_bytes());
    match res {
        Ok(_) => {}
        Err(_) => {
            println!("Error! Not possible to write on file...");
        }
    }
}
