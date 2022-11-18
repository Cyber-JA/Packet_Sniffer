use crate::lib::report_packet::ReportPacket;
use std::fs::File;
use std::io::Write;
#[warn(dead_code)]
pub fn print(packet: ReportPacket) {
    println!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\
                -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} \
                | {:?}:{:?} -> {:?}:{:?} | l3 protocol: {:?} | l4 protocol: {:?}",
        packet.source_mac.0[0],
        packet.source_mac.0[1],
        packet.source_mac.0[2],
        packet.source_mac.0[3],
        packet.source_mac.0[4],
        packet.source_mac.0[5],
        packet.dest_mac.0[0],
        packet.dest_mac.0[1],
        packet.dest_mac.0[2],
        packet.dest_mac.0[3],
        packet.dest_mac.0[4],
        packet.dest_mac.0[5],
        packet.source_ip,
        packet.source_port,
        packet.dest_ip,
        packet.dest_port,
        packet.l3_protocol,
        packet.l4_protocol
    );
}

pub fn fmt_for_file(packet: ReportPacket, file: &mut File) {
    let string = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\
            -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} \
            | {:?}:{:?} -> {:?}:{:?} | l3 protocol: {:?} | l4 protocol: {:?}\n",
        packet.source_mac.0[0],
        packet.source_mac.0[1],
        packet.source_mac.0[2],
        packet.source_mac.0[3],
        packet.source_mac.0[4],
        packet.source_mac.0[5],
        packet.dest_mac.0[0],
        packet.dest_mac.0[1],
        packet.dest_mac.0[2],
        packet.dest_mac.0[3],
        packet.dest_mac.0[4],
        packet.dest_mac.0[5],
        packet.source_ip,
        packet.source_port,
        packet.dest_ip,
        packet.dest_port,
        packet.l3_protocol,
        packet.l4_protocol
    );
    file.write_all(string.as_bytes()).unwrap();
}
