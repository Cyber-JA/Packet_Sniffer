/***************PARSING MODULE***************/
//TODO write format to print packet's information

use std::fmt::{Display, Formatter};
use pktparse::ethernet::MacAddress;
use crate::report_packet::report_packet::ReportPacket;

pub fn print(packet: ReportPacket){
    println!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\
                -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} \
                | {:?} -> {:?} | l3 protocol: {:?} | l4 protocol: {:?}", packet.source_mac.0[0], packet.source_mac.0[1], packet.source_mac.0[2], packet.source_mac.0[3], packet.source_mac.0[4], packet.source_mac.0[5],
             packet.dest_mac.0[0], packet.dest_mac.0[1], packet.dest_mac.0[2], packet.dest_mac.0[3], packet.dest_mac.0[4], packet.dest_mac.0[5]
             , packet.source_ip, packet.dest_ip, packet.l3_protocol, packet.l4_protocol);
}

fn print_mac(adr: MacAddress){
    println!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", adr.0[0], adr.0[1], adr.0[2], adr.0[3], adr.0[4], adr.0[5]);
}