use mpsc::Receiver;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::SyncSender;
use std::thread;
use pcap::{Device, Packet};
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;
use report_packet::ReportPacket;
use crate::parsing;
use crate::print_format::print;
use crate::report_packet::report_packet;

//function used by the thread that must sniff packet
pub fn sniff(net_adapter: usize, report_vector : Arc<Mutex<Vec<ReportPacket>>>, filter: String) -> () {

    /****************** SNIFFING THREAD *******************/
    thread::spawn(move || {
        let list = Device::list().unwrap();
        let mut cap = pcap::Capture::from_device(list[net_adapter-1].clone()).unwrap()
            .promisc(true)
            .open()
            .unwrap();
        while let Ok(packet) = cap.next_packet() {
            let report = parsing::parse(packet);
            insert_into_report(&report_vector, report);
        }

    });
    /******************************************************/
}

pub fn insert_into_report(report_vector : &Arc<Mutex<Vec<ReportPacket>>>, packet : ReportPacket) -> () {
    let mut vec = report_vector.lock().unwrap();
    vec.push(packet);
}