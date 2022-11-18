use mpsc::Receiver;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{Sender, SyncSender, TryRecvError};
use std::thread;
use pcap::{Capture, Device, Error, Inactive, Packet};
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;
use report_packet::ReportPacket;
use crate::lib;
use crate::print_format::print;
use crate::report_packet::report_packet;
use crate::parsing::parse;
#[allow(non_snake_case)]
//function used by the thread that must sniff packet
pub fn sniff(net_adapter: usize, report_vector : Arc<Mutex<Vec<ReportPacket>>>, filter: String, rx_sniffer: Receiver<String>, rev_tx_sniffer: Sender<String>) {

    /****************** SNIFFING THREAD *******************/
    thread::Builder::new()
        .name("sniffer".into()).spawn(move || {
        let list = Device::list().unwrap();
        let mut cap = pcap::Capture::from_device(list[net_adapter-1].clone()).unwrap()
            .promisc(true)
            .open()
            .unwrap();

        rev_tx_sniffer.send(String::from("sniffer ready!")).unwrap();
        while let Ok(packet) = cap.next_packet() {
            let handle = rx_sniffer.try_recv();
            println!("reader: {:?}", handle);
            match handle {
                Ok(_) => { break; },
                Err(error) => {if error != TryRecvError::Empty && error != TryRecvError::Disconnected { println!("Unexpected error in sniffer thread...{}", error); }},
            };
            let report = parse(packet).clone();
            let mut report_vectory_copy = report_vector.clone();
            thread::Builder::new()
                .name("reporter".into()).spawn(move || {
                insert_into_report(&report_vectory_copy, report);
            });
        }
        rev_tx_sniffer.send(String::from("Stopping sniffer thread")).unwrap();
    }).unwrap();
    /******************************************************/
}

pub fn insert_into_report(report_vector : &Arc<Mutex<Vec<ReportPacket>>>, packet : ReportPacket) -> () {
    let mut vec = report_vector.lock().unwrap();
    vec.push(packet);
}
