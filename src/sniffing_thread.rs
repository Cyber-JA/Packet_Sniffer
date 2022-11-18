#![allow(non_snake_case)]
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::thread;
use pcap::{Device};
use report_packet::ReportPacket;
use crate::report_packet::report_packet;
use crate::parsing::parse;

//function used by the thread that must sniff packet
pub fn sniff(net_adapter: usize, report_vector : Arc<Mutex<Vec<ReportPacket>>>, _filter: String, /*rx_sniffer: &Receiver<String>,*/ rev_tx_sniffer: Sender<String>) -> Sender<String> {

/****************** SNIFFING THREAD *******************/
    let (tx_sniffer, rx_sniffer) = channel::<String>();
    thread::Builder::new()
        .name("sniffer".into()).spawn(move || {
        let list = Device::list().unwrap();
        let mut cap = pcap::Capture::from_device(list[net_adapter - 1].clone()).unwrap()
            .promisc(true)
            .open()
            .unwrap();

        rev_tx_sniffer.send(String::from("sniffer ready!")).unwrap();
        while let Ok(packet) = cap.next_packet(){
            let handle = rx_sniffer.try_recv();
            //println!("reader: {:?}", handle);
            match handle {
                Ok(_) => { break; },
                Err(error) => { if error != TryRecvError::Empty && error != TryRecvError::Disconnected { println!("Unexpected error in sniffer thread...{}", error); } },
            };
            let report = parse(packet).clone();
            let report_vector_copy = report_vector.clone();
            thread::Builder::new()
                .name("reporter".into()).spawn(move || {
                insert_into_report(&report_vector_copy, report);
            }).unwrap();
        }
        rev_tx_sniffer.send(String::from("Stopping sniffer thread")).unwrap();
    }).unwrap();
    /******************************************************/
    tx_sniffer
}

pub fn insert_into_report(report_vector : &Arc<Mutex<Vec<ReportPacket>>>, packet : ReportPacket) -> () {
    let mut vec = report_vector.lock().unwrap();
    vec.push(packet);
}
