use std::fs::File;
use std::io::{BufReader, BufWriter};
use mpsc::Receiver;
use std::sync::mpsc;
use std::sync::mpsc::SyncSender;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use pcap::{Device, Packet};
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;
use report_packet::ReportPacket;
use crate::parsing;
use crate::print_format::print;
use crate::report_packet::report_packet;

pub fn write_file(file_name: String, timeout: u16, rx: Receiver<ReportPacket>){
    /****************** READING THREAD *******************/
    thread::spawn(move || {
        loop {
            sleep(Duration::from_millis(timeout as u64));
            println!("filename: {:?}, timeout: {:?}", file_name, timeout);
            let packet = rx.recv().unwrap();
            print(packet);
        }
    });
    /******************************************************/
}