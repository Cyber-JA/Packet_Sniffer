use std::fs::{File, OpenOptions};
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
use crate::print_format::{print, fmt_for_file};
use crate::report_packet::report_packet;
use std::io::prelude::*;
use std::path::PathBuf;

pub fn write_file(file_name: String, timeout: u16, rx: Receiver<ReportPacket>){
    /****************** READING THREAD *******************/
    thread::spawn(move || {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(file_name).unwrap(); //file opened in append mode, read-write mode, if not exists, create it
        loop {
            sleep(Duration::from_millis(timeout as u64));
            let packet = rx.recv().unwrap();
            fmt_for_file(packet, &mut file);
            print(packet);
        }
    });
    /******************************************************/
}