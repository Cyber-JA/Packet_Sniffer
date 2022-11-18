use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use mpsc::Receiver;
use std::cell::Ref;
use std::error::Error;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{Sender, SyncSender, TryRecvError};
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
#[allow(non_snake_case)]
pub fn write_file(file_name: String, timeout: u16, report_vector : Arc<Mutex<Vec<ReportPacket>>>, rx_writer: Receiver<String>, rev_tx_writer: Sender<String>){
    /****************** WRITER THREAD *******************/
    thread::Builder::new()
        .name("writer".into()).spawn(move || {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(file_name).unwrap(); //file opened in append mode, read-write mode, if not exists, create it
        rev_tx_writer.send(String::from("writer ready!")).unwrap();
        loop {
            let handle = rx_writer.try_recv();
            println!("writer: {:?}", handle);
            match handle {
                Ok(_) => { break; },
                Err(error) => { if error != TryRecvError::Empty && error != TryRecvError::Disconnected { panic!("Unexpected error in writer thread! Panicking...{}", error) } },
            };
            write_report(&report_vector, timeout as u64, &mut file);
        };
        rev_tx_writer.send(String::from("Stopping writer thread")).unwrap();
    }).unwrap();
    /******************************************************/
}

pub fn write_report(report_vector : &Arc<Mutex<Vec<ReportPacket>>>, timeout : u64, file: &mut File) -> (){
    thread::sleep(Duration::from_millis(timeout));
    //println!("----------------------------------------------------------------------------------");
    let mut vec = report_vector.lock().unwrap();
    vec.iter().for_each(|&p| fmt_for_file(p, file));
    //println!("----------------------------------------------------------------------------------");
    vec.clear();
}

