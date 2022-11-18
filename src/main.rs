extern crate core;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{channel, SyncSender};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use pcap::{Device, Error, Packet};
use pktparse::ethernet::{EtherType, MacAddress};
use pktparse::ip::IPProtocol;
use cli::cli::read_input_string;
use cli::cli::get_user_commands;
use print_format::print;
use report_packet::report_packet::ReportPacket;

//main di test
mod cli;
mod lib;
mod report_packet;
mod sniffing_thread;
mod parsing;
mod print_format;
mod writing_thread;
use crate::cli::cli::get_cli;
#[allow(non_snake_case)]
fn main() {

    /*******************READING FROM CLI******************/
    let mut args = get_cli();
    /********************************************************/
    /*  args's arguments:                                   */
    /*  net_adapter: index used in selecting Device::lookup */
    /*  output_file_name: self explained                    */
    /*  filter: string to filter packet sniffing            */
    /*  timeout: time after which a report must be produced */
    /*                                                      */
    /********************************************************/
    /*cloning parameters to pass to threads*/
    let net_adapter_cp = args.net_adapter.clone();
    let filter = args.filter.clone();
    let output_file_name = args.output_file_name.clone();
    let timeout = args.timeout.clone();
    let mut report_vector = Arc::new(Mutex::new(Vec::new()));
    /*flag used to check wheter the sniffing process is active or not*/
    let mut flag = false;
    /*creating channels to send commands to threads*/
    let (tx_writer, rx_writer) = channel::<String>();
    let (tx_sniffer, rx_sniffer) = channel::<String>();
    let (rev_tx_writer, rev_rx_writer) = channel::<String>();
    let (rev_tx_sniffer, rev_rx_sniffer) = channel::<String>();
    /*common strucutre to store sniffed packets to write them into a file*/
    let report_vector2 = report_vector.clone();
    let report_vector1 = report_vector.clone();
    /*starting sniffing*/
        let mut string = get_user_commands();
        match string.as_str(){
            "pause" => {
                if flag == false { println!("No active sniffing!");}
                else {
                    tx_writer.send(String::from("pause")).unwrap();
                    tx_sniffer.send(String::from("pause")).unwrap();
                    println!("Waiting for all the threads to stop...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    flag = false;
                }
            }
            "resume" => {
                if flag == true {println!("Sniffing yet!");}
                else {
                    /*starting sniffing and writing thread*/
                    sniffing_thread::sniff(net_adapter_cp, report_vector2, filter, rx_sniffer, rev_tx_sniffer);
                    writing_thread::write_file(output_file_name, timeout, report_vector1, rx_writer, rev_tx_writer);
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    flag = true;
                }
            }
            "stop" => {
                tx_sniffer.send(String::from("stop")).unwrap();
                tx_writer.send(String::from("stop")).unwrap();
                println!("Waiting for all the threads to stop...and terminating program");
                let mut notify = rev_rx_sniffer.recv().unwrap();
                println!("{}", notify);
                notify = rev_rx_writer.recv().unwrap();
                println!("{}", notify);
                println!("Done!");
                flag = false;
            }
            _ => {
                    //
            }

    }
    let var = get_user_commands();
    tx_sniffer.send(String::from("stop")).unwrap();
    tx_writer.send(String::from("stop")).unwrap();
    println!("Waiting for all the threads to stop...");
    let mut notify = rev_rx_sniffer.recv().unwrap();
    println!("{}", notify);
    notify = rev_rx_writer.recv().unwrap();
    println!("{}", notify);
    println!("Done!");
    /******************************************************/
}