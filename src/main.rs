extern crate core;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{channel, sync_channel, SyncSender};
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
    /*mutex used between writer and sniffer threads to push and pop packets*/
    let mut report_vector = Arc::new(Mutex::new(Vec::new()));
    /*flag used to check wheter the sniffing process is active or not*/
    let mut flag = false;
    let mut paused = false;
    /*creating channels to send commands to threads*/
    let  (mut tx_writer, rx_writer) = channel::<String>();
    let  (mut tx_sniffer, rx_sniffer) = channel::<String>();
    let (rev_tx_writer, rev_rx_writer) = channel::<String>();
    let (rev_tx_sniffer, rev_rx_sniffer) = channel::<String>();
    /*starting sniffing*/
    loop {
        let mut string = get_user_commands();
        match string.as_str() {
            "start" => {
                if flag == true && paused == false { println!("Sniffing yet!"); } else {
                    /*starting sniffing and writing thread*/
                    tx_sniffer = sniffing_thread::sniff(net_adapter_cp, report_vector.clone(), filter.clone(),
                                                        /*&rx_sniffer,*/ rev_tx_sniffer.clone());
                    tx_writer =writing_thread::write_file(output_file_name.clone(), timeout,
                                                          report_vector.clone(), /*&rx_writer,*/ rev_tx_writer.clone());
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    flag = true;
                }
            }
            "pause" => {
                if flag == false && paused == false { println!("No active sniffing!"); } else {
                    tx_writer.send(String::from("pause")).unwrap();
                    tx_sniffer.send(String::from("pause")).unwrap();
                    println!("Waiting for all the threads to stop...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    flag = false;
                    paused = true;
                }
            }
            "resume" => {
                if flag == true && paused == false { println!("Sniffing yet!"); } else {
                    /*starting sniffing and writing thread*/
                    tx_sniffer = sniffing_thread::sniff(net_adapter_cp, report_vector.clone(), filter.clone(),
                                           /*&rx_sniffer,*/ rev_tx_sniffer.clone());
                    tx_writer =writing_thread::write_file(output_file_name.clone(), timeout,
                                               report_vector.clone(), /*&rx_writer,*/ rev_tx_writer.clone());
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    flag = true;
                    paused = false;
                }
            }
            "stop" => {
                println!("Terminating program");
                if flag == true {
                    tx_sniffer.send(String::from("stop")).unwrap();
                    tx_writer.send(String::from("stop")).unwrap();
                    println!("Waiting for all the threads to stop...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                }
                println!("Done!");
                flag = false;
                break;
            }
            _ => {
                //
            }
        }
    }
    /******************************************************/
}