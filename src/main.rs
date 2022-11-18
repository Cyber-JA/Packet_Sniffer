#![allow(non_snake_case)]
extern crate core;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel};
use cli::cli::get_user_commands;

//main di test
mod cli;
mod lib;
mod report_packet;
mod sniffing_thread;
mod parsing;
mod print_format;
mod writing_thread;
use crate::cli::cli::get_cli;

fn main() {

    /*******************READING FROM CLI******************/
    let args = get_cli();
    /********************************************************/
    /*  args's struct arguments:                                   */
    /*  net_adapter: index used in selecting Device::lookup */
    /*  output_file_name: self explained                    */
    /*  filter: string to filter packet sniffing            */
    /*  timeout: time after which a report must be produced */
    /*                                                      */
    /********************************************************/

    /************ PARAMETERS TO PASS TO THREADS *************/
    let net_adapter_cp = args.net_adapter.clone();
    let filter = args.filter.clone();
    let output_file_name = args.output_file_name.clone();
    let timeout = args.timeout.clone();
    /********************************************************/

    /*** MUTEX WHERE PACKETS ARE PUSHED WHEN SNIFFED AND POPPED WHEN WROTE ON FILE ***/
    let report_vector = Arc::new(Mutex::new(Vec::new()));
    /*********************************************************************************/

    /**** FLAG USED TO CHECK WHETER THE SNIFFING PROCESS IS ACTIVE OR NOT ****/
    let mut flag = false;
    let mut paused = false;
    /*************************************************************************/

    /************* CREATING CHANNELS TO COMMUNICATE WITH THREADS *************/
    let  (mut tx_writer, _rx_writer) = channel::<String>();
    let  (mut tx_sniffer, _rx_sniffer) = channel::<String>();
    let (rev_tx_writer, rev_rx_writer) = channel::<String>();
    let (rev_tx_sniffer, rev_rx_sniffer) = channel::<String>();
    /*************************************************************************/

    /******************************** START SNIFFING ********************************/
    loop {
        //Acquire command from the user
        let string = get_user_commands();
        match string.as_str() {
            //start case
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
            //stop case
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
            //resume case
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
            //stop case
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
                //flag = false;
                break;
            }
            _ => {
                //
            }
        }
    }
    /********************************************************************************/
}