pub mod cli;
pub mod parsing;
pub mod print_format;
pub mod report_packet;
pub mod sniffing_thread;
pub mod writing_thread;

use std::io::{stdout, Write};
use crate::lib::cli::{get_cli, get_user_commands};
use pktparse::ethernet::EtherType;
use pktparse::ethernet::EtherType::ARP;
use pktparse::ip::IPProtocol;
use pktparse::ip::IPProtocol::{ICMP, TCP, UDP};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct SniffingManager {
    is_sniffing_active: bool,
    is_sniffing_paused: bool,
}

impl SniffingManager {
    pub fn new() -> Self {
        SniffingManager {
            is_sniffing_paused: false,
            is_sniffing_active: false,
        }
    }

    pub fn start(&mut self) {
        self.is_sniffing_active = true;
        self.is_sniffing_paused = false;
    }
    pub fn pause(&mut self) {
        self.is_sniffing_paused = true;
    }
    pub fn stop(&mut self) {
        self.is_sniffing_paused = false;
        self.is_sniffing_active = false;
    }

    pub fn resume(&mut self) {
        self.is_sniffing_paused = false;
    }

    pub fn is_active(&self) -> bool {
        return self.is_sniffing_active;
    }

    pub fn is_paused(&self) -> bool {
        return self.is_sniffing_paused && self.is_sniffing_active;
    }

    pub fn can_start(&self) -> bool {
        if self.is_active() == false && self.is_paused() == false {
            return true;
        } else {
            return false;
        }
    }

    pub fn can_resume(&self) -> bool {
        self.is_paused()
    }

    pub fn can_pause(&self) -> bool {
        if self.is_active() {
            if self.is_sniffing_paused == false {
                return true;
            }
        }
        return false;
    }
}

pub fn configure_and_run() -> () {
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
    let output_file_name = args.output_file_name.clone();
    let timeout = args.timeout.clone();
    let filters_vec = args.filters_list.clone();
    let filters_struct = fill_filters_vec(filters_vec.clone());
    println!("{:?}", filters_struct.l4_vector);
    println!("{:?}", filters_struct.l3_vector);
    println!("{:?}", filters_struct.l7_vector);
    let mut err;
    /********************************************************/
    /*** MUTEX WHERE PACKETS ARE PUSHED WHEN SNIFFED AND POPPED WHEN WROTE ON FILE ***/
    let report_vector = Arc::new(Mutex::new(Vec::new()));
    /*********************************************************************************/

    /**** FLAG USED TO CHECK WHETER THE SNIFFING PROCESS IS ACTIVE OR NOT ****/
    let mut manager = SniffingManager::new();
    /*************************************************************************/

    /************* CREATING CHANNELS TO COMMUNICATE WITH THREADS *************/
    let (mut tx_writer, _rx_writer) = channel::<String>();
    let (mut tx_sniffer, _rx_sniffer) = channel::<String>();
    let (rev_tx_writer, rev_rx_writer) = channel::<String>();
    let (rev_tx_sniffer, rev_rx_sniffer) = channel::<String>();
    /*************************************************************************/

    /******************************** START SNIFFING ********************************/
    let mut time = Instant::now();
    let mut pause_time = Instant::now();
    loop {
        //Acquire command from the user
        if manager.is_sniffing_active == true { println!("The sniffing session is in progress..."); stdout().flush().unwrap();}
        if manager.is_sniffing_paused == true { println!("The sniffing session is paused..."); stdout().flush().unwrap();}
        let string = get_user_commands();
        match string.as_str() {
            //start case
            "start" => {
                if manager.can_start() == false {
                    println!("Error: A sniffing session is still in progress!");
                } else {
                    time = Instant::now();
                    /*starting sniffing and writing thread*/
                    tx_sniffer = sniffing_thread::sniff(
                        net_adapter_cp,
                        report_vector.clone(),
                        filters_struct.clone(),
                        /*&rx_sniffer,*/ rev_tx_sniffer.clone(),
                        time,
                        0,
                    );
                    tx_writer = writing_thread::write_file(
                        output_file_name.clone(),
                        timeout,
                        report_vector.clone(),
                        /*&rx_writer,*/ rev_tx_writer.clone(),
                    );
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    manager.start();
                }
            }
            //pause case
            "pause" => {
                if manager.can_pause() == false {
                    println!("Error: Can't pause, no sniffing session in progress!");
                } else {
                    err = tx_sniffer.send(String::from("pause"));
                    match err {
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                    err = tx_writer.send(String::from("pause"));
                    match err {
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                    println!("Waiting for all the threads to pause...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    manager.pause();
                }
                pause_time = Instant::now();
            }
            //resume case
            "resume" => {
                if manager.can_resume() == false {
                    println!("Error: Can't resume, no sniffing session to resume!");
                } else {
                    println!(
                        "ELAPSED: {}, PAUSED: {}",
                        time.elapsed().as_millis(),
                        pause_time.elapsed().as_millis()
                    );
                    let resume_time = time.elapsed().as_millis() - pause_time.elapsed().as_millis();
                    time = Instant::now();
                    /*starting sniffing and writing thread*/
                    tx_sniffer = sniffing_thread::sniff(
                        net_adapter_cp,
                        report_vector.clone(),
                        filters_struct.clone(),
                        /*&rx_sniffer,*/ rev_tx_sniffer.clone(),
                        time,
                        resume_time,
                    );
                    tx_writer = writing_thread::write_file(
                        output_file_name.clone(),
                        timeout,
                        report_vector.clone(),
                        /*&rx_writer,*/ rev_tx_writer.clone(),
                    );
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    manager.resume();
                }
            }
            //stop case
            "stop" => {
                println!("Terminating program");
                if manager.is_active() == true && manager.is_paused() == false {
                    err = tx_sniffer.send(String::from("stop"));
                    match err {
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                    err = tx_writer.send(String::from("stop"));
                    match err {
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                    println!("Waiting for all the threads to stop...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                }
                println!("Done!");
                manager.stop();
                break;
            }
            _ => {
                //
            }
        }
    }
}

#[derive(Clone)]
pub struct LayersVectors {
    l3_vector: Vec<EtherType>,
    l4_vector: Vec<IPProtocol>,
    l7_vector: Vec<String>,
}

impl LayersVectors {
    pub fn new() -> Self {
        LayersVectors {
            l3_vector: Vec::new(),
            l4_vector: Vec::new(),
            l7_vector: Vec::new(),
        }
    }
}

pub fn fill_filters_vec(list: Vec<String>) -> LayersVectors {
    let mut vex_to_ret = LayersVectors::new();
    for val in list.iter() {
        match val.as_str() {
            "tcp" => {
                vex_to_ret.l4_vector.push(TCP);
            }
            "udp" => {
                vex_to_ret.l4_vector.push(UDP);
            }
            "arp" => {
                vex_to_ret.l3_vector.push(ARP);
            }
            "icmp" => {
                vex_to_ret.l4_vector.push(ICMP);
            }
            "dns" => {
                vex_to_ret.l7_vector.push("DNS".to_string());
            }
            "tls" => {
                vex_to_ret.l7_vector.push("TLS".to_string());
            }
            "dhcp" => {
                vex_to_ret.l7_vector.push("DHCP".to_string());
            }
            &_ => {}
        }
    }
    vex_to_ret
}
