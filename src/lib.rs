/*mod report_packet;
mod cli;
mod sniffing_thread;
mod print_format;
mod writing_thread;
mod parsing;

pub mod lib {
    use std::sync::{Arc, Mutex};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use crate::{cli, sniffing_thread};
    use crate::writing_thread;
    use crate::lib::cli::cli::get_user_commands;
    use crate::report_packet::report_packet::ReportPacket;

    fn configure_and_run() {
        /*******************READING FROM CLI******************/
        let mut args = cli::cli::get_cli();
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
        let mut report_vector = Arc::new(Mutex::new(Vec::<ReportPacket>::new()));

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

        /*user choose whether to start/stop/resume/pause the sniffing*/
        loop{
            let mut string = get_user_commands();
            match string.as_str() {
                "pause" => { pause_sniffing(string, *flag, &tx_writer, tx_sniffer.clone(), rev_rx_sniffer.clone(), rev_rx_writer.clone()); }
                "start" => { start_sniffing(string, *flag, tx_writer.clone(), tx_sniffer.clone(), &rev_rx_sniffer, rev_rx_writer.clone()); }
                "stop" => { stop_sniffing(string, *flag, tx_writer, tx_sniffer, rev_rx_sniffer, rev_rx_writer.clone()); }
                "resume" => { resume_sniffing(string, *flag, tx_writer, tx_sniffer, rev_rx_sniffer.clone(), rev_rx_writer.clone()); }
                _ => {}
            }
        }
    }

    /*PAUSE_SNIFFING FUNCTION*/
    fn pause_sniffing(string: String, flag: &mut bool, tx_writer: Sender<String>,
                      tx_sniffer: Sender<String>, rev_rx_sniffer: &Receiver<String>, rev_rx_writer: &Receiver<String>) {
        match string.as_str() {
            "pause" => {
                if *flag == false { println!("No active sniffing!"); } else {
                    tx_writer.send(String::from("pause")).unwrap();
                    tx_sniffer.send(String::from("pause")).unwrap();
                    println!("Waiting for all the threads to stop...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    *flag = false;
                }
            }
            _ => {}
        }
    }
    /********************/

    /*START_SNIFFING FUNCTION*/
    fn start_sniffing(string: String, flag: &mut bool, tx_writer: Sender<String>, tx_sniffer: Sender<String>,
                      rev_rx_sniffer: &Receiver<String>, rev_rx_writer: &Receiver<String>) {
        //same code as the resume case
        match string.as_str(){
            "start" => {
                if *flag == true { println!("Sniffing yet!"); } else {
                    /*starting sniffing and writing thread*/
                    sniffing_thread::ssniff(net_adapter_cp, report_vector2, filter, rx_sniffer, rev_tx_sniffer);
                    crate::writing_thread::write_file(output_file_name, timeout, report_vector1, rx_writer, rev_tx_writer);
                    println!("Waiting for all the threads to start...");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    *flag = true;
                }
            }
            _ => {}
        }
    }
    /********************/

    /*STOP_SNIFFING FUNCTION*/
    fn stop_sniffing(string: String, flag: &mut bool, tx_writer: Sender<String>, tx_sniffer: Sender<String>,
                     rev_rx_sniffer: Receiver<String>, rev_rx_writer: Receiver<String>) {
        match string.as_str(){
            "stop" => {
                if *flag == false { println!("No active sniffing!"); } else {
                    tx_sniffer.send(String::from("stop")).unwrap();
                    tx_writer.send(String::from("stop")).unwrap();
                    println!("Waiting for all the threads to stop...and terminating program");
                    let mut notify = rev_rx_sniffer.recv().unwrap();
                    println!("{}", notify);
                    notify = rev_rx_writer.recv().unwrap();
                    println!("{}", notify);
                    println!("Done!");
                    *flag = false;
                }
            }
            _ => {}
        }

    }
    /********************/

    /*RESUME_SNIFFING FUNCTION*/
    fn resume_sniffing(string: String, flag: &mut bool, tx_writer: Sender<String>, tx_sniffer: Sender<String>,
                       rev_rx_sniffer: Receiver<String>, rev_rx_writer: Receiver<String>) {
        match string.as_str(){
            "resume" => {
            if *flag == true { println!("Sniffing yet!"); } else {
                /*starting sniffing and writing thread*/
                sniffing_thread::sniff(net_adapter_cp, report_vector2, filter, rx_sniffer, rev_tx_sniffer);
                writing_thread::write_file(output_file_name, timeout, report_vector1, rx_writer, rev_tx_writer);
                println!("Waiting for all the threads to start...");
                let mut notify = rev_rx_sniffer.recv().unwrap();
                println!("{}", notify);
                notify = rev_rx_writer.recv().unwrap();
                println!("{}", notify);
                println!("Done!");
                *flag = true;
            }
        }
            _ => {}
        }
    }
    /********************/
}*/