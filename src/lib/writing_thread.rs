use crate::lib::print_format::fmt_for_file;
use crate::lib::report_packet::Report;
use std::fs::{File, OpenOptions};
use std::io::Seek;
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn write_file(
    mut file_name: String,
    timeout: u16,
    report_vector: Arc<Mutex<Vec<Report>>>,
    /*rx_writer: &Receiver<String>,*/ rev_tx_writer: Sender<String>,
) -> Sender<String> {
    /****************** WRITER THREAD *******************/
    let (tx_writer, rx_writer) = channel::<String>();
    file_name.push_str(".txt");
    thread::Builder::new()
        .name("writer".into())
        .spawn(move || {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(true)
                .create(true)
                .open(file_name)
                .unwrap(); //file opened in append mode, read-write mode, if not exists, create it
            rev_tx_writer.send(String::from("writer ready!")).unwrap();
            loop {
                let handle = rx_writer.try_recv();
                //println!("writer: {:?}", handle);
                match handle {
                    Ok(_) => {
                        println!("writer {:?}", handle);
                        break;
                    }
                    Err(error) => {
                        if error != TryRecvError::Empty && error != TryRecvError::Disconnected {
                            panic!("Unexpected error in writer thread! Panicking...{}", error)
                        }
                    }
                };
                write_report(&report_vector, timeout as u64, &mut file);
            }
            rev_tx_writer
                .send(String::from("Stopping writer thread"))
                .unwrap();
        })
        .unwrap();
    /******************************************************/
    tx_writer
}

pub fn write_report(report_vector: &Arc<Mutex<Vec<Report>>>, timeout: u64, file: &mut File) -> () {
    file.rewind().unwrap();
    thread::sleep(Duration::from_millis(timeout));
    //println!("----------------------------------------------------------------------------------");
    let vec = report_vector.lock().unwrap();
    vec.iter().for_each(|p| fmt_for_file(p, file));
    //println!("wrote file");
}
