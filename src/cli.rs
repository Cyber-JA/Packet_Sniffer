//CLI developed using clap
use clap::Parser;
use pcap::Device;
use std::io;

/// time to sniff
#[derive(Parser, Debug)]
#[command(author="Caruso, Andorno, Fois", version, about = "A simple packet_sniffer", long_about = "A simple packet_sniffer in Rust language. All right reserved")]
pub struct Args {
    /// specify net_adapter, do not use this option to see a list of available devices and select among them
    #[arg(short, long, default_value_t = -1)]
    pub(crate) net_adapter: i8, //used as index, given a list of device, to get the right handler

    /// specify output_file_name
    #[arg(short, long)]
    pub(crate) output_file_name: String,

    /// timeout after which a report is produced
    #[arg(short, long, default_value_t = 2000)]
    pub(crate) timeout: u16, //in ms

    /// specify a filter to apply (e.g. TCP, reports TCP's packets only)
    #[arg(short, long)]
    pub(crate) filter: String,
}

//function used to handle cli arguments and eventually choices by the user (e.g. select a device if not known one)
pub fn get_cli() -> Args {
    let mut args = Args::parse(); //launching CLI

    if args.net_adapter == -1 { //if this value is == -1 then user wants to see the list of devices
        let mut count = 0; //counter used to display a list jointly with the devices available and to select one
        let list = Device::list().unwrap(); //get the list of devices
        println!("Select a device:");

        for d in list.iter(){ //print list and counter (used to select the device)
            println!("count: {} device: {:?}", count, d.name);
            count+=1;
        }

        let mut user_input = String::new(); //gettin user's input choice
        let stdin = io::stdin();
        stdin.read_line(&mut user_input).unwrap();

        let my_int = user_input.trim().parse::<i8>().unwrap();
        args.net_adapter = my_int; //assign value selected to the struct to return
    }

    args //struct returned with filled value
}

