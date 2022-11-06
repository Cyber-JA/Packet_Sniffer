//CLI developed using clap
use clap::Parser;
use pcap::Device;
use std::io;
use std::io::BufRead;

//TODO: check input values correctness and managing errors.
/// time to sniff
#[derive(Parser, Debug)]
#[command(author="Caruso, Andorno, Fois", version, about = "A simple packet_sniffer", long_about = "A simple packet_sniffer in Rust language. All right reserved")]
pub struct Args {
    /// specify net_adapter, do not use this option to see a list of available devices and select among them
    #[arg(short, long, default_value_t = 0)]
    pub(crate) net_adapter: usize, //used as index, given a list of device, to get the right handler

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
    let mut user_input = String::new(); //gettin user's input choice
    let mut my_int = 0;


    /*****CHECKING VALUE TO SELECT DEVICE AND CHECK CORRECTNESS OF VALUES PROVIDED****/
    if args.net_adapter == 0 {
        let mut count:usize = 1;
        let list = Device::list().unwrap(); //get the list of devices
        println!("Select a device:");

        for d in list.iter(){ //print list and counter (used to select the device)
            println!("count: {} device: {:?}", count, d.desc.as_ref().unwrap());
            count+=1;
        }
        while my_int <= 0 || my_int > list.len() - 1 {
            io::stdin().lock().read_line(&mut user_input).unwrap();
            my_int = user_input.trim().parse::<usize>().unwrap();
            if my_int < 1 || my_int > list.len() { user_input.clear(); println!("Error! Insert a valid number:");}
        }
        args.net_adapter = my_int; //assign value selected to the struct to return
    }
    /*******************************************************************************/

    args //struct returned with filled value
}

