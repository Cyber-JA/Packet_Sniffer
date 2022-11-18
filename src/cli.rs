//CLI developed using clap
pub(crate) mod cli {
    use clap::Parser;
    use pcap::Device;
    use std::io;
    use std::io::BufRead;

    #[allow(non_snake_case)]
//TODO: check input values correctness and managing errors.
    /// time to sniff
    #[derive(Parser, Debug)]
    #[command(author = "Caruso, Andorno, Fois", version, about = "A simple packet_sniffer", long_about = "A simple packet_sniffer in Rust language. All rights reserved")]
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
        let mut my_int = 0; //flag used to select the correct device

        /*****CHECKING VALUE TO SELECT DEVICE AND CHECK CORRECTNESS OF VALUES PROVIDED****/
        if args.net_adapter == 0 {
            let mut count: usize = 1;
            let list = Device::list().unwrap(); //get the list of devices
            println!("Select a device:");

            for d in list.iter() { //print list and counter (used to select the device)
                println!("count: {} device: {:?}", count, d.desc.as_ref().unwrap());
                count += 1;
            }
            while my_int <= 0 || my_int > list.len() - 1 {
                my_int = read_input_usize(list.len());
            }
            args.net_adapter = my_int; //assign value selected to the struct to return
        }
        /*******************************************************************************/

        args //struct returned with filled value
    }

    pub fn read_input_string() -> String {
        println!("Waiting for user input...");
        let mut user_input = String::new();
        let std = io::stdin().lock().read_line(&mut user_input).unwrap();
        user_input = user_input.trim().parse().unwrap();
        user_input
    }

    pub fn read_input_usize(len: usize) -> usize {
        println!("Waiting for user input...");
        let mut user_input = String::new();
        let std = io::stdin().lock().read_line(&mut user_input).unwrap();
        let my_int = user_input.trim().parse::<usize>().unwrap();
        if my_int < 1 || my_int > len { println!("Error! Insert a valid number:"); }
        my_int
    }

    pub fn get_user_commands() -> String {
        println!("Commands:");
        println!("-'pause' to pause the sniffing (can resume)");
        println!("-'stop' to stop the sniffing");
        println!("-'resume' to resume the sniffing");
        let mut user_input = read_input_string();
        match user_input.as_str() {
            "pause" => {}
            "resume" => {}
            "stop" => {}
            _ => { println!("Invalid command...") }
        }
        user_input
    }
}