use clap::Parser;
use pcap::Device;
use std::io;
use std::io::{stdout, BufRead, Write};
use Option;

//CLI developed using
/// time to sniff
#[derive(Parser, Debug, Default)]
#[command(
    author = "Caruso, Andorno, Fois",
    version,
    about = "A simple packet_sniffer",
    long_about = "A simple packet_sniffer in Rust language. All rights reserved"
)]
pub struct Args {
    /// specify net_adapter, do not use this option to see a list of available devices
    #[arg(short, long, default_value_t = 0)]
    pub(crate) net_adapter: usize, //used as index, given a list of device, to get the right handler

    /// specify output_file_name
    #[arg(short, long)]
    pub(crate) output_file_name: String,

    /// timeout after which a report is produced (default value: 2000)
    #[arg(short, long, default_value_t = 2000)]
    pub(crate) timeout: u16, //in ms

    /// specify filters to apply between quotes (e.g. TCP, reports TCP's packets only), do not specify parameters to see a list of available filters
    /// Follows BPF syntax to specify protocols, otherwise no filter will be applied
    #[clap(short = 'f', long, default_value = "no")]
    pub(crate) filter: String,

    pub(crate) filters_list: Vec<String>,
}


//function used to handle cli arguments and eventually choices by the user (e.g. select a device if not known one)
pub fn get_cli() -> Args {
    let mut args = Args::parse(); //launching CLI
    let n = args.net_adapter.clone();
    let f = args.filter.clone();
    args.net_adapter = select_device(n);
    args.filters_list = select_filters(f);
    args //struct returned with filled value
}

pub fn read_input_string() -> String {
    println!("Waiting for user input...");
    stdout().flush().unwrap();
    println!(">>>");
    stdout().flush().unwrap();
    let mut user_input = String::new();
    io::stdin().lock().read_line(&mut user_input).unwrap();
    user_input = user_input.trim().parse().unwrap();
    user_input
}

pub fn read_input_usize(len: usize) -> usize {
    println!("Waiting for user input...");
    stdout().flush().unwrap();
    println!(">>>");
    stdout().flush().unwrap();
    let mut user_input = String::new();
    io::stdin().lock().read_line(&mut user_input).unwrap();
    let my_int = user_input.trim().parse::<usize>().unwrap();
    if my_int < 1 || my_int > len {
        println!("Error! Insert a valid number:");
        stdout().flush().unwrap();
    }
    my_int
}

pub fn get_user_commands() -> String {
    println!("Commands:");
    println!("-'start' to start the sniffing");
    println!("-'pause' to pause the sniffing (can resume)");
    println!("-'stop' to stop the sniffing");
    println!("-'resume' to resume the sniffing");
    stdout().flush().unwrap();
    let user_input = read_input_string();
    match user_input.as_str() {
        "start" => {}
        "pause" => {}
        "resume" => {}
        "stop" => {}
        _ => {
            println!("Invalid command...");
            stdout().flush().unwrap();
        }
    }
    user_input
}

pub fn select_device(net_adapter: usize) -> usize {
    let mut my_int = 0; //flag used to select the correct device
    let list = Device::list().unwrap();

    /*****CHECKING VALUE TO SELECT DEVICE AND CHECK CORRECTNESS OF VALUES PROVIDED****/
    if net_adapter == 0 {
        println!("Select a device:");
        stdout().flush().unwrap();
        for (num, net_adapter) in list.iter().enumerate() {
            println!(
                "{}) {} - {:?}",
                num + 1,
                net_adapter.desc.as_ref().unwrap(),
                net_adapter.addresses[1].addr
            );
            stdout().flush().unwrap();
        }
        while my_int <= 0 || my_int > list.len() - 1 {
            my_int = read_input_usize(list.len());
        }
    }
    return my_int;
    /*******************************************************************************/
}

pub fn show_filters_available() {
    println!("The following filters are supported: ");
    stdout().flush().unwrap();
    println!("> udp");
    println!("> tcp");
    println!("> icmp");
    println!("> arp");
}

/*pub fn select_filters(filter: String) -> String {
    let mut string_to_ret = String::new();
    match filter.as_str() {
        "list" => {
            show_filters_available();
            string_to_ret = read_input_string();
        }
        "no" => {
            println!("No filters applied, all the packets will be shown...");
            stdout().flush().unwrap();
        }
        _ => {
            string_to_ret = filter.clone();
        }
    }
    return string_to_ret;
}
*/
pub fn select_filters(filter: String) -> Vec<String> {
    let mut vec_to_ret = Vec::new();
    match filter.as_str() {
        "list" => {
            show_filters_available();
            vec_to_ret = select_among_filters();
        }
        _ => {
            if are_filters_acceptable(filter.clone()) == true {
                vec_to_ret = select_among_filters_with_provided_input(filter.clone());
            }
        }
    }
    return vec_to_ret;
}

pub fn are_filters_acceptable(filter: String) -> bool {
    let mut list: Vec<String> = Vec::new();
    list.push(String::from("tcp"));
    list.push(String::from("udp"));
    list.push(String::from("icmp"));
    list.push(String::from("arp"));
    let mut flag = false;
    for f in filter.as_str().trim().split(" ") {
        flag = false;
        for l in list.iter() {
            if f.to_lowercase().eq(l) == true {
                flag = true;
                break;
            };
        }
        if flag == false {
            println!("Filter <{}> is not available yet! But soon it will...", f);
            break;
        };
    }
    return flag;
}

pub fn filters_as_vec(filter: String) -> Vec<String> {
    let mut vec_of_filters = Vec::new();
    for f in filter.as_str().trim().split(" ") {
        vec_of_filters.push(String::from(f.to_lowercase()));
    }
    vec_of_filters
}

pub fn select_among_filters() -> Vec<String> {
    let mut list = Vec::new();
    loop {
        println!("Insert filters (ENTER to apply no filtering)");
        stdout().flush().unwrap();
        let input_string = read_input_string();
        match input_string.as_str() {
            "" => {
                println!("No filters applied, all the packets will be shown...");
                stdout().flush().unwrap();
                break;
            }
            _ => {
                if are_filters_acceptable(input_string.clone()) {
                    list = filters_as_vec(input_string);
                    break;
                }
            }
        }
    }
    list
}

pub fn select_among_filters_with_provided_input(input_string: String) -> Vec<String> {
    let mut list = Vec::new();
    println!("provided input: {}", input_string);
    loop {
        match input_string.as_str() {
            "" => {
                println!("No filters applied, all the packets will be shown...");
                stdout().flush().unwrap();
                break;
            }
            _ => {
                if are_filters_acceptable(input_string.clone()) {
                    list = filters_as_vec(input_string);
                    break;
                } else {
                    loop {
                        println!("Insert filters (ENTER to apply no filtering)");
                        stdout().flush().unwrap();
                        let new_input = read_input_string();
                        if are_filters_acceptable(new_input.clone()) {
                            list = filters_as_vec(new_input);
                            return list;
                        }
                    }
                }
            }
        }
    }
    list
}


