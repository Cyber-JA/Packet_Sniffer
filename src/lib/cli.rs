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

    /// timeout (in seconds) after which a report is produced (default value: 2 s)
    #[arg(short, long, default_value_t = 2)]
    pub(crate) timeout: u16, //in ms

    /// specify filters to apply between quotes (e.g. TCP, reports TCP's packets only), do not specify parameters to see a list of available filters
    #[clap(short = 'f', long, default_value = "no")]
    pub(crate) filter: String,

    pub(crate) filters_list: Vec<String>,
}

//function used to handle cli arguments and eventually choices by the user (e.g. select a device if not known one)
pub fn get_cli() -> Args {
    let mut args = Args::parse(); //launching CLI
    let n = args.net_adapter.clone();
    let f = trim_whitespaces(comma_to_space(args.filter.clone().as_str()).as_str());
    args.net_adapter = select_device(n);
    args.filters_list = select_filters(f);
    args //struct returned with filled value
}

pub fn read_input_string() -> String {
    println!("Waiting for user input...");
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    print!(">>> ");
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    let mut user_input = String::new();
    let val = io::stdin().lock().read_line(&mut user_input);
    match val {
        Ok(_) => {}
        Err(err) => {
            println!("{}", err);
        }
    }
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    user_input = user_input.trim().parse().unwrap();
    user_input
}
#[allow(unused_assignments)]
pub fn read_input_usize(len: usize) -> usize {
    let check;
    let mut my_int = 0;
    println!("Waiting for user input...");
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    print!(">>> ");
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    let mut user_input = String::new();
    io::stdin().lock().read_line(&mut user_input).unwrap();
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    check = user_input.trim().parse::<usize>();
    match check {
        Ok(val) => {
            my_int = val;
        }
        Err(_) => {
            println!("Error: Invalid input!");
            my_int = read_input_usize(len.clone());
        }
    }
    if my_int < 1 || my_int > len {
        println!("Error! Insert a valid number:");
        let res = stdout().flush();
        match res {
            Ok(_) => {}
            Err(_) => {
                println!(
                    "Error! Not all bytes could be written due to I/O errors or EOF being reached."
                )
            }
        }
    }
    my_int
}

pub fn get_user_commands() -> String {
    println!("Commands:");
    println!("-'start' to start the sniffing");
    println!("-'pause' to pause the sniffing (can resume)");
    println!("-'stop' to stop the sniffing");
    println!("-'resume' to resume the sniffing");
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    let user_input = read_input_string();
    match user_input.as_str() {
        "start" => {}
        "pause" => {}
        "resume" => {}
        "stop" => {}
        _ => {
            println!("Error: Invalid command...");
            let res = stdout().flush();
            match res {
                Ok(_) => {}
                Err(_) => {
                    println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                }
            }
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
        let res = stdout().flush();
        match res {
            Ok(_) => {}
            Err(_) => {
                println!(
                    "Error! Not all bytes could be written due to I/O errors or EOF being reached."
                )
            }
        }
        for (num, net_adapter) in list.iter().enumerate() {
            println!(
                "{}) {} - {:?}",
                num + 1,
                net_adapter.desc.as_ref().unwrap(),
                net_adapter.addresses[1].addr
            );
            let res = stdout().flush();
            match res {
                Ok(_) => {}
                Err(_) => {
                    println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                }
            }
        }
        while my_int <= 0 || my_int > list.len() - 1 {
            my_int = read_input_usize(list.len());
        }
    } else {
        my_int = net_adapter;
        if my_int <= 0 || my_int > list.len() - 1 {
            println!("Error! Insert a valid number:");
            let res = stdout().flush();
            match res {
                Ok(_) => {}
                Err(_) => {
                    println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                }
            }
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
    let res = stdout().flush();
    match res {
        Ok(_) => {}
        Err(_) => {
            println!(
                "Error! Not all bytes could be written due to I/O errors or EOF being reached."
            )
        }
    }
    println!("> udp");
    println!("> tcp");
    println!("> icmp");
    println!("> igmp");
    println!("> arp");
    println!("> dns");
    println!("> tls");
    println!("> dhcp");
}

pub fn trim_whitespaces(s: &str) -> String {
    let words: Vec<_> = s.split_whitespace().collect();
    words.join(" ")
}

pub fn comma_to_space(s: &str) -> String {
    let words: Vec<_> = s.split(",").collect();
    words.join(" ")
}

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
    list.push(String::from("dns"));
    list.push(String::from("tls"));
    list.push(String::from("dhcp"));
    list.push(String::from("igmp"));
    let mut flag = false;
    for f in filter.as_str().trim().split(" ") {
        flag = false;
        for l in list.iter() {
            if f.to_lowercase().eq(l) == true {
                flag = true;
                break;
            };
        }
        if flag == false && filter.ne("no") {
            println!("Error: Filter <{}> is not available", f);
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
        let res = stdout().flush();
        match res {
            Ok(_) => {}
            Err(_) => {
                println!(
                    "Error! Not all bytes could be written due to I/O errors or EOF being reached."
                )
            }
        }
        let input_string = read_input_string();
        match input_string.as_str() {
            "" => {
                println!("No filters applied...");
                let res = stdout().flush();
                match res {
                    Ok(_) => {}
                    Err(_) => {
                        println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                    }
                }
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
                println!("No filters applied");
                let res = stdout().flush();
                match res {
                    Ok(_) => {}
                    Err(_) => {
                        println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                    }
                }
                break;
            }
            _ => {
                if are_filters_acceptable(input_string.clone()) {
                    list = filters_as_vec(input_string);
                    break;
                } else {
                    loop {
                        println!("Insert filters (ENTER to apply no filtering)");
                        let res = stdout().flush();
                        match res {
                            Ok(_) => {}
                            Err(_) => {
                                println!("Error! Not all bytes could be written due to I/O errors or EOF being reached.")
                            }
                        }
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
