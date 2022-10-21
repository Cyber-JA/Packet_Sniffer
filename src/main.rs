//main di test
use crate::cli::get_cli;

mod cli;
mod lib;

fn main() {
    let mut args = get_cli();
    println!("{}", args.net_adapter);
    println!("{}", args.output_file_name);
    println!("{}", args.filter);
    println!("{}", args.timeout);
}