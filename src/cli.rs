//CLI developed using clap
use clap::Parser;

/// time to sniff
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// specify net_adapter
    #[arg(short, long)]
    pub(crate) net_adapter: u8, //used as index, given a list of device, to get the right handler

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

pub fn get_cli() -> Args {
    let args = Args::parse();
    args
}

