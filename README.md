# Packet_Sniffer

- [Basic Usage](#basic-usage)
- [Available Options](#available-options)

## Basic Usage

To run the provided test application (clone then build):
```
Packet_Sniffer.exe [OPTIONS] --output-file-name <OUTPUT_FILE_NAME> -f <FILTERS_LIST>...
```
```
cargo run [--] [args]...
```

### Arguments:  
```
[FILTERS_LIST...]
```
Multiple arguments and options are possible, check the section [Available Options](#available-options) for more.

## Available Options

Options:
```
-f, --filter "FILTER(s)"
  Specify filters to apply. Passing list as parameter will print a list of supported filters.
  Usage: cargo run -- -o report -f "tcp udp arp", cargo run -- -o report -f "list"

-n, --net-adapter <NET_ADAPTER>
  Specify the number of the net_adapter, do not use this option to see a list of available devices
  Usage: cargo run -- -o report -n 1

-o, --output-file-name <OUTPUT_FILE_NAME>
  Specify output_file_name. If such *.txt* file exists, it will be overwritten, otherwise a new one is created in the `cwd`.
  Usage: cargo run -- -o report

-t, --timeout <TIMEOUT>
  Specify timeout after which a report is produced/updated [default: 2000 ms]
  Usage: cargo run -- -o report -t 1000 

-V, --version
  Print version information
  Usage: cargo run -- -V

-h, --help
  Print help information (use `--help` for more detail)
  Usage: cargo run -- -h, cargo run -- --help
```

## Supported Filters
This section list the supported filters.
Note that those filters are not mutually exclusive (e.g. -f "tcp arp" will sniff *TCP* and *ARP* packets
Following filters are the ones supported, more can and will be added:
To get the list of supported filters `-f list`
- `TCP`
- `UDP`
- `ARP`
- `ICMP`

## Timeout
This sniffer gives the chance to setup a timeout. When the timeout expires, a report is generated the first time (e.g. file specified in the `-o file_name` option, if not existing, otherwise the old one is overwritten) and the timeout is restarted. Then, when expires, report is updated. And so on.
N.B. If this option is not used, a default one is set (2000 ms).

## Network Adapters
It is possible to specify the network adapter to be used during the sniffing. 
Do not specify this option to get a list of the available ones, giving chance to choose.
Not all the network adapters are active on the machine, hence pay attention to the selected one (usually the one with an IPv4 classic address).

## Available Commands
Commands available to control the sniffing process:
- `start`: when the configuration is finished, the sniffing process can start.
- `pause`: to temporarily pause the sniffing process (can resume later)
- `resume`: resume the sniffing process from a paused session.
- `stop`: kill the sniffing process, shutting down the application
