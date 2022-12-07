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
- `DNS`
- `TLS`
- `DHCP`

## Timeout
This sniffer gives the chance to setup a timeout (in seconds). When the timeout expires, a report is generated the first time (e.g. file specified in the `-o file_name` option, if not existing, otherwise the old one is overwritten) and the timeout is restarted. Then, when expires, report is updated. And so on.
N.B. If this option is not used, a default one is set (2 s).

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

## Errors
Using the tool, it is possible that some misbehaviour leads to errors, going in the opposite of the intended usage.
The one following is a list of the errors shown to the user, their context and their explanation:
- Adapter selection
  - If a number maps to a Device not included in the list supported by the tool then this error is shown to the user: `Error! Insert a valid number`. Then it is give the chance to prompt again.
  - If user's input is not a number then the Error `Error: Invalid input!` is shown to the user.
- Filter selection
  - In the filter selection, only supported filters can be specified, otherwise all the packets will be sniffed. `Error: Filter <FILTER_NAME> is not available`
- After configuration
  - After the configuration, the commands `start, pause, stop, resume` are possible. If other commands are specified, then the Error `Error: Invalid command...` is shown to the user
  - If there is no sniffing session started (even if paused) and the user try to pause or resume it, then respectively `Error: Can't pause, no sniffing session in progress!` `Error: Can't resume, no sniffing session to resume!` are shown. Then it is given the chance to prompt again a command.
  - If there is no sniffing session paused but started and the user try to start it, then `Error: A sniffing session is still in progress!` is shown. Then it is given the chance to prompt again a command.
- During sniffing
  - If something goes wrong during the sniffing, such as channels drop (channels are used as communication primitives), the error `Unexpected error! Press stop to end the program.` is shown to the user, giving the chance to shut down the tool.
  - Since threads are writing files, it is possible that errors occur. In such cases the error `Impossible to open the file! Press stop to end the program.` is shown if there are problems with file creation and opening and the error `Error! Not possible to write on file...` is shown if problems in writing such file arise.
  
## Functions
Follows a list of the main modules and their functionalities:
- `cli.rs`
  - this module contains all the functionalities used to interact with the user and to build the CLI (e.g. check the `get_cli()` function for further information).
- `sniffing_thread.rs`
  - this module contains the functions used to sniff packets (e.g. check the `sniff()` function for further information).
- `writing_thread.rs`
  - this module contains the functions used to interact with the sniffing thread (by means of a shared structure) and to write the report (e.g. check the `write_file()` function for further information).
- `parsing.rs`
  - this module contains the functions used to parse sniffed packets (e.g. check the `parse()` function for further information).
