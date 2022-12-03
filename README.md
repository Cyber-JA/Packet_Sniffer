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


