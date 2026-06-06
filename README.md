# TCP/IP Packet Demultiplexer

## Build Instructions
1. Ensure `libpcap-dev` and `build-essential` are installed on your system.
   * `sudo apt install libpcap-dev build-essential`
2. Run `make` in the project root directory to compile the executable.

## How to Run
The program requires a network interface as a command-line argument.
* Example: `./demux eth0`

## Required Permissions
Capturing packets requires root privileges or the `CAP_NET_RAW` capability.
* Execute with sudo: `sudo ./demux eth0`
* Or grant capability: `sudo setcap cap_net_raw+ep ./demux`