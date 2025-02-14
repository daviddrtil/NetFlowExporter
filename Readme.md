# NetFlow Exporter

## Project Description
This project implements a NetFlow exporter capable of processing captured network traffic in pcap format, generating NetFlow records from it, and sending them to a collector. Exported NetFlow records can be used for network traffic analysis, infrastructure performance monitoring, or attack detection.

## Technology stack
- Programming Language: C
- Libraries: `pcap`, `netinet`
- Supported NetFlow Version: v5

## Installation and Execution
### Requirements
- GNU/Linux
- GCC (Gnu Compiler Collection)
- `libpcap` library

### Compilation
```sh
make
```

### Execution
```sh
./netflow_exporter -f <pcap_file> -c <collector_address> -p <port>
```
**Example:**
```sh
./netflow_exporter -f test.pcap -c 127.0.0.1 -p 2055
```

## Detailed Description
- **Argument Processing**: Arguments are handled using the `parse_arguments()` function.
- **Main Loop**: The program iterates through the pcap file and analyzes only packets with TCP, UDP, and ICMP protocols.
- **NetFlow Aggregation**: NetFlow records are created based on the key `(protocol, src_ip, src_port, dst_ip, dst_port)`.
- **Data Export**: Generated NetFlow records are sent to the specified collector.

## Testing
### Testing Methods Used:
1. **Wireshark**: Capturing and visualizing NetFlow datagrams.
2. **Softflowd**: Comparing output with a reference exporter.
3. **nfcapd + nfdump**: Analyzing captured NetFlow data.
4. **Testing on the Merlin Server**: Verifying functionality on the university server.

## Author
- **Name:** David Drtil
- **Login:** xdrtil03

## References
- Cisco NetFlow: [Cisco Documentation](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- NetFlow Key: [Cisco Community](https://community.cisco.com/t5/security-knowledge-base/netflow-on-asa/ta-p/3119176)
- TCP Flags: [Manito Networks](https://www.manitonetworks.com/flow-management/2016/10/16/decoding-tcp-flags)

## License
This project is intended for academic purposes within the ISA course at VUT FIT.
