# Packet Sniffer - IPK 2nd project, variant ZETA

The network analyzer that is capable of capturing and filtering packets on a the network interface.


---
## Getting started

Via makefile compile and build project.

Write command "make", which creates executable file "ipk-sniffer".

The program, sniffer, is executable either without inteface argument to list out all active intefaces
or with interface argument on which will be listen to and arbitrary set of other optional arguments.

The sniffer is possible to shut down safely by 'CTRL + C' or other system interrupt signal,
in this way all recources are freed and program exited.


## Supported protocols
It's possible to capture, filter out packets with both IPv4 and IPv6.

**Sniffer is able to process 4 main types of protocols:**
1. ARP
2. ICMP - ICMPv6 is also supported
3. TCP
4. UDP


---
## Usage

ipk-sniffer [-i interface | --interface interface] [OPTIONS...]
ipk-sniffer [-h | --help]

Optional arguments can be arbitrarily combined.

### Optional arguments:

    -p <port_number>    Filter packets on the specific interface by port.

                        If this argument is not set, all ports are considered.

                        If no argument for filtering tcp or udp is set, 

                        automaticaly filter packets both protocols tcp and upd.

> :warning: **Port number has to be in interval <0, 2^16 - 1>, i.e. <0, 65535>.**

    -n <packet_number>  Display only given number of packets. 

                        Implicitly is set to show only one packet.
> :warning: **Number of packet has to be higher than 1.**

**Filters:**

    --tcp | -t          Display only TCP packets.
    --udp | -u          Display only UDP packets.
    --arp               Display only ARP frames.
    --icmp              Display only ICMPv4 and ICMPv6 packets.

Whether any of optional arguments aren't set, sniffer capturing packets of all 4 protocols.

It can be set 1 or more protocol filters.


### Examples:

$ 1st example
```
./ipk-sniffer
```

$ 2nd example
```
./ipk-sniffer -i ens33 --arp
```

$ 3rd example
```
./ipk-sniffer -i lo -p 45901 --tcp --udp
```

$ 4th example
```
./ipk-sniffer -i lo -n 10 --icmp
```

---
## Author
David Drtil, <xdrtil03@stud.fit.vutbr.cz>

### License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  
