# IPK - project 1

Creates a server, that communicates via HTTP protocol and provides information about system.

The server listen on specific port and via url send answers.

Communication with the server is possible with web browser and tools like wget, curl.


---
## Getting started

Via makefile compile and build project.
Write command "make", which creates executable file "hinfosvc".

The server is executable with argument indicating port number.

The server is possible to shut down by 'CTRL + C'.


## Supported requests
**It's able to process 3 types of requests:**
1. Obtain domain name - the network name of computer, including the domain
2. Obtain full cpu name
3. Obtain current cpu load / cpu usage

## Usage

hinfosvc [PORT NUMBER]

> :warning: **Port number has to from interval <0, 2^16 - 1>, i.e. <0, 65535>.**

$ 1st example
```
./hinfosvc 12345 & curl http://localhost:12345/hostname
```

$ 2nd example
```
./hinfosvc 49152 & curl http://localhost:49152/cpu-name
```

$ 3rd example
```
./hinfosvc 51520 & curl http://localhost:51520/load
```


## Author
David Drtil, <xdrtil03@stud.fit.vutbr.cz>
