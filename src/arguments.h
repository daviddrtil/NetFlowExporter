/**
 * @file    arguments.h
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Error codes
#define PROCESS_ABORTED        9
#define INVALID_ARGUMENT       10
#define PCAP_FUNCTION_FAILED   11
#define SOCKET_FUNCTION_FAILED 12
#define INTERNAL_ERROR         99    // Allocation failed or failed to open file

#define MILISECONDS 1000             // Miliseconds (ms) in second
#define MIKROSECONDS 1000000         // Microseconds (us) in second

// Buffer sizes
#define PORT_NUMBER_LENGHT 6

// Default netflow exporter values
#define DEFAULT_COLLECTOR_ADDR "127.0.0.1"
#define DEFAULT_PORT_NUMBER    2055
#define DEFAULT_PCAP_FILE      "-"   // "-" means stdin
#define DEFAULT_ACTIVE_TIMER   60 * MIKROSECONDS
#define DEFAULT_INACTIVE_TIMER 10 * MIKROSECONDS
#define DEFAULT_CACHE_SIZE     1024

// Contains program arguments data
typedef struct args
{
    struct sockaddr_in collector_addr;  // server address
    int socket_id;
    char *pcap_file_name;
    uint64_t active_interval;       // Measured in microsecond (us)
    uint64_t inactive_interval;     // Measured in microsecond (us)
    int flow_cache_size;
} args_t;


void print_help();

int convert_string2int(char *number, const char *error_message);

args_t *parse_arguments(int argc, char **argv);

void args_dtor(args_t *args);


#endif

/** End of file arguments.h **/
