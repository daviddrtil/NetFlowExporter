/**
 * @file    netflow_exporter.h
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#ifndef NETFLOW_EXPORTER_H
#define NETFLOW_EXPORTER_H

#include "nf_cache.h"

// Constants for program usage
#define IP_ADDRESS_LENGHT_IN_BYTES 4
#define WORDS2BYTES_SIZE 4          // In header is stored only 4 bit number that specify number of 32-bit words

// Protocol types
#define IPV4_PROTOCOL   0x0800
#define ICMP_PROTOCOL   0x01
#define TCP_PROTOCOL    0x06
#define UDP_PROTOCOL    0x11


// Buffer sizes
#define IPV4_ADDRESS_LENGHT 16
#define MAC_ADDRESS_LENGHT  18
#define DATE_LENGHT         20
#define TIMESTAMP_LENGHT    30

#define DISPLAY_FILTER "ip and (tcp or udp or icmp)"

// from: https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
#define NETFLOW_DATAGRAM_V5_SIZE sizeof(netflow_datagram_v5_t)
typedef struct netflow_datagram_v5
{
    // Header format
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t  engine_type;
    uint8_t  engine_id;
    uint16_t sampling_interval;

    // Flow record format
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  pad1;
    uint8_t  tcp_flags;
    uint8_t  prot;
    uint8_t  tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t  src_mask;
    uint8_t  dst_mask;
    uint16_t pad2;
} netflow_datagram_v5_t;

// Used typedef to get rid of writing struct
typedef struct bpf_program bpf_program_t;
typedef struct timeval timeval_t;

void nf_export(nf_cache_t *cache, nf_t *nf_to_export, args_t *args, uint64_t current_time);

// todo add other function definitions

#endif

/** End of file netflow_exporter.h **/
