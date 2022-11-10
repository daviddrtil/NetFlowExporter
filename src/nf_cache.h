/**
 * @file    nf_cache.h
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#ifndef NF_CACHE_H
#define NF_CACHE_H

#include "arguments.h"

// Used typedef to get rid of writing struct
typedef struct timeval timeval_t;

typedef struct nf_key
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_protocol;
} nf_key_t;

// todo doplnit dalsi potrebne udaje
typedef struct nf_data
{
    // Flow key
    nf_key_t *key;

    // Additional info - updateable
    uint32_t dPkts;             // Packets in flow
    uint32_t dOctets;           // Total number of Layer 3 bytes in the packets of the flow
                                // (every time is added packet to flow, it's incremented DOctets += ip_hl)
    timeval_t *first_sys;       // SysUpTime at start of flow
    timeval_t *last_sys;        // SysUpTime at time last packet of the flow was received
    uint8_t tcp_flags;         // Cumulative OR of TCP flags   // todo
    uint8_t tos;               // IP type of service           // todo
} nf_data_t;

typedef struct nf
{
    nf_data_t *data;
    struct nf *prev;
    struct nf *next;
} nf_t;

// NetFlow cache is implemented as double linked list
typedef struct nf_cache
{
    nf_t *first;        // newest
    nf_t *last;         // oldest
    int nf_cnt;         // total cnt
} nf_cache_t;


timeval_t *timeval_ctor();
nf_key_t *nf_key_ctor();
nf_data_t *nf_data_ctor();
nf_t *nf_ctor();
nf_cache_t *nf_cache_ctor();

void nf_data_dtor(nf_data_t *nf_data);
void nf_dtor(nf_t *netflow);

void nf_cache_init(nf_cache_t *cache);

void nf_insert(nf_cache_t *cache, nf_t *new_nf);

void nf_delete(nf_cache_t *cache, nf_t *nf_todelete);

bool nf_equals(nf_key_t *existing_key, nf_key_t *loaded_key);

nf_t *get_nf(nf_cache_t *cache, nf_key_t *key_to_find);

#endif

/** End of file nf_cache.h **/
