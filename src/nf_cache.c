/**
 * @file    nf_cache.c
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#include "nf_cache.h"


#pragma region CTORS_DTORS

timeval_t *timeval_ctor()
{
    timeval_t *timeval = (timeval_t *)malloc(sizeof(struct timeval));
    if (timeval == NULL)
    {
        fprintf(stderr, "Allocation of struct timeval failed.\n");
        exit(INTERNAL_ERROR);
    }
    return timeval;
}

nf_key_t *nf_key_ctor()
{
    nf_key_t *nf_key = (nf_key_t *)malloc(sizeof(struct nf_key));
    if (nf_key == NULL)
    {
        fprintf(stderr, "Allocation of struct nf_key failed.\n");
        exit(INTERNAL_ERROR);
    }
    return nf_key;
}

nf_data_t *nf_data_ctor()
{
    nf_data_t *nf_data = (nf_data_t *)malloc(sizeof(struct nf_data));
    if (nf_data == NULL)
    {
        fprintf(stderr, "Allocation of struct nf_data failed.\n");
        exit(INTERNAL_ERROR);
    }
    nf_data->key = nf_key_ctor();
    nf_data->first_sys = timeval_ctor();
    nf_data->last_sys = timeval_ctor();
    return nf_data;
}

nf_t *nf_ctor()
{
    nf_t *nf = (nf_t *)malloc(sizeof(struct nf));
    if (nf == NULL)
    {
        fprintf(stderr, "Allocation of struct nf failed.\n");
        exit(INTERNAL_ERROR);
    }
    nf->data = nf_data_ctor();
    nf->prev = NULL;
    nf->next = NULL;
    return nf;
}

nf_cache_t *nf_cache_ctor()
{
    nf_cache_t *nf_cache = (nf_cache_t *)malloc(sizeof(struct nf_cache));
    if (nf_cache == NULL)
    {
        fprintf(stderr, "Allocation of struct nf_cache failed.\n");
        exit(INTERNAL_ERROR);
    }
    return nf_cache;
}


void nf_data_dtor(nf_data_t *nf_data)
{
    free(nf_data->key);
    nf_data->key = NULL;
    free(nf_data->first_sys);
    nf_data->first_sys = NULL;
    free(nf_data->last_sys);
    nf_data->last_sys = NULL;
    free(nf_data);
}

void nf_dtor(nf_t *nf)
{
    nf->prev = NULL;
    nf->next = NULL;
    nf_data_dtor(nf->data);
    nf->data = NULL;
    free(nf);
}

#pragma endregion CTORS_DTORS


void nf_cache_init(nf_cache_t *cache)
{
    cache->first = NULL;
    cache->last = NULL;
    cache->nf_cnt = 0;
}

void nf_insert(nf_cache_t *cache, nf_t *new_nf)
{
    new_nf->prev = NULL;
    new_nf->next = cache->first;
    if (cache->first != NULL)
    {
        // Cache is not empty
        cache->first->prev = new_nf;
    }
    else
    {
        cache->last = new_nf;           // Set nf to last
    }
    cache->first = new_nf;          // Cache is empty, added first element
    cache->nf_cnt++;
}

// After exporting the netflow
void nf_delete(nf_cache_t *cache, nf_t *nf_todelete)
{
    if (nf_todelete->prev == NULL && nf_todelete->next == NULL)
    {
        cache->first = NULL;
        cache->last = NULL;
    }
    else if (nf_todelete->prev == NULL && nf_todelete->next != NULL)
    {
        // Is first
        nf_t *right_nf = nf_todelete->next;
        right_nf->prev = NULL;
        cache->first = right_nf;
    }
    else if (nf_todelete->prev != NULL && nf_todelete->next == NULL)
    {
        // Is last
        nf_t *left_nf = nf_todelete->prev;
        left_nf->next = NULL;
        cache->last = left_nf;
    }
    else
    {
        // Is in middle
        nf_t *left_nf = nf_todelete->prev;
        nf_t *right_nf = nf_todelete->next;
        left_nf->next = right_nf;
        right_nf->prev = left_nf;
    }
    nf_dtor(nf_todelete);
    cache->nf_cnt--;
}

/// @brief Compares the existing netflow with loaded netflow
/// @param existing_key Existing netflow stored in cache
/// @param loaded_key   Loaded netflow from pcap file
/// @return True whether netflows are equal, false otherwise
bool nf_equals(nf_key_t *existing_key, nf_key_t *loaded_key)
{
    return existing_key->ip_protocol == loaded_key->ip_protocol &&
        (
           (
           existing_key->src_ip      == loaded_key->src_ip      &&
           existing_key->dst_ip      == loaded_key->dst_ip      &&
           existing_key->src_port    == loaded_key->src_port    &&
           existing_key->dst_port    == loaded_key->dst_port
           )
        ||
           (
           existing_key->src_ip      == loaded_key->dst_ip      &&
           existing_key->dst_ip      == loaded_key->src_ip      &&
           existing_key->src_port    == loaded_key->dst_port    &&
           existing_key->dst_port    == loaded_key->src_port
           )
        );
}

/// @brief Get netflow
/// @param cache Cache with all netflows
/// @param key_to_find Key to find6
/// @return Existing netflow or NULL if doesn't exist
nf_t *get_nf(nf_cache_t *cache, nf_key_t *key_to_find)
{
    nf_t *tmp_nf = cache->first;
    while (tmp_nf != NULL)
    {
        nf_key_t *tmp_nf_key = tmp_nf->data->key;
        if (nf_equals(tmp_nf_key, key_to_find))
            break;
        tmp_nf = tmp_nf->next;
    }
    return tmp_nf;
}

/** End of file nf_cache.c **/
