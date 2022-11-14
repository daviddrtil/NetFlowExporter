/**
 * @file    netflow_exporter.c
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#include "netflow_exporter.h"

#define LOG_NETFLOWS_PROCESSING_ENABLED true
#if defined(LOG_NETFLOWS_PROCESSING_ENABLED) && LOG_NETFLOWS_PROCESSING_ENABLED == true
    #define log_netflow_info printf
#else
    #define log_netflow_info
#endif

void handle_sigint(int sig)
{
    printf("\nProccess terminated. Caught signal %d (ctrl + c).\n", sig);
    exit(PROCESS_ABORTED);
}

int create_client_socket(args_t *args)
{
    int socket_id = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_id == 0)
    {
        args_dtor(args);
        fprintf(stderr, "Failed to create a socket with collector address.\n");
        exit(SOCKET_FUNCTION_FAILED);
    }

    if (connect(socket_id, (struct sockaddr *)&args->collector_addr, sizeof(args->collector_addr)) == -1)
    {
        args_dtor(args);
        fprintf(stderr, "Failed connect to server with socket_connect().\n");
        exit(SOCKET_FUNCTION_FAILED);
    }

    return socket_id;
}

pcap_t *pcap_open_file(char *pcap_file_name, args_t *args)
{
    char errbuffer[PCAP_ERRBUF_SIZE] = {'\0'};
    pcap_t *pcap_file = pcap_open_offline(pcap_file_name, errbuffer);
    if (pcap_file == NULL || errbuffer[0] != '\0')
    {
        if (!strcmp(pcap_file_name, "-"))
        {
            fprintf(stderr, "Failed to load pcap input from stdin. Error message: [%s].\n", errbuffer);
        }
        else
        {
            fprintf(stderr, "Failed to load pcap file [%s]. Error message: [%s].\n", 
                pcap_file_name, errbuffer);
        }
        close(args->socket_id);
        args_dtor(args);
        exit(PCAP_FUNCTION_FAILED);
    }
    return pcap_file;
}

bpf_program_t *set_display_filter(pcap_t *pcap_file, args_t *args, const char *display_filter_str)
{
    // Check and recompile the filter of packets
    bpf_program_t *packet_filter = (bpf_program_t *)malloc(sizeof(struct bpf_program));
    if (packet_filter == NULL)
    {
        fprintf(stderr, "Allocation of packet_filter failed.\n");
        exit(INTERNAL_ERROR);
    }
    int pcap_compile_error = pcap_compile(pcap_file, packet_filter, display_filter_str, 0, -1);
    if (pcap_compile_error != 0)
    {
        char *filter_error_message = pcap_geterr(pcap_file);
        fprintf(stderr, "Pcap_compile failed to compile filter \'%s\' with error code %d.\n",
                    display_filter_str, pcap_compile_error);
        fprintf(stderr, "Error message: \'%s\'\n", filter_error_message);
        pcap_close(pcap_file);
        close(args->socket_id);
        args_dtor(args);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Set the filter of packets
    int pcap_setfilter_error = pcap_setfilter(pcap_file, packet_filter);
    if (pcap_setfilter_error != 0)
    {
        char *setfilter_error_message = pcap_geterr(pcap_file);
        fprintf(stderr, "Pcap_setfilter failed to set filter \'%s\' with error code %d.\n",
            display_filter_str, pcap_setfilter_error);
        fprintf(stderr, "Error message: \'%s\'\n", setfilter_error_message);
        pcap_close(pcap_file);
        close(args->socket_id);
        args_dtor(args);
        exit(PCAP_FUNCTION_FAILED);
    }
    return packet_filter;
}

uint64_t convert_timeval2int(timeval_t *time)
{
    return time->tv_sec * MIKROSECONDS + time->tv_usec;
}

void send_netflow(int socket_id, uint8_t *data)
{
    int send_status = send(socket_id, data, NETFLOW_DATAGRAM_V5_SIZE, 0);
    if (send_status == -1)
    {
        fprintf(stderr, "Failed to send data to server with function send().\n");
        exit(SOCKET_FUNCTION_FAILED);
    }
    else if (send_status != NETFLOW_DATAGRAM_V5_SIZE)
    {
        fprintf(stderr, "Failed to send data to server with function send(). Buffer written partially.\n");
        exit(SOCKET_FUNCTION_FAILED);
    }
}

void get_readable_ipv4_address(uint32_t ip_address_number, char *ip_address_buffer)
{
    for (int i = 0; i < IP_ADDRESS_LENGHT_IN_BYTES; i++)
    {
        if (i > 0)
        {
            strcat(ip_address_buffer, ".");
        }
        char tmp[4];
        sprintf(tmp, "%d", ((u_char *)(&ip_address_number))[i]);
        strcat(ip_address_buffer, tmp);
    }
    ip_address_buffer[IPV4_ADDRESS_LENGHT - 1] = '\0';
}

void log_netflow_id(nf_key_t *nf_to_log)
{
    char src_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
    get_readable_ipv4_address(nf_to_log->src_ip, src_ip);

    char dst_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
    get_readable_ipv4_address(nf_to_log->dst_ip, dst_ip);
    
    int src_port = nf_to_log->src_port;
    int dst_port = nf_to_log->dst_port;
    
    log_netflow_info("%15s:%-5d -> %15s:%-5d\n", src_ip, src_port, dst_ip, dst_port);
}

// Parse to netflow v5 format
void nf_export(nf_cache_t *cache, nf_t *nf_to_export, args_t *args, uint64_t sysuptime, uint64_t current_time)
{
    static int exported_flows = 0;
    uint8_t compressed_datagram[NETFLOW_DATAGRAM_V5_SIZE];
    netflow_datagram_v5_t *nf_datagram = (netflow_datagram_v5_t *)compressed_datagram;

    nf_data_t *nf_data = nf_to_export->data;
    uint64_t start_netflow_time = nf_data->first_sys - sysuptime;
    uint64_t end_netflow_time   = nf_data->last_sys - sysuptime;

    // Fill out header informations
    nf_datagram->version = htons(5);
    nf_datagram->count = htons(1);
    nf_datagram->SysUptime = htonl((current_time - sysuptime) / MILISECONDS);
    nf_datagram->unix_secs = htonl(current_time / MIKROSECONDS);
    nf_datagram->unix_nsecs = htonl((current_time * 1000) % NANOSECONDS);
    nf_datagram->flow_sequence = htonl(exported_flows);
    nf_datagram->engine_type = 0;
    nf_datagram->engine_id = 0;
    nf_datagram->sampling_interval = 0;

    // Fill out flow record informations
    nf_datagram->srcaddr = nf_data->key->src_ip;
    nf_datagram->dstaddr = nf_data->key->dst_ip;
    nf_datagram->nexthop = 0;
    nf_datagram->input = 0;
    nf_datagram->output = 0;
    nf_datagram->dPkts = htonl(nf_data->dPkts);
    nf_datagram->dOctets = htonl(nf_data->dOctets);
    nf_datagram->First = start_netflow_time < 0 ? 0 : htonl(start_netflow_time / MILISECONDS);
    nf_datagram->Last = end_netflow_time < 0 ? 0 : htonl(end_netflow_time / MILISECONDS);
    nf_datagram->srcport = nf_data->key->src_port;
    nf_datagram->dstport = nf_data->key->dst_port;
    nf_datagram->pad1 = 0;
    nf_datagram->tcp_flags = nf_data->tcp_flags;
    nf_datagram->prot = nf_data->key->ip_protocol;
    nf_datagram->tos = nf_data->tos;
    nf_datagram->src_as = 0;
    nf_datagram->dst_as = 0;
    nf_datagram->src_mask = 0;
    nf_datagram->dst_mask = 0;
    nf_datagram->pad2 = 0;

    // Log export of netflow
    log_netflow_info("Exported %3d. nf with: ", exported_flows + 1);
    log_netflow_id(nf_to_export->data->key);

    send_netflow(args->socket_id, compressed_datagram);
    nf_delete(cache, nf_to_export);
    exported_flows++;
}

void check_timers(nf_cache_t *cache, args_t *args, uint64_t sysuptime, uint64_t current_time)
{
    nf_t *tmp_nf = cache->last;
    while (tmp_nf != NULL)
    {
        nf_t *tmp_nf_prev = tmp_nf->prev;

        uint64_t first_systime = tmp_nf->data->first_sys;
        uint64_t last_systime = tmp_nf->data->last_sys;
        int active_diff = current_time - first_systime;
        int inactive_diff = current_time - last_systime;
        if (active_diff < 0 || inactive_diff < 0)
        {
            // Packets with incorrect order are skipped
            tmp_nf = tmp_nf_prev;
            continue;
        }

        if (active_diff > args->active_interval || inactive_diff > args->inactive_interval)
        {
            // Export outdated netflow
            if (active_diff > args->active_interval)
            {
                log_netflow_info("Due to expiration of Active timer:\n");
            }
            else
            {
                log_netflow_info("Due to expiration of INactive timer:\n");
            }
            nf_export(cache, tmp_nf, args, sysuptime, current_time);
        }

        tmp_nf = tmp_nf_prev;
    }   // while
}



void create_new_netflow(nf_cache_t *cache, nf_data_t *loaded_data, uint64_t current_time)
{
    nf_t *new_nf = nf_ctor();
    nf_key_t *nf_key = new_nf->data->key;
    nf_key->ip_protocol = loaded_data->key->ip_protocol;
    nf_key->src_ip = loaded_data->key->src_ip;
    nf_key->dst_ip = loaded_data->key->dst_ip;
    nf_key->src_port = loaded_data->key->src_port;
    nf_key->dst_port = loaded_data->key->dst_port;

    nf_data_t *nf_data = new_nf->data;
    nf_data->first_sys = current_time;
    nf_data->last_sys  = current_time;
    nf_data->tcp_flags = loaded_data->tcp_flags;
    nf_data->tos = loaded_data->tos;
    nf_data->dOctets = loaded_data->dOctets;
    nf_data->dPkts = 1;

    nf_insert(cache, new_nf);
}

void update_netflow(nf_t *nf_to_update, nf_data_t *tmp_data, uint64_t current_time)
{
    nf_to_update->data->last_sys = current_time;
    nf_to_update->data->tcp_flags |= tmp_data->tcp_flags;  // has effect only in case of TCP packets
    nf_to_update->data->dOctets += tmp_data->dOctets;
    nf_to_update->data->dPkts++;
}

// Exports remaining netflows in cache and dispose the cache 
void export_remaining_nfs(nf_cache_t *cache, args_t *args, uint64_t sysuptime, uint64_t current_time)
{
    log_netflow_info("\nExport of remaining netflows in cache:\n");
    nf_t *cur_nf = cache->last;
    nf_t *prev_nf;
    while (cur_nf != NULL)
    {
        prev_nf = cur_nf->prev;
        nf_export(cache, cur_nf, args, sysuptime, current_time);
        cur_nf = prev_nf;
    }
    free(cache);
}

void process_pcap_file(pcap_t *pcap_file, args_t *args)
{
    nf_cache_t *cache = nf_cache_ctor();
    nf_cache_init(cache);

    uint64_t current_time;
    uint64_t sysuptime = 0;     // Capture time of the first packet from pcap file
    nf_data_t *tmp_data = nf_data_ctor();

    const u_char *frame;
    struct pcap_pkthdr pcap_metadata;
    while ((frame = pcap_next(pcap_file, &pcap_metadata)) != NULL)
    {
        if (sysuptime == 0)
        {
            // Set sysuptime for capture time of the first packet
            sysuptime = convert_timeval2int(&pcap_metadata.ts);
        }
        current_time = convert_timeval2int(&pcap_metadata.ts);
        check_timers(cache, args, sysuptime, current_time);

        struct ether_header *eth_header = (struct ether_header *)frame;
        int ethernet_type = ntohs(eth_header->ether_type);
        if (ethernet_type != IPV4_PROTOCOL)
        {
            // Skip IPv6 packets
            continue;
        }

        // Process IPv4 packet and load its data
        struct ip *ip_header = (struct ip *)(frame + sizeof(struct ether_header));
        tmp_data->key->ip_protocol = ip_header->ip_p;
        tmp_data->key->src_ip = ip_header->ip_src.s_addr;
        tmp_data->key->dst_ip = ip_header->ip_dst.s_addr;
        tmp_data->dOctets = htons(ip_header->ip_len);
        tmp_data->tos = ip_header->ip_tos;
        tmp_data->tcp_flags = 0;

        // Resolve IP protocol
        int ip_protocol = ip_header->ip_p;
        if (ip_protocol == ICMP_PROTOCOL)
        {
            tmp_data->key->src_port = 0;
            tmp_data->key->dst_port = 0;
        }
        else if (ip_protocol == TCP_PROTOCOL || ip_protocol == UDP_PROTOCOL)
        {
            // Has port number
            int data_offset = sizeof(struct ether_header) + ip_header->ip_hl * WORDS2BYTES_SIZE;
            const u_char *data = frame + data_offset;
            if (ip_protocol == TCP_PROTOCOL)
            {
                struct tcphdr *tcp_header = (struct tcphdr *)data;
                tmp_data->key->src_port = tcp_header->th_sport;
                tmp_data->key->dst_port = tcp_header->th_dport;
                tmp_data->tcp_flags = tcp_header->th_flags;
            }
            else
            {
                struct udphdr *udp_header = (struct udphdr *)data;
                tmp_data->key->src_port = udp_header->uh_sport;
                tmp_data->key->dst_port = udp_header->uh_dport;
            }
        }
        else
        {
            // Skip other protocols than TCP, UDP or ICMP
            continue;
        }

        nf_t *existing_nf = get_nf(cache, tmp_data->key);
        if (existing_nf != NULL)
        {
            // NetFlow exists, update its data
            update_netflow(existing_nf, tmp_data, current_time);
            if (tmp_data->tcp_flags & TH_FIN || tmp_data->tcp_flags & TH_RST)
            {
                // TCP connection was ended, netflow can be exported
                log_netflow_info("Due to obtaining fin or reset flag:\n");
                nf_export(cache, existing_nf, args, sysuptime, current_time);
            }
        }
        else
        {
            // New Netflow has to be created
            if (cache->nf_cnt + 1 > args->max_cache_size)
            {
                // Cache is full, export oldest netflow
                log_netflow_info("Due to reaching maximum cache capacity:\n");
                nf_export(cache, cache->last, args, sysuptime, current_time);
            }
            create_new_netflow(cache, tmp_data, current_time);
            if (tmp_data->tcp_flags & TH_FIN || tmp_data->tcp_flags & TH_RST)
            {
                // TCP connection was ended, netflow can be exported
                log_netflow_info("Due to obtaining fin or reset flag:\n");
                nf_export(cache, cache->first, args, sysuptime, current_time);
            }

            // Log netflow inserted to cache
            static int inserted_cnt = 1;
            log_netflow_info("Inserted %3d. nf with: ", inserted_cnt++);
            log_netflow_id(tmp_data->key);
        }
    }   // while

    export_remaining_nfs(cache, args, sysuptime, current_time);
    cache = NULL;
    nf_data_dtor(tmp_data);
    tmp_data = NULL;
}

void cleanup_on_exit(args_t *args, pcap_t *pcap_file, bpf_program_t *packet_filter)
{
    pcap_freecode(packet_filter);
    free(packet_filter);
    
    pcap_close(pcap_file);

    close(args->socket_id);

    args_dtor(args);
}

int main(int argc, char **argv)
{
    // Treat safely system interrupt signal and exit program
    signal(SIGINT, handle_sigint);

    args_t *args = parse_arguments(argc, argv);
    args->socket_id = create_client_socket(args);

    pcap_t *pcap_file = pcap_open_file(args->pcap_file_name, args);
    bpf_program_t *packet_filter = set_display_filter(pcap_file, args, DISPLAY_FILTER);
    process_pcap_file(pcap_file, args); // Main program loop

    // Flow export is done, all allocated structures can be freed and opened files can be closed
    cleanup_on_exit(args, pcap_file, packet_filter);

    return 0;
}

/** End of file netflow_exporter.c **/
