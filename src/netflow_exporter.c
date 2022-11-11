/**
 * @file    netflow_exporter.c
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#include "netflow_exporter.h"

// Used cmds:
// cd ~/Desktop/ISA_project
// make
// 1.1) ./flow -c 127.0.0.1:2055 -f /home/daviddrtil/Desktop/ISA_project/pcap_files/icmp.pcap
// 1.2) ./flow -a 30 -i 8 -c www.google.com:5524 -f /home/daviddrtil/Desktop/ISA/captured_packets/icmp_test.pcap
// 2)   ./flow -a 30 -i 8 -c www.google.com:5524 -f /home/daviddrtil/Desktop/ISA/captured_packets/active_inactive_test.pcap

// Debugger arguments:
// "-c", "192.168.0.1:2055", "<", "${workspaceFolder}/../captured_packets/icmp_test.pcap"
// "-c", "192.168.0.1:2055", "-f", "${workspaceFolder}/../captured_packets/icmp_test.pcap"


// Testing:
// 1) Capture packets:
//    sudo tcpdump -n -nn -N -s 0 -i enp0s3 -w nf_test.pcap
// 2) Run collector server / socket:
//    nfcapd -D -T all -l . -I any -S 2 -p 20550
// 3) Check if its running:
//    netstat -n --udp --listen
// 4) Export nf to collector (it generates nf after 5 minutes):
//    ./flow -a 30 -i 8 -c 127.0.0.1:20550 -f /home/daviddrtil/Desktop/ISA/nf_test.pcap
// 5) Generated file try view via nfdump:
//    nfdump -r nfcapd.current.28664
//    or
//    nfdump -I -r nfcapd.current.28664
// *6) Compare with reference output:
//    sudo softflowd -v 5 -n 127.0.0.1:2055 -r ./nf_test.pcap

// Domik's anal testing: (flow analyzer)
// 1) Poslani flows na collector:
// cd ~/Downloads/isa_domik/
// nfcapd -D -T all -l . -I any -S 2 -p 20550
// ./flow -a 30 -i 8 -c 127.0.0.1:20550 -f ./files/tcp-fin.pcap                 (nebo ./files/icmp-timeout.pcap)
// sudo softflowd -v 5 -n 127.0.0.1:20550 -r ./files/tcp-fin.pcap               (nebo ./files/icmp-timeout.pcap)
// 
// 2) Vypsani vypisu:
// cd ~/Downloads/isa_domik/2022/11/09/16/
// nfdump -r nfcapd.202211091624

// Kill collector server:
// fuser -n udp -k 20550


// current:
// ~/Desktop/ISA_project/flow -c 0.0.0.0:2055 -f /home/daviddrtil/Desktop/ISA_project/pcap_files/icmp.pcap
// ~/Desktop/isa_domik/flow -c 0.0.0.0:2055 -f /home/daviddrtil/Desktop/ISA_project/pcap_files/icmp.pcap
// sudo softflowd -v 5 -n 0.0.0.0:2055 -r /home/daviddrtil/Desktop/ISA_project/pcap_files/icmp.pcap

//todo add to documentation: https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html

void handle_sigint(int sig)
{
    printf("\nProccess terminated. Caught signal %d (ctrl + c).\n", sig);
    exit(PROCESS_ABORTED);
}

int create_client_socket(args_t *args)
{
    int socket_id = socket(AF_INET, SOCK_DGRAM, 0); // todo try with IPPROTO_UDP
    if (socket_id == 0)
    {
        fprintf(stderr, "Failed to create a socket with collector address.\n");
        exit(SOCKET_FUNCTION_FAILED);
    }

    if (connect(socket_id, (struct sockaddr *)&args->collector_addr, sizeof(args->collector_addr)) == -1)
    {
        fprintf(stderr, "Failed connect to server with socket_connect().\n");
        exit(SOCKET_FUNCTION_FAILED);
    }

    return socket_id;
}

pcap_t *pcap_open_file(char *pcap_file_name)
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
        exit(PCAP_FUNCTION_FAILED);
    }
    return pcap_file;
}

bpf_program_t *set_display_filter(pcap_t *pcap_file, const char *display_filter_str)
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
        exit(PCAP_FUNCTION_FAILED);
    }

    // Set the filter of packets
    int pcap_setfilter_error = pcap_setfilter(pcap_file, packet_filter);
    if (pcap_setfilter_error != 0)
    {
        char *setfilter_error_message = pcap_geterr(pcap_file);
        fprintf(stderr, "Pcap_setfilter failed to set filter \'%s\' with error code %d.\n", display_filter_str, pcap_setfilter_error);
        fprintf(stderr, "Error message: \'%s\'\n", setfilter_error_message);
        exit(PCAP_FUNCTION_FAILED);
    }
    return packet_filter;
}

// todo pravdepodobne to nebude potreba
void get_timestamp(struct pcap_pkthdr *pcap_header, char *timestamp_buffer)
{
    struct timeval *tv = &pcap_header->ts;
    struct tm *gt = localtime(&tv->tv_sec);
    int ms = (tv->tv_usec) / 1000;
    int offset = gt->tm_gmtoff / 60;

    // Change sign of offset (zone)
    char sign = '+';
    if(offset < 0)
    {
        sign = '-';
        offset = -offset;
    }

    // Load string with timestamp
    char date[DATE_LENGHT];
    strftime(date, DATE_LENGHT, "%Y-%m-%dT%H:%M:%S", gt);
    sprintf(timestamp_buffer, "%s.%03d%c%02d:%02d", date, ms, sign, offset / 60, offset % 60);
}

void get_ipv4_address(uint32_t ip_address_number, char *ip_address_buffer)
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

uint64_t convert_timeval2int(timeval_t *time)
{
    return time->tv_sec * MIKROSECONDS + time->tv_usec;
}

void send_netflow(int socket_id, uint8_t *data, int flags)
{
    int send_status = send(socket_id, data, NETFLOW_DATAGRAM_V5_SIZE, flags);
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

// Parse to netflow v5 format
void nf_export(nf_cache_t *cache, nf_t *nf_to_export, args_t *args, uint64_t sysuptime, uint64_t current_time)
{
    // Neat print - DEBUG only! // todo smazat
    char src_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
    get_ipv4_address(nf_to_export->data->key->src_ip, src_ip);
    char dst_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
    get_ipv4_address(nf_to_export->data->key->dst_ip, dst_ip);
    int src_port = nf_to_export->data->key->src_port;
    int dst_port = nf_to_export->data->key->dst_port;
    printf("Exported nf with: %s:%d -> %s:%d.\n", src_ip, src_port, dst_ip, dst_port);

    static int exported_flows = 0;
    uint8_t compressed_datagram[NETFLOW_DATAGRAM_V5_SIZE];
    netflow_datagram_v5_t *nf_datagram = (netflow_datagram_v5_t *)compressed_datagram;

    nf_data_t *nf_data = nf_to_export->data;
    uint64_t start_netflow_time = nf_data->first_sys - sysuptime;
    uint64_t end_netflow_time   = nf_data->last_sys - sysuptime;

    // Fill out header informations
    nf_datagram->version = htons(5);
    nf_datagram->count = htons(1);
    nf_datagram->SysUptime = htonl(sysuptime / MILISECONDS);
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

    send_netflow(args->socket_id, compressed_datagram, nf_data->tcp_flags);
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
            continue;
        }

        if (active_diff > args->active_interval || inactive_diff > args->inactive_interval)
        {
            // Neat print - DEBUG only! // todo smazat
            int ip_protocol = tmp_nf->data->key->ip_protocol;
            if (ip_protocol == ICMP_PROTOCOL)
                printf("ICMP:");
            else if (ip_protocol == TCP_PROTOCOL)
                printf("TCP:");
            else if (ip_protocol == UDP_PROTOCOL)
                printf("UDP:");

            if (active_diff > args->active_interval)
                printf("Active\n");
            else
                printf("Inactive\n");

            // Export outdated netflow
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
    uint64_t sysuptime = 0;
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
        bool tcp_fin = false;
        bool tcp_reset = false;

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
                tmp_data->key->src_port = tcp_header->th_sport;     // todo nema tu byt jiny byte order? ntohs()?
                tmp_data->key->dst_port = tcp_header->th_dport;
                tmp_data->tcp_flags = tcp_header->th_flags;
                tcp_fin = (bool)tcp_header->fin;
                tcp_reset = (bool)tcp_header->rst;
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
            if (tcp_fin || tcp_reset)
            {
                // TCP connection was ended, netflow can be exported
                nf_export(cache, existing_nf, args, sysuptime, current_time);
            }
        }
        else
        {
            // New Netflow has to be created
            if (cache->nf_cnt + 1 > args->flow_cache_size)
            {
                // Cache is full, export oldest netflow
                nf_export(cache, cache->last, args, sysuptime, current_time);
            }
            create_new_netflow(cache, tmp_data, current_time);

            // todo potom smazat!
            char src_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
            get_ipv4_address(tmp_data->key->src_ip, src_ip);
            char dst_ip[IPV4_ADDRESS_LENGHT] = {'\0'};
            get_ipv4_address(tmp_data->key->dst_ip, dst_ip);
            int src_port = tmp_data->key->src_port;
            int dst_port = tmp_data->key->dst_port;
            printf("Inserted nf with: %s:%d -> %s:%d.\n", src_ip, src_port, dst_ip, dst_port);
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

    pcap_t *pcap_file = pcap_open_file(args->pcap_file_name);
    bpf_program_t *packet_filter = set_display_filter(pcap_file, DISPLAY_FILTER);
    process_pcap_file(pcap_file, args); // Main program loop

    // Flow export is done, all allocated structures can be freed and opened files can be closed
    cleanup_on_exit(args, pcap_file, packet_filter);

    return 0;
}

/** End of file netflow_exporter.c **/
