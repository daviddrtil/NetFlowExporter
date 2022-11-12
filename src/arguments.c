/**
 * @file    arguments.c
 * @brief   ISA - project
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-10-01
*/

#include "arguments.h"

void print_help()
{
    printf("NetFlow Exporter\n");
    printf("Generating and exporting NetFlow from captured network traffic.\n");
    printf("Usage: \n");
    printf("    ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
    printf("    ./flow [-h | --help]\n");
    printf("Arguments:\n");
    printf("    -f <file>                           File to analyze, in default state it's input from stdin.\n");
    printf("    -c <netflow_collector>[:<port>]     IP address or hostname of NetFlow collector (default: [127.0.0.1:2055]).\n");
    printf("    -a <active_timer>                   Interval in seconds after which active records are exported\n");
    printf("                                        to collector (default: [60 sec]).\n");
    printf("    -i <inactive_timer>                 Interval in seconds after which inactive records are exported\n");
    printf("                                        to collector (default: [10 sec]).\n");
    printf("    -m <count>                          Size of flow-cache in records. When maximal size is reached,\n");
    printf("                                        records from oldest flow are exported to the collector (default: 1024).\n");
    printf("Arguments can be arbitrarily combined.\n");
    printf("Help:\n");
    printf("    -h | --help                         Prints this help and exit program.\n\n");
}

void args_init(args_t *args)
{
    args->pcap_file_name = DEFAULT_PCAP_FILE;
    args->active_interval = DEFAULT_ACTIVE_TIMER;
    args->inactive_interval = DEFAULT_INACTIVE_TIMER;
    args->flow_cache_size = DEFAULT_CACHE_SIZE;
}

void args_dtor(args_t *args)
{
    if (strcmp(args->pcap_file_name, DEFAULT_PCAP_FILE) != 0)
    {
        free(args->pcap_file_name);
    }
    free(args);
}

int convert_string2int(char *number, const char *error_message)
{
    char *invalid_part;
    int converted_number = (int)strtol(number, &invalid_part, 10); 
    if (*invalid_part != '\0')
    {
        fprintf(stderr, "%sFailed to convert number \'%s\'.\n", error_message, number);
        exit(INVALID_ARGUMENT);
    }
    return converted_number;
}

void load_collector_address(args_t *args, char *arg_address, int port_number)
{
    struct hostent *translated_addr = gethostbyname(arg_address);
    if (translated_addr == NULL)
    {
        fprintf(stderr, "Failed to translate collector address [%s] by gethostbyname().\n",
                arg_address);
        exit(INVALID_ARGUMENT);
    }

    memset(&args->collector_addr, 0, sizeof(args->collector_addr));
    memcpy(&args->collector_addr.sin_addr, translated_addr->h_addr, translated_addr->h_length);
    args->collector_addr.sin_family = AF_INET;
    args->collector_addr.sin_port = htons(port_number);
}

args_t *parse_arguments(int argc, char **argv)
{
    if (argc == 2)
    {
        // Print Help
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
        {
            print_help();
            exit(EXIT_SUCCESS);
        }
    }

    // Create argument structure
    args_t *args = (args_t *)malloc(sizeof(struct args));
    if (args == NULL)
    {
        fprintf(stderr, "Allocation of struct args_t failed.\n");
        exit(INTERNAL_ERROR);
    }
    args_init(args);
    char *collector_addr = DEFAULT_COLLECTOR_ADDR;
    int port_number = DEFAULT_PORT_NUMBER;
    bool allocated_collector_addr = false;

    // Parse all arguments
    for (int i = 1; i < argc; i += 2)
    {
        if (!strcmp(argv[i], "-f"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -f is missing filename.\n");
                exit(INVALID_ARGUMENT);
            }
            args->pcap_file_name = (char *)malloc(strlen(argv[i+1]) + 1);
            if (args->pcap_file_name == NULL)
            {
                fprintf(stderr, "Allocation of pcap_file_name failed.\n");
                exit(INTERNAL_ERROR);
            }
            strcpy(args->pcap_file_name, argv[i+1]);
        }
        else if (!strcmp(argv[i], "-c"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -c is missing collector address.\n");
                exit(INVALID_ARGUMENT);
            }

            // parse ip_address and port
            collector_addr = (char *)malloc(strlen(argv[i+1]) + PORT_NUMBER_LENGHT + 1);
            if (collector_addr == NULL)
            {
                fprintf(stderr, "Allocation of collector_address failed.\n");
                exit(INTERNAL_ERROR);
            }
            allocated_collector_addr = true;

            char port_number_str[PORT_NUMBER_LENGHT];
            int j;
            for (j = 0; argv[i+1][j] != '\0'; j++)
            {
                if (argv[i+1][j] != ':')
                {
                    collector_addr[j] = argv[i+1][j];
                }
                else
                {
                    // Load custom port
                    int port_idx = 0;
                    for (int k = j + 1; argv[i+1][k] != '\0'; k++)
                    {
                        port_number_str[port_idx] = argv[i+1][k];
                        port_idx++;
                    }
                    port_number_str[port_idx] = '\0';   // end string
                    break;
                }
            }
            collector_addr[j] = '\0';    // end string

            if (port_number_str[0] != '\0' && strcmp(port_number_str, "2055") != 0)
            {
                port_number = convert_string2int(port_number_str, "Invalid argument -c, it has invalid port number.");
                if (port_number < 0 || port_number > 65535)
                {
                    fprintf(stderr, "Invalid value of port number '%d', it's out of range. Cannot be lower than 0 or bigger than 65535.\n", port_number);
                    exit(INVALID_ARGUMENT);
                }
            }
        }
        else if (!strcmp(argv[i], "-a"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -a is missing interval lenght.\n");
                exit(INVALID_ARGUMENT);
            }
            args->active_interval = convert_string2int(argv[i + 1], "Invalid argument -a, it has wrong number of interval in seconds.");
            args->active_interval *= MIKROSECONDS;
        }
        else if (!strcmp(argv[i], "-i"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -i is missing interval lenght.\n");
                exit(INVALID_ARGUMENT);
            }
            args->inactive_interval = convert_string2int(argv[i + 1], "Invalid argument -i, it has wrong number of interval in seconds.");
            args->inactive_interval *= MIKROSECONDS;
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            fprintf(stderr, "Invalid argument help. To print help, no other arguments cannot be set.\n");
            exit(INVALID_ARGUMENT);
        }
        else
        {
            fprintf(stderr, "Invalid argument \'%s\'.\n", argv[i]);
            exit(INVALID_ARGUMENT);
        }
    }

    load_collector_address(args, collector_addr, port_number);
    if (allocated_collector_addr)
    {
        free(collector_addr);
    }
    return args;
}

/** End of file arguments.c **/
