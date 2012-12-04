/*
 *
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <unistd.h>

#include "netsnmp-pcap.h"


/* defaults options */
struct options options = {
    /* base_oid = */ NULL,
    /* config   = */ NULL,
    /* debug    = */ 0,
    /* detach   = */ 1,
    /* help     = */ 0,
    /* pidfile  = */ NULL,
    /* socket   = */ NULL,
    /* version  = */ 0,
};


/*
 * version()
 * -------
 */
static void
version(void) {
    puts(PROGRAM" v"VERSION);
    exit(EXIT_SUCCESS);
}


/*
 * usage()
 * -----
 */
static void
usage(void) {
    puts(
        "Usage:\n"
        "    netsnmp-pcap [--config /etc/snmp/pcap.conf] [--debug [n]]\n"
        "    netsnmp-pcap { --help | --version }\n"
        "\n"
        "Options:\n"
        "  Program options:\n"
        "    -B, --base-oid OID\n"
        "        Specify the base OID to server the table from. Default\n"
        "        to the same as bsnmpd-pcap, "DEFAULT_BASE_OID"\n"
        "\n"
        "    -c, --config path\n"
        "        Specify the path to the configuration file. Default to\n"
        "        "DEFAULT_CONFIG_PATH"\n"
        "\n"
        "    -d, --debug [level]\n"
        "        Enable debug mode.\n"
        "\n"
        "    -D, --detach\n"
        "        Tell the program to detach itself from the terminal and\n"
        "        become a daemon. Use --nodetach to prevent this.\n"
        "\n"
        "    -p, --pidfile path\n"
        "        Specify the path to a file to write the PID of the daemon.\n"
        "\n"
        "    -x, --socket address\n"
        "        Specify an address to use as AgentX socket. See the manual\n"
        "        page of snmpd, section \"LISTENING ADDRESSES\".\n"
        "\n"
        "  Help options:\n"
        "    -h, --help\n"
        "        Print a short usage description, then exit.\n"
        "\n"
        "    -V, --version\n"
        "        Print the program name and version, then exit.\n"
    );
    exit(EXIT_SUCCESS);
}


/*
 * main()
 * ----
 */
int
main(int argc, char **argv) {
    int optind = 0;

    /* options definition */
    const char short_options[] = "B:c:d::Dhp:Vx:";
    static struct option long_options[] = {
        { "help",       no_argument,        &options.help, 1 },
        { "usage",      no_argument,        &options.help, 1 },
        { "version",    no_argument,        &options.version, 1 },
        { "debug",      optional_argument,  NULL, 'd' },
        { "detach",     no_argument,        &options.detach, 1 },
        { "daemon",     no_argument,        &options.detach, 1 },
        { "nodetach",   no_argument,        &options.detach, 0 },
        { "nodaemon",   no_argument,        &options.detach, 0 },
        { "base-oid",   required_argument,  NULL, 'B' },
        { "config",     required_argument,  NULL, 'c' },
        { "pidfile",    required_argument,  NULL, 'p' },
        { "socket",     required_argument,  NULL, 'x' },
        { NULL,         0,                  NULL, 0 }
    };

    /* parse options */
    while (1) {
        int opt = getopt_long(argc, argv, short_options, long_options, &optind);
        if (opt == -1)
            break;

        switch (opt) {
            case 'B': /* --base-oid */
                options.base_oid = strdup(optarg);
                break;

            case 'c': /* --config */
                options.config = strdup(optarg);
                break;

            case 'd': /* --debug */
                if (optarg != NULL)
                    options.debug = atoi(optarg);
                else
                    options.debug++;
                break;

            case 'D': /* --detach */
                options.detach = 1;
                break;

            case 'h': /* --help */
                options.help = 1;
                break;

            case 'p': /* --pidfile */
                options.config = strdup(optarg);
                break;

            case 'x': /* --socket */
                options.socket = strdup(optarg);
                break;

            case 'V': /* --version */
                options.version = 1;
                break;

            default:
                break;
        }
    }

    /* handle --help and --version */
    if (options.help)    usage();
    if (options.version) version();

    /* defaults options */
    if (options.base_oid == NULL)
        options.base_oid = DEFAULT_BASE_OID;

    if (options.config == NULL)
        options.config = DEFAULT_CONFIG_PATH;

    /* become a daemon */
    if (options.detach) {

        /* write PID file */
        if (options.pidfile != NULL && strlen(options.pidfile) > 0) {
            FILE *fh = fopen(options.pidfile, "w");

            if (fh == NULL) {
                fprintf(stderr, PROGRAM ": can't write file '%s': %s\n",
                    options.pidfile, strerror(errno));
                exit(EXIT_FAILURE);
            }

            fprintf(fh, "%d", getpid());
            fclose(fh);
        }

        /* detach from the terminal */
        if (daemon(0, 0) != 0) {
            perror(PROGRAM ": failed to detach from the terminal");
            exit(EXIT_FAILURE);
        }
    }

    /* configure syslog */
    openlog(PROGRAM, LOG_NDELAY|LOG_PID|LOG_PERROR, LOG_DAEMON);
    syslog(LOG_INFO, PROGRAM " v" VERSION " starting");

    /* run the main program */
    netsnmp_pcap_run();

    return(EXIT_SUCCESS);
}


