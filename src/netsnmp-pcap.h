#ifndef NETSNMP_PCAP_H
#define NETSNMP_PCAP_H

#include <event2/event.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>

#define PROGRAM "netsnmp-pcap"
#define VERSION "0.01"

#define DEFAULT_BASE_OID    ".1.3.6.1.4.1.12325.1.1112"
#define DEFAULT_CONFIG_PATH "/etc/snmp/pcap.conf"

#define _LOGERR_    LOG_ERR, PROGRAM ": error: "
#define _LOGWARN_   LOG_WARNING, PROGRAM ": warning: "


/* program options */
struct options {
    char    *base_oid;
    char    *config;
    int     debug;
    int     detach;
    int     help;
    char    *pidfile;
    char    *socket;
    int     version;
};

extern struct options   options;


/* monitor definition */
struct monitor_definition {
    uint32_t    index;
    char        *description;
    char        *device;
    char        *filter;
};

/* monitor */
struct monitor {
    /* the fields that will be served over SNMP */
    uint32_t                index;          /* pcap.2.1.0 */
    char                    *description;   /* pcap.2.1.1 */
    char                    *device;        /* pcap.2.1.2 */
    char                    *filter;        /* pcap.2.1.3 */
    uint64_t                seen_octets;    /* pcap.2.1.4 */
    uint64_t                seen_packets;   /* pcap.2.1.5 */

    /* private fields */
    TAILQ_ENTRY(monitor)    link;
    struct event            *watcher;
    pcap_t                  *pcap;
    struct bpf_program      filter_bpf;
    int                     filter_valid;
};

TAILQ_HEAD(monitor_list, monitor);

/* prototypes */
void monitor_parse_config(const char *path, struct event_base *ev_base);
void netsnmp_pcap_run(void);


#endif

