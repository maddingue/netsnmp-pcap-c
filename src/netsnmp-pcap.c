#include <libev/ev.h>

#include "netsnmp-pcap.h"
#include "bsnmp-snmpmod-listmgmt.h"


void
netsnmp_pcap_run(void) {
    struct event_base  *ev_base;

    /* create the libevent event base */
    ev_base = event_base_new();

    /* parse the config file and create the monitors */
    monitor_parse_config(options.config, ev_base);

    /* start libevent dispatch loop */
    event_base_dispatch(ev_base);
}

