/*
 * netsnmp-pcap :: monitor.c
 * -------------------------
 * This file is heavily based on bsnmp-pcap.c
 *
 * Copyright (c) 2008, Stefan Walter <stef@memberwebs.com>
 * Copyright (c) 2012, Sebastien Aperghis-Tramoni <sebastien@aperghis.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 *     * Redistributions of source code must retain the above 
 *       copyright notice, this list of conditions and the 
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the 
 *       above copyright notice, this list of conditions and 
 *       the following disclaimer in the documentation and/or 
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be 
 *       used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
 * DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <libev/ev.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/types.h>

#include "netsnmp-pcap.h"
#include "bsnmp-snmpmod-listmgmt.h"


#define ETHERNET_HEADER_LENGTH  14
#define SNAP_LENGTH             48
#define MAX_DEFINITIONS         64



/* list of monitors */
struct monitor_list monitors = TAILQ_HEAD_INITIALIZER(monitors);

/* number of monitors */
int monitor_count = 0;


/*
 * monitor_packet()
 * --------------
 * callback function for handling received packets, invoked by pcap_dispatch()
 */
static void
monitor_packet(u_char *arg, const struct pcap_pkthdr *header,
    const u_char *bytes) {
    struct monitor *mon = (struct monitor*)arg;

    /* skip short packets */
    if (header->len < ETHERNET_HEADER_LENGTH)
        return;

fprintf(stderr, "- monitor_packet: packet matching filter <%s>\n", mon->filter);
    mon->seen_octets  += header->len - ETHERNET_HEADER_LENGTH;
    mon->seen_packets += 1;
}


/*
 * monitor_io()
 * ----------
 * callback function invoked by libevent when there are incoming data in
 * the watched socket
 */
static void
monitor_io(evutil_socket_t fd, short what, void *arg) {
    struct monitor *mon = (struct monitor*)arg;
    int n;

    n = pcap_dispatch(mon->pcap, -1, monitor_packet, (u_char *)mon);

    if (n < 0) {
        syslog(_LOGERR_"pcap_dispatch: %s", pcap_geterr(mon->pcap));
        return;
    }
}


/*
 * monitor_free()
 * ------------
 * deallocate a monitor
 */
static void
monitor_free(struct monitor *mon) {
    if (mon != NULL)
        return;

    /* deallocate each field */
    if (mon->description != NULL)
        free(mon->description);

    if (mon->device != NULL)
        free(mon->device);

    if (mon->filter != NULL)
        free(mon->filter);

    if (mon->filter_valid)
        pcap_freecode(&mon->filter_bpf);

    if (mon->watcher != NULL) {
        event_del(mon->watcher);
        event_free(mon->watcher);
    }

    if (mon->pcap != NULL)
        pcap_close(mon->pcap);

    /* remove the monitor from the list */
    TAILQ_REMOVE(&monitors, mon, link);
    monitor_count--;

    /* deallocate the monitor structure */
    free(mon);
}


/*
 * monitor_new()
 * -----------
 * allocate and initialize a monitor from a monitor definition,
 * and associate it with a libevent watcher
 */
static struct monitor *
monitor_new(struct monitor_definition *mondef, struct event_base *ev_base) {
    char    errbuf[PCAP_ERRBUF_SIZE];
    struct  monitor *mon;
    int     fd;

    /* allocate memory for the monitor */
    mon = calloc(1, sizeof(struct monitor));
    if (mon == NULL) {
        syslog(_LOGERR_"couldn't allocate monitor: %s", strerror(errno));
        return(NULL);
    }

    /* insert it into the monitors list */
    mon->index = mondef->index;
    INSERT_OBJECT_INT(mon, &monitors);
    monitor_count++;

    /* populate the monitor fields */
    if (mondef->description != NULL)
        mon->description = mondef->description;

    if ((mondef->device != NULL) && (strlen(mondef->device) > 0))
        mon->device = mondef->device;
    else {
        mon->device = pcap_lookupdev(errbuf);
        if (mon->device == NULL) {
            syslog(_LOGWARN_"pcap_lookupdev: %s", errbuf);
            syslog(_LOGWARN_"trying with interface \"any\"");
            mon->device = "any";
        }
    }

    if (mondef->filter != NULL)
        mon->filter = mondef->filter;

    /* create the pcap handle */
    assert(mon->device);
    mon->pcap = pcap_open_live(mon->device, SNAP_LENGTH, 1, 100, errbuf);
    if (mon->pcap == NULL) {
        syslog(_LOGERR_"couldn't open monitor on %s: %s", mon->device, errbuf);
        monitor_free(mon);
        return(NULL);
    }

    /* if there's a filter.. */
    if ((mon->filter != NULL) && (strlen(mon->filter) > 0)) {
        /* compile it */
        if (pcap_compile(mon->pcap, &mon->filter_bpf, mon->filter, 1, 0) < 0) {
            syslog(_LOGERR_"couldn't compile monitor filter: %s",
                pcap_geterr(mon->pcap));
            monitor_free(mon);
            return(NULL);
        }

        mon->filter_valid = 1;

        /* associate it to the pcap handle */
        if (pcap_setfilter(mon->pcap, &mon->filter_bpf) < 0) {
            syslog(_LOGERR_"couldn't setup monitor filter: %s",
                pcap_geterr(mon->pcap));
            monitor_free(mon);
            return(NULL);
        }
    }

    /* set the pcap handle in non-block mode */
    if (pcap_setnonblock(mon->pcap, 1, errbuf) < 0) {
        syslog(_LOGERR_"couldn't set monitor in non-block mode: %s", errbuf);
        monitor_free(mon);
        return(NULL);
    }

    /* get a selectable file descriptor */
    fd = pcap_get_selectable_fd(mon->pcap);
    if (fd < 0) {
        syslog(_LOGERR_"couldn't get a selectable file descriptor: %s",
            pcap_geterr(mon->pcap));
        monitor_free(mon);
        return(NULL);
    }

    /* create and activate the libevent watcher associated with
       the pcap handle */
    mon->watcher = event_new(ev_base, fd, EV_READ|EV_PERSIST,
        monitor_io, (void *)mon);
    if (mon->watcher == NULL) {
        syslog(_LOGERR_"couldn't create a new watcher");
        monitor_free(mon);
        return(NULL);
    }

    if (event_add(mon->watcher, NULL) < 0) {
        syslog(_LOGERR_"couldn't activate watcher");
        monitor_free(mon);
        return(NULL);
    }

    return(mon);
}


/*
 * monitor_parse_config()
 * --------------------
 */
void
monitor_parse_config(const char *path, struct event_base *ev_base) {
    struct monitor_definition **defs;
    FILE        *fh;
    char        line[1025];
    char        *token, *suboid;
    uint32_t    index;
    int         i = 0;

    if ((fh = fopen(path, "r")) == NULL) {
        syslog(_LOGERR_"can't read file '%s': %s", path, strerror(errno));
        return;
    }

    defs = calloc(MAX_DEFINITIONS, sizeof(void*));

    while (fgets(line, 1024, fh)) {
        i++;
        if (line[0] == '#') continue;
        if (line[0] == '%') continue;
        if (!strstr(line, "pcap")) continue;

        /* extract the suboid name ("pcapDescr", "pcapDevice", "pcapFilter") */
        if ((suboid = strtok(line, ".")) == NULL) {
            syslog(_LOGERR_"parse error on line %d", i);
            continue;
        }

        /* extract the index */
        if ((token = strtok(NULL, " \t=")) == NULL) {
            syslog(_LOGERR_"parse error on line %d", i);
            continue;
        }
        index = atoi(token);

        /* extract the value */
        if ((token = strtok(NULL, "\"")) == NULL) {
            syslog(_LOGERR_"parse error on line %d", i);
            continue;
        }
        if ((token[0] == ' ') || (token[0] == '=')) {
            if ((token = strtok(NULL, "\"")) == NULL) {
                syslog(_LOGERR_"parse error on line %d", i);
                continue;
            }
        }

        /* allocate a monitor definition if needed */
        if (defs[index-1] == NULL)
            defs[index-1] = calloc(1, sizeof(struct monitor_definition));

        /* fill up the fields */
        defs[index-1]->index = index;

        if (strstr(suboid+4, "Descr") != NULL)
            defs[index-1]->description = strdup(token);

        if (strstr(suboid+4, "Device") != NULL)
            defs[index-1]->device = strdup(token);

        if (strstr(suboid+4, "Filter") != NULL)
            defs[index-1]->filter = strdup(token);

    }

    for (i=0; i<MAX_DEFINITIONS; i++) {
        if (defs[i] == NULL)
            continue;

        /* create the monitor from the given definition */
        monitor_new(defs[i], ev_base);

        /* deallocate the monitor definition */
        free(defs[i]);
    }

    free(defs);
}

