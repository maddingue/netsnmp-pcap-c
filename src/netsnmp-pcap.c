/*
 * netsnmp-pcap :: netsnmp-pcap.c
 * ------------------------------
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>

#include "netsnmp-pcap.h"
#include "bsnmp-snmpmod-listmgmt.h"

/*
 * prototypes
 */
static void nsp_exporter_start(struct event_base *ev_base);
static void nsp_exporter_do(evutil_socket_t fd, short what, void *arg);



/*
 * netsnmp_pcap_run()
 * ----------------
 * initialize and start the different components
 */
void
netsnmp_pcap_run(void) {
    struct event_base  *ev_base;

    /* create the libevent event base */
    ev_base = event_base_new();

    /* parse the config file and create the monitors */
    monitor_parse_config(options.config, ev_base);

    /* initialize the stats exporter */
    nsp_exporter_start(ev_base);

    /* start libevent dispatch loop */
    event_base_dispatch(ev_base);
}


/*
 * nsp_exporter_start()
 * ------------------
 * set up a timer watcher to regularly "export" the data collected
 * by the pcap monitors
 */
static void
nsp_exporter_start(struct event_base *ev_base) {
    struct event    *timer_watcher;
    struct timeval  *interval;

    if (options.debug >= 1)
        fprintf(stderr, "nsp_exporter_start\n");

    /* set the timer interval */
    interval = calloc(1, sizeof(struct timeval));
    if (interval == NULL) {
        syslog(_LOGERR_"couldn't allocate memory for a struct timeval");
        exit(EXIT_FAILURE);
    }
    interval->tv_sec = options.interval;

    /* create and activate the timer watcher */
    timer_watcher = event_new(ev_base, -1, EV_PERSIST, nsp_exporter_do, NULL);
    if (timer_watcher == NULL) {
        syslog(_LOGERR_"couldn't create the timer watcher to export the "
            "statistics");
        exit(EXIT_FAILURE);
    }

    if (event_add(timer_watcher, interval) < 0) {
        syslog(_LOGERR_"couldn't activate the timer watcher to export the "
            "statistics");
        exit(EXIT_FAILURE);
    }
}


/*
 * nsp_exporter_do()
 * ---------------
 * do the actual job of exporting the data collected by the pcap monitors,
 * that is, dump them as JSON in a file
 */
static void
nsp_exporter_do(evutil_socket_t fd, short what, void *arg) {
    struct monitor  *mon;
    FILE*   file = NULL;

    if (options.debug >= 2)
        fprintf(stderr, "nsp_exporter_start\n");

    /* if a dump path was provided, open it */
    if (options.dump_file) {
        if ((file = fopen(options.dump_file, "w")) == NULL) {
            syslog(_LOGERR_"couldn't open file '%s': %s", options.dump_file,
                strerror(errno));
            exit(EXIT_FAILURE);
        }

        fprintf(file, "[\n");
    }

    TAILQ_FOREACH(mon, &monitors, link) {
        /* write the stats to the file */
        if (file) {
            fprintf(file, 
                "  { \"pcapIndex\":%d, \"pcapDescr\":\"%s\","
                " \"pcapDevice\":\"%s\", \"pcapFilter\":\"%s\","
                " \"pcapOctets\":%lu, \"pcapPackets\":%lu }",
                mon->index, mon->description, mon->device,
                mon->filter, mon->seen_octets, mon->seen_packets
            );

            /* JSON is picky about trailing commas */
            if (TAILQ_NEXT(mon, link) == NULL)
                fputs("\n", file);
            else
                fputs(",\n", file);
        }
    }

    if (file) {
        fprintf(file, "]\n");
        fclose(file);
    }
}


