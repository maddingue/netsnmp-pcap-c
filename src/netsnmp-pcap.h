/*
 * netsnmp-pcap :: netsnmp-pcap.h
 * ------------------------------
 * This file uses portions of bsnmp-pcap.c
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

#ifndef NETSNMP_PCAP_H
#define NETSNMP_PCAP_H

#include <event2/event.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>

#define PROGRAM "netsnmp-pcap"
#define VERSION "0.01"

#define SYSLOG_OPTIONS      LOG_NDELAY|LOG_PID|LOG_PERROR
#define SYSLOG_FACILITY     LOG_DAEMON
#define AGENT_NAME          "pcap"

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
void nsp_agent_init(void);
void nsp_agent_start(struct event_base *ev_base);
void nsp_agent_stop(void);


#endif

