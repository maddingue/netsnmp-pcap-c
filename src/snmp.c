/*
 * netsnmp-pcap :: snmp.c
 * ----------------------
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syslog.h>

#include "netsnmp-pcap.h"


/*
 * prototypes
 */
static void init_pcap(void);
static void nsp_agent_check(evutil_socket_t fd, short what, void *arg);
static int  nsp_tree_handler(netsnmp_mib_handler*,
    netsnmp_handler_registration*, netsnmp_agent_request_info*,
    netsnmp_request_info*);



/*
 * nsp_agent_init()
 * --------------
 * initialize the AgentX sub-agent
 */
void
nsp_agent_init(void) {
    /* configure netsnmp logging */
    if (options.debug) {
        fprintf(stderr, "nsp_agent_init: initialize the AgentX sub-agent\n");
        snmp_enable_stderrlog();
    }
    else {
        snmp_enable_syslog_ident(PROGRAM, SYSLOG_FACILITY);
    }

    /* declare ourself as an AgentX sub-agent */
    netsnmp_enable_subagent();

    /* set the AgentX socket, if specified */
    if (options.socket != NULL)
        netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
            NETSNMP_DS_AGENT_X_SOCKET, options.socket);

    /* initialize the agent library */
    init_agent(AGENT_NAME);
    init_pcap();
    init_snmp(AGENT_NAME);

    if (options.debug < 2)
        snmp_disable_log();

    /* restore our syslog options */
    openlog(PROGRAM, SYSLOG_OPTIONS, SYSLOG_FACILITY);
}


/*
 * init_pcap()
 * ---------
 * register our handler for serving the OID tree
 */
static void
init_pcap(void) {
    netsnmp_mib_handler             *handler;
    netsnmp_handler_registration    *reg;
    oid     root[MAX_OID_LEN];
    size_t  rootlen = MAX_OID_LEN;
    int     res;

    if (options.debug)
        fprintf(stderr, "init_pcap: register on %s\n", options.base_oid);

    /* parse the given base OID */
    if (!snmp_parse_oid(options.base_oid, root, &rootlen)) {
        if (!read_objid(options.base_oid, root, &rootlen)) {
            syslog(_LOGERR_"couldn't parse '%s' as an OID", options.base_oid);
            exit(EXIT_FAILURE);
        }
    }

    /* create the OID tree handler callback */
    handler = netsnmp_create_handler(AGENT_NAME, nsp_tree_handler);
    if (handler == NULL) {
        syslog(_LOGERR_"couldn't create the handler callback");
        exit(EXIT_FAILURE);
    }

    /* create a handler registration thingy (yay Net-SNMP) */
    reg = netsnmp_handler_registration_create(AGENT_NAME, handler,
        root, rootlen, HANDLER_CAN_RONLY);
    if (reg == NULL) {
        syslog(_LOGERR_"couldn't create the handler registration");
        exit(EXIT_FAILURE);
    }

    /* actually register the OID tree handler */
    res = netsnmp_register_handler(reg);
    if (res != MIB_REGISTERED_OK) {
        syslog(_LOGERR_"couldn't register the handler (code %d)", res);
        exit(EXIT_FAILURE);
    }
}


/*
 * nsp_agent_start()
 * ---------------
 * create the I/O watchers over netsnmpagent's file descriptors
 *
 * XXX: the watchers are currently not stored. this may need to
 *      be changed in the future.
 */
void
nsp_agent_start(struct event_base *ev_base) {
    struct event    *socket_watcher /*, *timer_watcher */;
    struct timeval  tv, ping_delay = { 30, 0 };
    fd_set  fdset;
    int     i, numfds = 0, block = 0;

    if (options.debug)
        fprintf(stderr, "nsp_agent_start: create the I/O and timer watchers\n");

    /* get the file descriptor of the AgentX socket */
    FD_ZERO(&fdset);
    snmp_select_info(&numfds, &fdset, &tv, &block);
    if (numfds) {
        for (i=0; i<numfds; i++) {
            if (FD_ISSET(i, &fdset)) {
                /* create and activate a libevent watcher associated with
                   the AgentX socket */
                socket_watcher = event_new(ev_base, i, EV_READ|EV_PERSIST,
                    nsp_agent_check, NULL);
                if (socket_watcher == NULL) {
                    syslog(_LOGERR_"couldn't create a watcher for the AgentX "
                        "socket");
                    exit(EXIT_FAILURE);
                }

                if (event_add(socket_watcher, &ping_delay) < 0) {
                    syslog(_LOGERR_"couldn't activate a watcher for the AgentX "
                        "socket");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    /* create and activate a timer watcher, to regularly check that we are
       still connected to the AgentX master */
    /* replaced by adding timeout in the I/O watchers; however the handler
       now gets called three times in a row, which is a bit stupid */
    /*
    timer_watcher = event_new(ev_base, -1, EV_PERSIST, nsp_agent_check, NULL);
    if (timer_watcher == NULL) {
        syslog(_LOGERR_"couldn't create the timer watcher to monitor the "
            "AgentX socket");
        exit(EXIT_FAILURE);
    }

    if (event_add(timer_watcher, &ping_delay) < 0) {
        syslog(_LOGERR_"couldn't activate the timer watcher to monitor the "
            "AgentX socket");
        exit(EXIT_FAILURE);
    }
    */

}


/*
 * nsp_agent_stop()
 * --------------
 */
void
nsp_agent_stop(void) {
    if (options.debug >= 1)
        fprintf(stderr, "nsp_agent_stop\n");

    snmp_shutdown(AGENT_NAME);
}


/*
 * nsp_agent_check()
 * ---------------
 * callback function invoked by libevent when there are incoming data in
 * the watched AgentX socket
 */
static void
nsp_agent_check(evutil_socket_t fd, short what, void *arg) {
    if (options.debug >= 3)
        fprintf(stderr, "nsp_agent_check\n");

    snmp_timeout();
    agent_check_and_process(0);
}


/*
 * nsp_tree_handler()
 * ----------------
 * callback invoked by netsnmpagent during agent_check_and_process()
 */
static int
nsp_tree_handler(
    netsnmp_mib_handler          *handler,
    netsnmp_handler_registration *reginfo,
    netsnmp_agent_request_info   *reqinfo,
    netsnmp_request_info         *requests)
{
    if (options.debug >= 3)
        fprintf(stderr, "nsp_tree_handler\n");

    /* TODO */

    return(0);
}

