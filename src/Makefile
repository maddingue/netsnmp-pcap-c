
SOURCES=main.c monitor.c netsnmp-pcap.c snmp.c

all: netsnmp-pcap

netsnmp-pcap: $(SOURCES)
	cc -Wall -levent_core -levent_extra -lpcap -lnetsnmpmibs -lnetsnmpagent -lnetsnmp $(SOURCES) -o netsnmp-pcap

