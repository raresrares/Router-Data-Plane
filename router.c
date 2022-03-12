#include <queue.h>
#include "skel.h"

struct route_table_entry* routeTable;
long routeTableLength;

struct arp_entry* arpTable;
int arpTableLength;

queue icmpQ;
int icmpQLength;

int initRouteTable () {
	routeTable = (struct route_table_entry*) calloc (65000, sizeof(struct route_table_entry));
	routeTableLength = 65000;

	return routeTable != NULL;
}
void processRouteTable (char * pathToFile) {
	if (!initRouteTable()) fprintf(stderr, "processRouteTable failed!\n");

	FILE *f;
	char buffer[1000];
	f = fopen(pathToFile, "r");

	int i = 0;
	while (fgets(buffer, 1000, f)) {
		struct route_table_entry entry;

		char* p = strtok (buffer, " \n");
		
		struct in_addr prefix; 
		inet_aton(p, &prefix);
		memcpy(&(entry.prefix), &(prefix.s_addr), sizeof(uint32_t));

		p = strtok (NULL, " \n");

		struct in_addr nextHop; 
		inet_aton(p, &nextHop);
		memcpy(&(entry.next_hop), &(nextHop.s_addr), sizeof(uint32_t));
		
		p = strtok (NULL, " \n");

		struct in_addr mask; 
		inet_aton(p, &mask);
		memcpy(&(entry.mask), &(mask.s_addr), sizeof(uint32_t));
		
		p = strtok (NULL, " \n");

		int interface;
		interface = atoi(p);
		memcpy(&(entry.interface), &(interface), sizeof(int));
		
		p = strtok (NULL, " \n");

		memcpy (routeTable + i, &entry, sizeof(struct route_table_entry));

		i++;
	}
	
	routeTableLength = i;

	fclose(f);
}
void printtable () {
	for (int i = 0; i < routeTableLength; i++) {
		struct in_addr aux;

		aux.s_addr = routeTable[i].prefix;
		fprintf(stderr, "%s\n", inet_ntoa(aux));

		aux.s_addr = routeTable[i].next_hop;
		fprintf(stderr, "%s ", inet_ntoa(aux));
		
		aux.s_addr = routeTable[i].mask;
		fprintf(stderr, "%s ", inet_ntoa(aux));
		
		fprintf(stderr, "%d\n", routeTable[i].interface);
	}
}
struct route_table_entry* getRouteTableEntry(uint32_t ip) {
	for (int i = 0; i < routeTableLength; i++)
		if ((ip & routeTable[i].mask) == routeTable[i].prefix)
			return routeTable + i;

	return NULL;
}


int initArpTable() {
	arpTable = (struct arp_entry *) calloc(50, sizeof(struct arp_entry));
	arpTableLength = 0;

	return arpTable != NULL;
}
void addArpEntry(uint32_t ip, uint8_t* mac) {
	if (getArpEntry(ip) != NULL)
		return;

	arpTable[arpTableLength].ip = ip;
	memcpy(arpTable[arpTableLength].mac, mac, sizeof(uint8_t) * ETH_ALEN);

	arpTableLength++;
}
struct arp_entry* getArpEntry(uint32_t ip) {
	for (int i = 0; i < arpTableLength; i++) {
		if (arpTable[i].ip == ip)
			return &arpTable[i];
	}
    return NULL;
}
void printArpTable() {
	fprintf(stderr, "IP-------------%d------------MAC\n", arpTableLength);
	for (int i = 0; i < arpTableLength; i++) {
		struct in_addr ip;
		ip.s_addr = arpTable[i].ip;

		fprintf(stderr, "%s     %x:%x:%x:%x:%x:%x\n", inet_ntoa(ip),
		arpTable[i].mac[0], arpTable[i].mac[1], arpTable[i].mac[2],
		arpTable[i].mac[3], arpTable[i].mac[4], arpTable[i].mac[5]);
	}
	fprintf(stderr, "---------------%d---------------\n", arpTableLength);
}

void processICMP(packet p) {
	fprintf(stderr, "Received ICMP!\n");
	
	struct ether_header *ether = (struct ether_header *)(p.payload);
	struct iphdr *ip = (struct iphdr *)(p.payload + sizeof(struct ether_header));
	struct icmphdr* icmp = parse_icmp(p.payload);

	struct route_table_entry *routeTableEntry = getRouteTableEntry(ip->daddr);

	uint8_t routerMAC[ETH_ALEN];
	get_interface_mac(p.interface, routerMAC);

	struct in_addr routerIP;
	inet_aton(get_interface_ip(p.interface), &routerIP);

	if (icmp->type == ICMP_ECHO) {
		if (ip->daddr == routerIP.s_addr) {
			struct in_addr interfaceIP;
			inet_aton(get_interface_ip(routeTableEntry->interface), &interfaceIP);

			send_icmp(ip->saddr, interfaceIP.s_addr, routerMAC, ether->ether_shost, ICMP_ECHOREPLY, 0,routeTableEntry->interface, icmp->un.echo.id, icmp->un.echo.sequence);
		}
	}
}

void processARP(packet p) {
	struct arp_header* arp = parse_arp(p.payload);

	if (!arp) return;

	if (ntohs(arp->op) == 1) { /* If the packet is an ARP Request */
		processARPRequest(p);
	} else if (ntohs(arp->op) == 2) { /* If the packet is an ARP Reply */
		processARPReply(p);
	}
}

void processARPRequest(packet p) {
	struct arp_header* arp = parse_arp(p.payload);

	struct in_addr routerIP;
	inet_aton(get_interface_ip(p.interface), &routerIP);

	if (arp->tpa == routerIP.s_addr) {
		fprintf(stderr, "Received ARP Request for the router!\n");

		struct ether_header ether;

		uint8_t routerMAC[ETH_ALEN];
		get_interface_mac(p.interface, routerMAC);

		build_ethhdr(&ether, routerMAC, arp->sha, htons(ETHERTYPE_ARP));
		send_arp(arp->spa, arp->tpa, &ether, p.interface, htons(ARPOP_REPLY));
	}
}

void processARPReply(packet p) {
	struct arp_header* arpReply = parse_arp(p.payload);

	fprintf(stderr, "Received ARP Reply!\n");
	if (!getArpEntry(arpReply->spa)) {
		addArpEntry(arpReply->spa, arpReply->sha);
	}

	while (!queue_empty(icmpQ)) {
		packet icmpPacket;
		memcpy(&icmpPacket, queue_deq(icmpQ), sizeof(packet));

		struct ether_header *ether = (struct ether_header *)(icmpPacket.payload);
		struct ether_header etherToSend;

		uint8_t routerMAC[ETH_ALEN];
		get_interface_mac(icmpPacket.interface, routerMAC);

		build_ethhdr(&etherToSend, routerMAC, ether->ether_shost, htons(ETHERTYPE_ARP));

		send_packet(p.interface, &icmpPacket);
	}
}

void processDifferent(packet p) {
	struct iphdr *ip = (struct iphdr *)(p.payload + sizeof(struct ether_header));

	struct route_table_entry* entry = getRouteTableEntry(ip->daddr);

	if (!getArpEntry(ip->daddr)) {
		fprintf(stderr, "Did not found MAC address. Sending ARP Request! diff\n");

		struct ether_header ether;
		
		uint8_t broadcast[ETH_ALEN];
		hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast);

		uint8_t routerMAC[ETH_ALEN];
		get_interface_mac(entry->interface, routerMAC);
		struct in_addr routerIP;
		inet_aton(get_interface_ip(entry->interface), &routerIP);

		build_ethhdr(&ether, routerMAC, broadcast, htons(0x0806));
		send_arp(ip->daddr, routerIP.s_addr, &ether, entry->interface, htons(ARPOP_REQUEST));
	}
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF , 0);
	
	packet m;
	int rc;
	init(argc - 2, argv + 2);

	processRouteTable(*(argv + 1));

	icmpQ = queue_create();

	if (!initArpTable()) fprintf(stderr, "processRouteTable failed!\n");

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct arp_header* arp = parse_arp(m.payload);
		struct icmphdr * icmp = parse_icmp(m.payload);

		struct ether_header *ether = (struct ether_header *) (m.payload);
		struct iphdr *ip = (struct iphdr *) (m.payload + sizeof(struct ether_header));

		if (icmp) {
			processICMP(m);
			continue;
		}

		if (arp) {
			processARP(m);
			continue;
		}

		if (ip->ttl <= 1) {
			uint8_t routerMAC[ETH_ALEN];
			get_interface_mac(m.interface, routerMAC);

			send_icmp_error(ip->saddr, ip->daddr, routerMAC, ether->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);

			continue;
		}

		struct route_table_entry *routeTableEntry = getRouteTableEntry(ip->daddr);
		if (!routeTableEntry) {
			uint8_t routerMAC[ETH_ALEN];
			get_interface_mac(m.interface, routerMAC);

			struct in_addr routerIP;
			inet_aton(get_interface_ip(m.interface), &routerIP);

			send_icmp_error(ip->saddr, routerIP.s_addr, routerMAC, ether->ether_shost, ICMP_DEST_UNREACH, 0, m.interface);

			continue;
		}

		uint16_t oldChksm = ip->check;

		ip->check = 0;
		ip->check = ip_checksum((void *)ip, sizeof(struct iphdr));

		if (oldChksm != ip->check) continue;

		ip->ttl--;
		ip->check = 0;
		ip->check = ip_checksum((void *)ip, sizeof(struct iphdr));

		struct arp_entry* arpEntry = getArpEntry(routeTableEntry->next_hop);

		if (!arpEntry) {
			packet *toEnQ = (packet *) calloc(1, sizeof(packet));
			memcpy(toEnQ, &m, sizeof(packet));
			queue_enq(icmpQ, toEnQ);

			struct ether_header ether;
			uint8_t broadcast[ETH_ALEN];
			hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast);

			uint8_t mac[ETH_ALEN];
			get_interface_mac(routeTableEntry->interface, mac);

			struct in_addr routerIP;
			inet_aton(get_interface_ip(routeTableEntry->interface), &routerIP);

			build_ethhdr(&ether, mac, broadcast, htons(ETHERTYPE_ARP));
			send_arp(routeTableEntry->next_hop, routerIP.s_addr, &ether, routeTableEntry->interface, htons(ARPOP_REQUEST));
		} else {
			uint8_t mac[ETH_ALEN];
			get_interface_mac(routeTableEntry->interface, mac);

			memcpy(ether->ether_dhost, arpEntry->mac, ETH_ALEN * sizeof(uint8_t));
			memcpy(ether->ether_shost, mac, ETH_ALEN * sizeof(uint8_t));

			send_packet(routeTableEntry->interface, &m);
		}
	}
}