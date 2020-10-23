#pragma once
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // protocoale de nivel 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
// in concordanta cu POSIX.1-2001, POSIX.1-2008
#include <sys/select.h>
// ethheader
#include <net/ethernet.h>
// ether_header
#include <arpa/inet.h>
// icmphdr
#include <netinet/ip_icmp.h>
// arphdr
#include <net/if_arp.h>
#include <asm/byteorder.h>
//contine toate campurile pentru arp header
#include <netinet/if_ether.h>
#include "queue.h"

#define MAX_LEN 1600
#define ROUTER_NUM_INTERFACES 4

// avem doar 2 valori pentru fiecare bit dintr-o adresa ip: 0 si 1
#define BITS 2

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[%d]: %s\n", __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

typedef struct {
	int len;
	char payload[MAX_LEN];
	int interface;
} packet;

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
};

// in nod-ul unui Trie tinem minte intrarea, daca exista, altfel NULL
struct Trie
{
	struct route_table_entry* r_entry;
	struct Trie* bit[BITS];
};

extern int interfaces[ROUTER_NUM_INTERFACES];

int send_packet(int interface, packet *m);
int get_packet(packet *m);
char *get_interface_ip(int interface);
int get_interface_mac(int interface, uint8_t *mac);
void init();
void parse_arp_table();

uint16_t checksum(void *vdata, size_t length);
void init_packet(packet* pkt, int length, int interface);
struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry * arp_table, int arp_table_len);
struct route_table_entry * parse_rtable(struct Trie * trie);
int bit(uint32_t N, int i);
struct Trie* getNewTrieNode();
void insert(struct Trie *head, struct route_table_entry* entry);
struct route_table_entry* best_route_from_trie(struct Trie* head, uint32_t dest_ip);
void free_trie(struct Trie * current);
void echo_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr);
void time_exceeded_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr);
void dest_unreachable_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr);
void arp_request(uint8_t* best_mac, struct route_table_entry * best_route);
void arp_reply(packet m, struct ether_header *eth_hdr, struct ether_arp* arp);