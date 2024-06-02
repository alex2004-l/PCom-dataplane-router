#ifndef HELPER_H
#define HELPER_H

#include <arpa/inet.h>
#include <stdbool.h>

#include "lib.h"
#include "trie.h"
#include "protocols.h"

#define RTABLE_SIZE    80000
#define ARP_TABLE_SIZE 100

#define IPV4 0x0800
#define ARP  0x0806

#define MAC_ADDR_SIZE  6
#define IP_ADDR_SIZE   4

#define ETHERNET 1
#define ICMP 1

#define REQUEST 1
#define REPLY   2

#define DEFAULT_TTL 64

#define PAYLOAD_LEN 64 

#define ECHO_REQUEST 8
#define DESTINATION_UNREACHABLE 3
#define TIME_EXCEDEED 11

extern struct arp_table_entry *arp_table;
extern int arp_table_len;
extern struct trie_node *trie_tree;

struct queue_data {
	char *buffer;
	struct route_table_entry* best_route;
	size_t length;
};

/* Return the entry in the routing table with the LPM for a given ip,
 * or NULL if there is no such entry */
struct route_table_entry* get_best_route(uint32_t next_ip);

/* Returns the arp entry that matches a given ip, or NULL if such entry does not exist */
struct arp_table_entry *get_arp_entry(uint32_t ip);

/* Returns true if the destination is the broadcast addres, false otherwise */
bool check_broadcast(struct ether_header *eth_hdr);

/* Return true if the router is the target of the packet, false*/
bool check_for_router(int interface, struct ether_header *eth_hdr);

#endif