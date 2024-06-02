#include <string.h>
#include <stdio.h>

#include "queue.h"
#include "lib.h"
#include "trie.h"
#include "helper.h"


/************************* Global variables *************************/
struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

queue q;
struct trie_node *trie_tree;

/***************************** Functions *****************************/

/* Sens an arp request on the given interface for newxt_ip */
void send_arp_request(int interface, uint32_t next_ip) {
	/* Calculating dimensions for arp request */
	size_t request_dim = sizeof(struct ether_header) + sizeof(struct arp_header);

	/* Allocating memory */
	char *request = malloc(request_dim);
	DIE(request == NULL, "malloc");

	struct ether_header *req_eth = (struct ether_header *) request;
	struct arp_header   *req_arp = (struct arp_header *) (request + sizeof(struct ether_header));

	/* Setting the fields in the ethernet header */
	get_interface_mac(interface, req_eth->ether_shost);
	memset(req_eth->ether_dhost, 0xFF, MAC_ADDR_SIZE); // broadcast address
	req_eth->ether_type = htons(ARP);

	/* Setting the fields in the ARP header */
	req_arp->htype = htons(ETHERNET);
	req_arp->ptype = htons(IPV4);
	req_arp->hlen = MAC_ADDR_SIZE;
	req_arp->plen = IP_ADDR_SIZE;
	req_arp->op = htons(REQUEST);

	memcpy(req_arp->sha, req_eth->ether_shost, MAC_ADDR_SIZE);
	req_arp->spa = inet_addr(get_interface_ip(interface));
	memset(req_arp->tha, 0xFF, MAC_ADDR_SIZE);
	req_arp->tpa = next_ip;

	/* Sending packet */
	send_to_link(interface, request, request_dim);

	/* Freeing memory */
	free(request);
}


/* Sends icmp reply from router */
void send_icmp_echo_reply(char *buffer, size_t length, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buffer;
	struct iphdr *ip_hdr = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));

	/* Updating ethernet header mac addreses for source and destination */
	uint8_t aux_array[6];
	memcpy(aux_array, eth_hdr->ether_dhost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_shost, aux_array, MAC_ADDR_SIZE);

	/* Updating ip header ip addresses for source and destination */
	uint32_t aux;
	aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;

	/* Resetting time-to-live to default value */
	ip_hdr->ttl = DEFAULT_TTL;

	/* Updating icmp code and type */
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;

	/* Recalculating checksums for headers */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, length - sizeof(struct ether_header) - sizeof(struct iphdr)));

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* Sending packet */
	send_to_link(interface, buffer, length);
}


/* Sends icmp error message from router */
void send_icmp_error(char *buffer, size_t length, int interface, uint8_t type) {
	struct ether_header *eth_hdr = (struct ether_header *) buffer;
	struct iphdr *ip_hdr = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr*) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));


	/* Updating ethernet header mac addreses for source and destination */
	uint8_t aux_array[6];
	memcpy(aux_array, eth_hdr->ether_dhost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_shost, aux_array, MAC_ADDR_SIZE);

	/* Copying the ip header and 64 bits of payload data */
	char *aux_buffer = malloc(sizeof(struct iphdr) + PAYLOAD_LEN);
	DIE(aux_buffer == NULL, "malloc");
	memcpy(aux_buffer, ip_hdr, sizeof(struct iphdr) + PAYLOAD_LEN);

	/* Calculating length of ip header and data */
	ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + PAYLOAD_LEN);

	/* Resetting time-to-live to default value and updating the encapsulated protocol */
	ip_hdr->ttl = DEFAULT_TTL;
	ip_hdr->protocol = ICMP;

	/* Updating ip addresses for host and destination */
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));

	/* Updating icmp code and type */
	icmp_hdr->type = type;
	icmp_hdr->code = 0;

	/* Copying the ip header and data of the dropped packet into the error message */
	char *aux_pointer = ((char *)icmp_hdr) + sizeof(struct icmphdr);
	memcpy(aux_pointer, aux_buffer, sizeof(struct iphdr) + PAYLOAD_LEN);

	/* Calculating total length of the packet */
	size_t new_length = sizeof(struct ether_header) + ntohs(ip_hdr->tot_len);

	/* Updating headers' checksum */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, new_length - sizeof(struct ether_header) - sizeof(struct iphdr)));

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* Sending packet */
	send_to_link(interface, buffer, new_length);

	/* Frreing auxiliary resources */
	free(aux_buffer);
}


/* Parsing IPv4 packets */
void ipv4_protocol(char *buffer, size_t length, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buffer;
	struct iphdr *ip_hdr = (struct iphdr *) (buffer + sizeof(struct ether_header));

	/* If packet length is too short, drop packet */
	if (length < sizeof(struct ether_header) + sizeof(struct iphdr)) {
		return;
	}

	/* Checks if the packet is a ICMP Echo request for the router and sends Echo reply */
	if (ip_hdr->protocol == ICMP && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
		struct icmphdr *icmphdr = (struct icmphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
		if (icmphdr->type == ECHO_REQUEST) {
			send_icmp_echo_reply(buffer, length, interface);
			return;
		}
	}

	/* Checks if packet is corrupt */
	uint16_t old_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;

	/* Drop packet if the checksums don't match */
	if (old_checksum != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
		return;
	}

	/* Drop packet if ttl expires and send icmp error */
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		send_icmp_error(buffer, length, interface, TIME_EXCEDEED);
		return;
	}

	/* Decrement time-to-live */
	ip_hdr->ttl = ip_hdr->ttl - 1;

	/* Get best route, and if a route isn't avaiable, send ICMP error */
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

	if (best_route == NULL) {
		send_icmp_error(buffer, length, interface, DESTINATION_UNREACHABLE);
		return;
	}
	
	/* Calculates new checksum using the formula */
	ip_hdr->check = ~(~htons(old_checksum) + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)ip_hdr->ttl) - 1;

	/* Updating ethernet header */
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	struct arp_table_entry *destination = get_arp_entry(best_route->next_hop);

	/* If there is no arp entry for the next hop, send an arp request */
	if (destination == NULL) {
		send_arp_request(best_route->interface, best_route->next_hop);

		/* Enqueue a copy of the current packet and drop it */
		struct queue_data *data = malloc(sizeof(struct queue_data));
		data->buffer = malloc(length * sizeof(char));
		memcpy(data->buffer, buffer, length);
		data->best_route = best_route;
		data->length = length;

		queue_enq(q, (void *) data);
		return;
	}

	memcpy(eth_hdr->ether_dhost, destination->mac, MAC_ADDR_SIZE);

	/* Send packet to the next hop */
	send_to_link(best_route->interface, buffer, length);
}


/* Parsing the arp reply */
void parse_arp_reply(char *buffer, size_t length, int interface) {
	struct arp_header   *reply_arp = (struct arp_header *) (buffer + sizeof(struct ether_header));

	/* If the length of the packet is too short, drop packet */
	if (length < sizeof(struct ether_header) + sizeof(struct arp_header)) {
		return;
	}

	/* Adding the new pair in the arp table */
	arp_table[arp_table_len].ip = reply_arp->spa;
	memcpy(arp_table[arp_table_len].mac, reply_arp->sha, MAC_ADDR_SIZE);
	arp_table_len ++;

	/* If queue is not empty, deque first element */
	if (queue_empty(q)) {
		return;
	}

	struct queue_data *data = (struct queue_data *) queue_deq(q);

	/* Update the mac destination of the dequed packet */
	struct ether_header* eth_hdr = (struct ether_header *) data->buffer;
	struct arp_table_entry *destination = get_arp_entry(data->best_route->next_hop);
	memcpy(eth_hdr->ether_dhost, destination->mac, MAC_ADDR_SIZE);
	send_to_link(data->best_route->interface, data->buffer, data->length);

	/* Free auxiliary resources */
	free(data->buffer);
	free(data);
}


/* Parsing the arp request */
void parse_arp_request(char *buffer, size_t length, int interface) {
	struct ether_header *req_eth = (struct ether_header *) buffer;
	struct arp_header *req_arp = (struct arp_header *) (buffer + sizeof(struct ether_header));

	/* If the length of the packet is too short, drop packet */
	if (length < sizeof(struct ether_header) + sizeof(struct arp_header)) {
		return;
	}

	/* Updating ether header addresses */
	memcpy(req_eth->ether_dhost, req_eth->ether_shost, MAC_ADDR_SIZE);
	get_interface_mac(interface, req_eth->ether_shost);

	/* Updating arp header data */
	req_arp->op = htons(REPLY);

	uint8_t source_mac_addr[6], dest_mac_addr[6];
	uint32_t source_ip_addr, dest_ip_addr;
	memcpy(source_mac_addr, req_arp->sha, MAC_ADDR_SIZE);
	get_interface_mac(interface, dest_mac_addr);

	source_ip_addr = req_arp->spa;
	dest_ip_addr = inet_addr(get_interface_ip(interface));

	memcpy(req_arp->tha, source_mac_addr, MAC_ADDR_SIZE);
	memcpy(req_arp->sha, dest_mac_addr, MAC_ADDR_SIZE);

	req_arp->tpa = source_ip_addr;
	req_arp->spa = dest_ip_addr;

	/* Sending packet */
	send_to_link(interface, buffer, length);
}


/* Parsing ARP protocol packet */
void arp_protocol(char *buffer, int length, int interface) {
	struct arp_header   *arp_hdr = (struct arp_header *) (buffer + sizeof(struct ether_header));

	if (length < sizeof(struct ether_header) + sizeof(struct arp_header)) {
		return;
	}

	switch (ntohs(arp_hdr->op)) {
		case REPLY:
			parse_arp_reply(buffer, length, interface);
			break;
		case REQUEST:
			parse_arp_request(buffer, length, interface);
			break;
		default:
			break;	
	} 
}


int main(int argc, char *argv[])
{
	init(argc - 2, argv + 2);

	char buf[MAX_PACKET_LEN];
	size_t len;
	int interface;

	/* Allocating memory for routing table and arp cache */
	rtable = malloc(sizeof(struct route_table_entry) * RTABLE_SIZE);
	DIE(rtable == NULL, "Couldn't allocate routing table\n");

	arp_table = malloc(sizeof(struct arp_table_entry) * ARP_TABLE_SIZE);
	DIE(arp_table == NULL, "Couldn't allocate arp table\n");

	/* Reading the routing table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	/* Creating the queue and the trie */
	q = queue_create();
	trie_tree = create_tree();

	for (int i = 0; i < rtable_len; ++i) {
        add_trie_node(trie_tree, &rtable[i]);
    }

	while (1) {

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* Checking if the packet is for the router */
		if (!check_for_router(interface, eth_hdr) && !check_broadcast(eth_hdr)) {
			continue;
		}
		
		/* Verifying the type of the packet */
		if (ntohs(eth_hdr->ether_type) == IPV4) {
			ipv4_protocol(buf, len, interface);
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ARP) {
			arp_protocol(buf, len, interface);
			continue;
		}

	}

}