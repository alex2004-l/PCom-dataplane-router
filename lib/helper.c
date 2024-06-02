#include "helper.h"


struct route_table_entry* get_best_route(uint32_t next_ip) {
	uint32_t ip = ntohl(next_ip);
    uint32_t m = 1 << 31;
    struct trie_node* iter = trie_tree;
    struct route_table_entry *result = NULL;

	/* Iteration through the trie according to next_ip's bits */
    while (iter != NULL) {
		/* Saves the last found node on the path that matches a prefix from the table */
        if (iter->is_end == true) {
            result = (struct route_table_entry *) iter->data;
        }
        if (m & ip) {
            iter = iter->right;
        } else {
            iter = iter->left;
        }
        m = m >> 1;
    }

    return result;
}


struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; ++i) {
		if(arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}


bool check_broadcast(struct ether_header *eth_hdr) {
	for (int i = 0; i < MAC_ADDR_SIZE; ++i) {
		if (eth_hdr->ether_dhost[i] != 0xFF) {
			return false;
		}
	}
	return true;
}

bool check_for_router(int interface, struct ether_header *eth_hdr) {
	uint8_t interface_mac[6];
	get_interface_mac(interface, interface_mac);

    /* Compares destination mac address with interface mac address */
	for (int i = 0; i < MAC_ADDR_SIZE; ++i) {
		if (eth_hdr->ether_dhost[i] != interface_mac[i]) {
			return false;
		}
	}
	return true;
}