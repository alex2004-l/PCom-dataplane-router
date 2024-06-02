#include "trie.h"

#include <stdlib.h>
#include <arpa/inet.h>


struct trie_node *create_tree() {
    struct trie_node *root = malloc(sizeof(struct trie_node));
    root->left = NULL;
    root->right = NULL;
    root->data = NULL;
    root->is_end = false;
    return root;
}

void add_trie_node(struct trie_node* tree, struct route_table_entry *entry) {
    uint32_t mask = htonl(entry->mask);
    uint32_t prefix = htonl(entry->prefix);

    uint32_t m = 1 << 31;
    struct trie_node* iter = tree;
    while (m & mask) {
        if (m & prefix) {
            if (iter->right == NULL) {
                struct trie_node *new_node = create_tree();
                iter->right = new_node;
            }
            iter = iter->right;
        } else {
            if (iter->left == NULL) {
                struct trie_node *new_node = create_tree();
                iter->left = new_node;
            }
            iter = iter->left;
        }
        m = m >> 1;
    }
    iter->is_end = true;
    iter->data = (void *) entry;
}

void free_trie(struct trie_node *trie) {
    if (trie == NULL)
        return;
    free_trie(trie->left);
    free_trie(trie->right);
    free(trie);
}