#ifndef TRIE_H
#define TRIE_H

#include "lib.h"
#include <stdbool.h>

struct trie_node {
    struct trie_node *left;
    struct trie_node *right;
    void *data;
    bool is_end;
};


/* Creates empty trie */
struct trie_node *create_tree();
/* Adds node in trie */
void add_trie_node(struct trie_node* tree, struct route_table_entry *entry);
/* Frees trie */
void free_trie(struct trie_node *trie);

#endif