#pragma once

#include <stdint.h>

#include <unordered_map>
#include <vector>

#define BCPID_DEFAULT_PATH "/var/tmp"

#define BCPI_SHA256_SIZE 32
#define BCPI_MAX_NUM_COUNTER 16

#define BCPI_MAJOR_VERSION 1
#define BCPI_MINOR_VERSION 0
#define BCPI_DEFAULT_FLAGS 0

typedef uint32_t bcpi_hash;

struct bcpi_function {
	std::string name;
	uint64_t begin_address;
	uint64_t end_address;
};

struct bcpi_node;
struct bcpi_object {
	std::string path;
	bcpi_hash hash;
	std::vector<bcpi_function> functions;
	std::vector<bcpi_node> nodes;
	int object_index;
	uint64_t internal;
};

struct bcpi_edge {
	bcpi_node *to;
	bcpi_node *from;
	uint64_t counters[BCPI_MAX_NUM_COUNTER];
	uint64_t internal;
};

struct bcpi_node {
	bcpi_object *object;
	uint64_t node_address;
	std::vector<bcpi_edge> edges;
	uint64_t terminal_counters[BCPI_MAX_NUM_COUNTER];
	int node_index;
	uint64_t internal;
};

struct bcpi_record {
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t flags;
	std::string system_name;
	uint64_t epoch_start;
	uint64_t epoch_end;
	std::vector<std::string> counters;
	std::vector<bcpi_object> objects;
};

struct bcpi_archive_header {
	uint32_t identifier;
	uint32_t size;
};

void bcpi_save(const bcpi_record &, char **, int *);
int bcpi_save_file(const bcpi_record &, const char *);
int bcpi_load(char *, int, bcpi_record *);
int bcpi_load_file(const char *, bcpi_record *);
bool bcpi_is_equal(const bcpi_record &a, const bcpi_record &b);
int bcpi_get_index_from_name(
    const bcpi_record &record, const std::string &name);
void bcpi_print_summary(const bcpi_record &r);
void bcpi_dump_nodes(const bcpi_record &r);

int bcpi_merge(bcpi_record **out, const bcpi_record **list, int num);
void bcpi_show_node_info(
    bcpi_record *r, bcpi_node *, const char *sort_criteria);

void bcpi_collect_edge(bcpi_node *n, std::vector<bcpi_edge *> &edge_out);
void bcpi_collect_node(bcpi_record *record, std::vector<bcpi_node *> &node_out);
void bcpi_node_sort(int index, std::vector<bcpi_node *> &sorted_nodes);
void bcpi_node_sort(std::vector<bcpi_node *> &sorted_nodes);
void bcpi_edge_sort(int index, std::vector<bcpi_edge *> &sorted_edges);

void bcpi_collect_object(bcpi_record *record,
    std::vector<bcpi_object *> &object_out, const char *name);

void bcpi_collect_node_from_object(
    bcpi_record *record, std::vector<bcpi_node *> &node_out, bcpi_object *ro);

std::vector<bcpi_node *> hash2vec(
    std::unordered_map<uint64_t, bcpi_node *> umap);

std::vector<bcpi_node *> vec2hash_merge_nodes(std::vector<bcpi_node *> nodes);
std::vector<bcpi_node *> vec2hash_merge_nodes(
    int index, std::vector<bcpi_node *> nodes);
