#pragma once

#include <stdint.h>
#include <vector>
#include <unordered_map>

#define BCPI_SHA256_SIZE 32
#define BCPI_MAX_NUM_COUNTER 16

using namespace std;

#ifdef __cplusplus

extern "C" {

#endif

typedef uint32_t bcpi_hash;
typedef struct bcpi_node bcpi_node;
struct bcpi_function {
	const char *name;
	uint64_t begin_address;
	uint64_t end_address;
};

struct bcpi_object {
	const char *path;
	bcpi_hash hash;

	int num_function;
	struct bcpi_function *function_list;

	int num_node;
	struct bcpi_node *node_list;

	int object_index;
	uint64_t internal;
};

struct bcpi_edge {
	struct bcpi_node *to;
	struct bcpi_node *from;

	uint64_t counters[BCPI_MAX_NUM_COUNTER];

	uint64_t internal;
};

struct bcpi_node {
	struct bcpi_object *object;
	uint64_t node_address;

	int num_incoming_edge;
	struct bcpi_edge *edge_list;

	uint64_t terminal_counters[BCPI_MAX_NUM_COUNTER];

	int node_index;
	uint64_t internal;
};

struct bcpi_record {
	const char *system_name;
	uint64_t epoch;

	int num_counter;
	const char **counter_name;

	int num_object;
	struct bcpi_object *object_list;
};

struct bcpi_archive_header {
	uint32_t identifier;
	uint32_t size;
};

void bcpi_save(const struct bcpi_record *, char **, int *);
int bcpi_save_file(const struct bcpi_record *, const char *);
void bcpi_load(char *, int, struct bcpi_record **);
int bcpi_load_file(const char *, struct bcpi_record **);
void bcpi_free(struct bcpi_record *);
bool bcpi_is_equal(struct bcpi_record *a, struct bcpi_record *b);
int bcpi_get_index_from_name(struct bcpi_record *record, const char *name);
void bcpi_print_summary(const struct bcpi_record *r);
int bcpi_merge(struct bcpi_record **out, const struct bcpi_record **list, int num);
void bcpi_show_node_info(struct bcpi_record *r, struct bcpi_node *, const char *sort_criteria);

#ifdef __cplusplus
}

void bcpi_collect_edge(struct bcpi_node *n, vector<struct bcpi_edge *> &edge_out);

void bcpi_collect_node(struct bcpi_record *record, vector<struct bcpi_node *> &node_out);

void bcpi_node_sort(int, vector<struct bcpi_node*> &sorted_nodes);

void bcpi_edge_sort(int index , vector<struct bcpi_edge*> &sorted_edges);

void bcpi_collect_object(struct bcpi_record *record, vector<struct bcpi_object *> &object_out, const char *name);

void bcpi_collect_node_from_object(struct bcpi_record *record, vector<struct bcpi_node *> &node_out, struct bcpi_object *ro);

std::vector<bcpi_node *> hash2vec(unordered_map<uint64_t, bcpi_node *> umap);

std::vector<bcpi_node *> vec2hash_merge_nodes(int index, std::vector<bcpi_node *> nodes);

#endif
