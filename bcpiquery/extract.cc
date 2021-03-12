#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <getopt.h>
#include <libdwarf.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>

#include "../libbcpi/crc32.h"
#include "../libbcpi/libbcpi.h"
#include "find_an_address.h"
#include "util.h"

#define BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH "/usr/lib/debug"

static bool verbose = false;
static std::string outfile = "address_info.csv";

struct util_query_parameter {
	std::vector<std::string> files;
	const char *counter_name;
	// object files containing this string in their names will be included
	// for traversal
	const char *object_name;
	int counter_index;
	// Show top n nodes when printing call graph.
	size_t top_n_node;
	// Show top n edges when printing call graph.
	size_t top_n_edge;
	size_t max_depth;
};

/*
 * Do not visit the same node twice; do not go too deep when traversing.
 */

static bool
check_recurse_condition(
    const util_query_parameter &u, int cur_level, bcpi_node *n)
{
	int index = u.counter_index;
	if (n->internal & (1 << index)) {
		printf("(visited)\n");
		return (false);
	}

	if (cur_level > u.max_depth) {
		printf("(......)\n");
		return (false);
	}

	n->internal |= (1 << index);
	printf("\n");

	return (true);
}

static uint64_t
get_revised_addr(const char *object_path, uint64_t offset)
{
	int rc = -1;
	uint64_t revised_addr;

	rc = search_addr(object_path, offset, &revised_addr);
	if (rc == 1)
		return (0);
	if (rc == 0)
		return (revised_addr);

	return (0);
}

static std::string
util_find_symbols(const std::string &s)
{
	std::string symbolpath;

	symbolpath = BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH + s + ".debug";

	std::cout << "foo" << symbolpath << std::endl;

	if (access(symbolpath.c_str(), R_OK) == -1) {
		return (s);
	}

	return (symbolpath);
}

void
util_traverse(const util_query_parameter &u, int cur_level, bcpi_node *n)
{
	std::vector<struct bcpi_edge *> edges;
	bcpi_collect_edge(n, edges);
	bcpi_edge_sort(u.counter_index, edges);
	int traverse_node;

	traverse_node = std::min(edges.size(), u.top_n_edge);

	for (size_t i = 0; i < traverse_node; ++i) {
		struct bcpi_edge *e = edges[i];
		struct bcpi_node *from = e->from;
		uint64_t value = e->counters[u.counter_index];

		if (!value) {
			break;
		}

		printf("%*c<- %ld : %lx (%s) ", cur_level, ' ', value,
		    from->node_address, from->object->path);

		std::string debug_info = util_find_symbols(from->object->path);
		// cout << check_addr(from->object->path, debug_info.c_str(),
		// from->node_address) << endl;
		if (check_recurse_condition(u, cur_level + 1, from)) {
			util_traverse(u, cur_level + 1, from);
		}
	}
}

void
util_process(util_query_parameter &u)
{
	std::vector<struct bcpi_node *> nodes;
	std::vector<struct bcpi_record *> records;
	for (size_t i = 0; i < u.files.size(); i++) {
		int index;
		std::vector<struct bcpi_object *> objects;
		struct bcpi_record *record;

		if (bcpi_load_file(u.files[i].c_str(), &record) < 0) {
			fprintf(stderr, "Failed to load bcpi file '%s'\n",
			    u.files[i].c_str());
		}

		index = bcpi_get_index_from_name(record, u.counter_name);
		if (index == -1) {
			if (verbose)
				printf("%s not present in %s!\n",
				    u.counter_name, u.files[i].c_str());
			continue;
		}

		if (verbose)
			bcpi_print_summary(record);
		records.push_back(record);

		// We set the counter_index on the first matching file
		if (records.size() == 1) {
			u.counter_index = index;
		}

		// XXX: Support counter index changing between files
		if (bcpi_get_index_from_name(records[0], u.counter_name) !=
		    bcpi_get_index_from_name(record, u.counter_name)) {
			fprintf(stderr,
			    "KNOWN BUG: Unsupported scanning across files with different counter indicies\n");
			exit(EX_USAGE);
		}

		if (u.object_name) {
			bcpi_collect_object(record, objects, u.object_name);
			// here only the objects that we are interested in are
			// loaded into objects
			for (auto o : objects) {
				bcpi_collect_node_from_object(record, nodes, o);
			}
		} else {
			bcpi_collect_node(record, nodes);
		}
	}
	// call node merge here
	nodes = vec2hash_merge_nodes(u.counter_index, nodes);
	bcpi_node_sort(u.counter_index, nodes);
	int traverse_node;

	FILE *f = fopen(outfile.c_str(), "w");
	if (!f) {
		perror("fopen");
		exit(EX_OSERR);
	}

	traverse_node = std::min(u.top_n_node, nodes.size());

	for (size_t i = 0; i < traverse_node; ++i) {
		struct bcpi_node *n = nodes[i];
		uint64_t value = n->terminal_counters[u.counter_index];
		if (!value) {
			break;
		}

		// cout <<hex<<get_revised_addr(n->object->path,
		// n->node_address) << endl;
		if (verbose)
			printf("* %ld: %lx (%s) ", value,
			    get_revised_addr(n->object->path, n->node_address),
			    n->object->path);
		fprintf(f, "%ld,%lx\n", value,
		    get_revised_addr(n->object->path, n->node_address));
		// printf("* %ld: %lx (%s) ", value, n->node_address,
		// n->object->path); fprintf(f, "%ld, %lx\n", value,
		// n->node_address); string debug_info =
		// util_get_object_path(n->object->path); cout<<"This is
		// T"<<endl;
		if (verbose)
			bcpi_show_node_info(records[0], n, u.counter_name);
	}
	printf("Found %d nodes\n", traverse_node);

	if (fclose(f)) {
		perror("fclose");
	}
}

void
extract_usage()
{
	fprintf(stderr,
	    "Usage: bcpiquery -c [COUNTER] [OPTIONS]\n"
	    "\nOptions:\n"
	    "\t-h -- Show this help\n"
	    "\t-n n -- Show top n nodes\n"
	    "\t-d d -- Traverse up to d levels deep\n"
	    "\t-e e -- Show top e edges\n"
	    "\t-o o -- Only show object at o\n"
	    "\t-c c -- Show callchain concerning counter name c\n"
	    "\t-k file -- Compute checksum of file\n"
	    "\t-f name -- Process file with name\n");
	fprintf(stderr, "\t-p path -- Path to bcpid files (default: %s)\n",
	    BCPID_DEFAULT_PATH);
	fprintf(stderr, "\t--host -- Filter directory by hostname\n");
	fprintf(stderr, "\t--begin -- Filter directory by begin time\n");
	fprintf(stderr, "\t--end -- Filter directory by end time\n");
}

static struct option longopts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "hostname", required_argument, NULL, 1000 },
	{ "begin", required_argument, NULL, 1001 },
	{ "end", required_argument, NULL, 1002 },
	{ "output", required_argument, NULL, 1003 },
	{ NULL, 0, NULL, 0 },
};

int
extract_cmd(int argc, char **argv)
{
	int opt;
	struct util_file_filter f;
	struct util_query_parameter u;

	f.bcpi_path = BCPID_DEFAULT_PATH;
	f.filter_hostname = "";
	f.filter_begin = "";
	f.filter_end = "";

	u.counter_name = 0;
	u.counter_index = -1;
	u.object_name = 0;
	u.top_n_node = std::numeric_limits<size_t>::max();
	u.top_n_edge = std::numeric_limits<size_t>::max();
	u.max_depth = std::numeric_limits<size_t>::max();

	while ((opt = getopt_long(
		    argc, argv, "hf:n:d:e:c:o:k:p:v", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			extract_usage();
			return (EX_OK);
		case 'f':
			u.files.push_back(optarg);
			break;
		case 'n':
			u.top_n_node = atol(optarg);
			break;
		case 'd':
			u.max_depth = atol(optarg);
			break;
		case 'e':
			u.top_n_edge = atol(optarg);
			break;
		case 'c':
			u.counter_name = strdup(optarg);
			break;
		case 'o':
			u.object_name = strdup(optarg);
			break;
		case 'p':
			f.bcpi_path = optarg;
			break;
		case 'v':
			verbose = true;
			f.verbose = true;
			break;
		case 1000:
			f.filter_hostname = optarg;
			break;
		case 1001:
			f.filter_begin = optarg;
			break;
		case 1002:
			f.filter_end = optarg;
			break;
		case 1003:
			outfile = optarg;
			break;
		default:
			break;
		}
	}

	if ((argc == 1) || (u.counter_name == nullptr)) {
		fprintf(stderr, "You must specify a counter name!\n");
		extract_usage();
		return (EX_OK);
	}

	if (u.files.size() == 0) {
		u.files = util_filter_files(&f);
	}

	if (u.files.size() == 0) {
		fprintf(stderr, "No file names specified or found in '%s'\n",
		    f.bcpi_path.c_str());
		exit(EX_USAGE);
	}

	util_process(u);

	return (EX_OK);
}
