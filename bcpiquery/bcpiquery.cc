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

#define BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH "/usr/lib/debug"

static bool verbose = false;

struct util_query_parameter {
	std::string bcpi_path;
	std::string filter_hostname;
	std::string filter_begin;
	std::string filter_end;
	std::vector<std::string> file_names;
	const char *counter_name;
	// object files containing this string in their names will be included
	// for traversal
	const char *object_name;
	int counter_index;
	// Show this many top nodes when pretty printing call graph.
	int top_n_node;
	int max_depth;
	// Show this many top edges when pretty printing call graph.
	int top_n_edge;
	// Whether the utility should just calculate checksum and exit.
	bool do_checksum;
};

void
util_print_spaces(int n)
{
	printf("%*c", n, ' ');
}

/*
 * Do not visit the same node twice; do not go too deep when traversing.
 */

bool
util_check_recurse_condition(
    struct util_query_parameter *u, int cur_level, struct bcpi_node *n)
{
	int index = u->counter_index;
	if (n->internal & (1 << index)) {
		printf("(visited)\n");
		return false;
	}

	if (cur_level > u->max_depth) {
		printf("(......)\n");
		return false;
	}

	n->internal |= (1 << index);
	printf("\n");
	return true;
}

uint64_t
get_revised_addr(const char *object_path, uint64_t offset)
{
	int rc = -1;
	uint64_t revised_addr;

	rc = search_addr(object_path, offset, &revised_addr);

	if (rc == 1)
		return 0;
	if (rc == 0)
		return revised_addr;
	return 0;
}

std::string
util_get_object_path(const char *str)
{
	const std::string debug_ext = ".debug";
	std::string debug_file_path = std::string(
					  BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH) +
	    std::string(str) + debug_ext;
	struct stat s;
	if (stat(debug_file_path.c_str(), &s) == -1) {
		return std::string(str);
	}
	return debug_file_path;
}

void
util_traverse(
    struct util_query_parameter *u, int cur_level, struct bcpi_node *n)
{
	std::vector<struct bcpi_edge *> edges;
	bcpi_collect_edge(n, edges);
	bcpi_edge_sort(u->counter_index, edges);
	int traverse_node;

	if (u->top_n_edge)
		traverse_node = std::min((int)edges.size(), u->top_n_edge);
	else
		traverse_node = edges.size();

	for (int i = 0; i < traverse_node; ++i) {
		struct bcpi_edge *e = edges[i];
		struct bcpi_node *from = e->from;
		uint64_t value = e->counters[u->counter_index];
		if (!value) {
			break;
		}
		util_print_spaces(cur_level);
		printf("<- %ld : %lx (%s) ", value, from->node_address,
		    from->object->path);

		std::string debug_info = util_get_object_path(
		    from->object->path);
		// cout << check_addr(from->object->path, debug_info.c_str(),
		// from->node_address) << endl;
		if (util_check_recurse_condition(u, cur_level + 1, from)) {
			util_traverse(u, cur_level + 1, from);
		}
	}
}

void
bcpiquery_filter_files(struct util_query_parameter *u)
{
	time_t begin_time, end_time;
	struct tm t {
	};

	if (u->filter_begin != "") {
		if (strptime(u->filter_begin.c_str(), "%F_%T", &t) == nullptr) {
			fprintf(stderr,
			    "Failed to parse start time YYYY-MM-DD_HH:MM:SS\n");
			exit(EX_USAGE);
		}
		begin_time = mktime(&t);
	}
	if (u->filter_end != "") {
		if (strptime(u->filter_end.c_str(), "%F_%T", &t) == nullptr) {
			fprintf(stderr,
			    "Failed to parse start time YYYY-MM-DD_HH:MM:SS\n");
			exit(EX_USAGE);
		}
		end_time = mktime(&t);
	}

	for (auto &p : std::filesystem::directory_iterator(u->bcpi_path)) {
		std::string filename = p.path().filename();
		std::string date;
		std::string hostname;
		time_t file_time;

		if (!p.is_regular_file())
			continue;
		if (!filename.starts_with("bcpi_") ||
		    !filename.ends_with(".bin"))
			continue;

		/*
		 * bcpi_2021-02-16_16:25:23_hostname.bin
		 * 0    0                 2 2
		 * 0    6                 4 6
		 */
		date = filename.substr(5, 19);
		hostname = filename.substr(25, filename.size() - 29);

		if (u->filter_hostname != "" && u->filter_hostname != hostname)
			continue;

		if (strptime(date.c_str(), "%F_%T", &t) == nullptr) {
			fprintf(stderr,
			    "Unable to parse the time for file '%s'\n",
			    filename.c_str());
			continue;
		}
		file_time = mktime(&t);

		if (u->filter_begin != "" && begin_time > file_time)
			continue;
		if (u->filter_end != "" && end_time < file_time)
			continue;

		u->file_names.push_back(p.path());
		if (verbose)
			printf("Found match %s\n", p.path().c_str());
	}

	printf("Querying %lu files\n", u->file_names.size());
}

void
util_process(struct util_query_parameter *u)
{
	if (u->file_names.size() == 0) {
		bcpiquery_filter_files(u);
	}

	if (u->file_names.size() == 0) {
		fprintf(stderr, "No file names specified or found in '%s'\n",
		    u->bcpi_path.c_str());
		exit(EX_USAGE);
	}

	if (!u->counter_name) {
		return;
	}

	// If merely do checksum, do so then exit.
	if (u->do_checksum) {
		int file_fd = open(
		    u->file_names[0].c_str(), O_RDONLY | O_CLOEXEC);
		if (file_fd == -1) {
			if (errno != ENOENT && errno != EPERM &&
			    errno != EACCES) {
				perror("open");
			}
			return;
		}

		uint64_t file_size = lseek(file_fd, 0, SEEK_END);
		lseek(file_fd, 0, SEEK_SET);

		void *file_content = mmap(0, file_size, PROT_READ,
		    MAP_NOCORE | MAP_SHARED, file_fd, 0);
		if (file_content == MAP_FAILED) {
			perror("mmap");
			return;
		}

		uint32_t hash = bcpi_crc32(file_content, file_size);

		int status = munmap(file_content, file_size);
		if (status == -1) {
			perror("munmap");
		}

		status = close(file_fd);
		if (status == -1) {
			perror("close");
		}

		fprintf(stdout, "%x\n", hash);
		return;
	}

	std::vector<struct bcpi_node *> nodes;
	std::vector<struct bcpi_record *> records;
	for (size_t i = 0; i < u->file_names.size(); i++) {
		int index;
		std::vector<struct bcpi_object *> objects;
		struct bcpi_record *record;

		if (bcpi_load_file(u->file_names[i].c_str(), &record) < 0) {
			fprintf(stderr, "Failed to load bcpi file '%s'\n",
			    u->file_names[i].c_str());
		}

		index = bcpi_get_index_from_name(record, u->counter_name);
		if (index == -1) {
			if (verbose)
				printf("%s not present in %s!\n",
				    u->counter_name, u->file_names[i].c_str());
			continue;
		}

		if (verbose)
			bcpi_print_summary(record);
		records.push_back(record);

		// We set the counter_index on the first matching file
		if (records.size() == 1) {
			u->counter_index = index;
		}

		// XXX: Support counter index changing between files
		if (bcpi_get_index_from_name(records[0], u->counter_name) !=
		    bcpi_get_index_from_name(record, u->counter_name)) {
			fprintf(stderr,
			    "KNOWN BUG: Unsupported scanning across files with different counter indicies\n");
			exit(EX_USAGE);
		}

		if (u->object_name) {
			bcpi_collect_object(record, objects, u->object_name);
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
	nodes = vec2hash_merge_nodes(u->counter_index, nodes);
	bcpi_node_sort(u->counter_index, nodes);
	int traverse_node;
	std::string filename = "address_info.csv";

	FILE *f = fopen(filename.c_str(), "w");
	if (!f) {
		perror("fopen");
		exit(EX_OSERR);
	}

	if (u->top_n_node)
		traverse_node = std::min(u->top_n_node, (int)nodes.size());
	else
		traverse_node = nodes.size();

	for (int i = 0; i < traverse_node; ++i) {
		struct bcpi_node *n = nodes[i];
		uint64_t value = n->terminal_counters[u->counter_index];
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
			bcpi_show_node_info(records[0], n, u->counter_name);
	}
	printf("Found %d nodes\n", traverse_node);

	if (fclose(f)) {
		perror("fclose");
	}
}

void
util_show_help()
{
	fprintf(stderr,
	    "Usage: bcpiquery [OPTIONS]\n"
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
	{ NULL, 0, NULL, 0 },
};

int
main(int argc, char **argv)
{
	int opt;
	struct util_query_parameter _util_conf, *util_conf = &_util_conf;

	util_conf->bcpi_path = BCPID_DEFAULT_PATH;
	util_conf->filter_hostname = "";
	util_conf->filter_begin = "";
	util_conf->filter_end = "";
	util_conf->counter_name = 0;
	util_conf->counter_index = -1;
	util_conf->object_name = 0;
	util_conf->top_n_node = 0;
	util_conf->top_n_edge = 0;
	util_conf->max_depth = 5;
	util_conf->do_checksum = false;

	while ((opt = getopt_long(
		    argc, argv, "hf:n:d:e:c:o:k:p:v", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			util_show_help();
			break;
		case 'f':
			util_conf->file_names.push_back(optarg);
			break;
		case 'n':
			util_conf->top_n_node = atoi(optarg);
			break;
		case 'd':
			util_conf->max_depth = atoi(optarg);
			break;
		case 'e':
			util_conf->top_n_edge = atoi(optarg);
			break;
		case 'c':
			util_conf->counter_name = strdup(optarg);
			break;
		case 'o':
			util_conf->object_name = strdup(optarg);
			break;
		case 'k':
			util_conf->file_names.push_back(optarg);
			util_conf->do_checksum = true;
			break;
		case 'p':
			util_conf->bcpi_path = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 1000:
			util_conf->filter_hostname = optarg;
			break;
		case 1001:
			util_conf->filter_begin = optarg;
			break;
		case 1002:
			util_conf->filter_end = optarg;
			break;
		default:
			break;
		}
	}

	if (argc == 1) {
		util_show_help();
		return 0;
	}

	util_process(util_conf);

	return EX_OK;
}
