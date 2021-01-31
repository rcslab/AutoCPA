#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include "find_an_address.h"
#include "../libbcpi/libbcpi.h"
#include "../libbcpi/crc32.h"

#include <algorithm>
#include <iostream>
#include <string>

#define BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH "/usr/lib/debug"

struct util_query_parameter {
	std::vector<const char *> file_names;
	//const char *file_name;
	const char *counter_name;
	// object files containing this string in their names will be included for traversal
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
uitl_check_recurse_condition(struct util_query_parameter *u, int cur_level,
	struct bcpi_node *n)
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

// string check_addr(const char *object_path, const char *debug_file_path, uint64_t offset) {
//     int rc=-1;
//     string dw_data;

//     rc = search_symbol(object_path, debug_file_path, offset, &dw_data);

//     if (rc==1)
//         return "error in srchsymbol";
//     if (rc==0)
//         return dw_data;
//     return "";
// }

uint64_t
get_revised_addr(const char *object_path, uint64_t offset)
{
	int rc = -1;
	uint64_t revised_addr;

	rc = search_addr(object_path, offset, &revised_addr);

	if (rc==1)
		return 0;
	if (rc==0)
		return revised_addr;
	return 0;
}

std::string
util_get_object_path(const char *str)
{
	const std::string debug_ext = ".debug";
	std::string debug_file_path = std::string(BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH) + std::string(str) + debug_ext;
	struct stat s;
	if (stat(debug_file_path.c_str(), &s) == -1) {
		return std::string(str);
	}
	return debug_file_path;
}

void
util_traverse(struct util_query_parameter *u, int cur_level, struct bcpi_node *n)
{
	std::vector<struct bcpi_edge *> edges;
	bcpi_collect_edge(n, edges);
	bcpi_edge_sort(u->counter_index, edges);
	int traverse_node = std::min((int)edges.size(), u->top_n_edge);
	for (int i = 0; i < traverse_node; ++i) {
		struct bcpi_edge *e = edges[i];
		struct bcpi_node *from = e->from;
		uint64_t value = e->counters[u->counter_index];
		if (!value) {
			break;
		}
		util_print_spaces(cur_level);
		printf("<- %ld : %lx (%s) ", value, from->node_address, from->object->path);

		std::string debug_info = util_get_object_path(from->object->path);
		//cout << check_addr(from->object->path, debug_info.c_str(), from->node_address) << endl;
		if (uitl_check_recurse_condition(u, cur_level + 1, from)) {
			util_traverse(u, cur_level + 1, from);
		}
	}
}

void
util_process(struct util_query_parameter *u)
{
	if (u->file_names.size()==0) {
		return;
	}
	if (!u->counter_name) {
		return;
	}
	// If merely do checksum, do so then exit.
	if (u->do_checksum) {
		int file_fd = open(u->file_names[0], O_RDONLY | O_CLOEXEC);
		if (file_fd == -1) {
			if (errno != ENOENT && errno != EPERM && errno != EACCES) {
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
	for (size_t i = 0; i < u->file_names.size() ; i++) {

		std::vector<struct bcpi_object *> objects;
		struct bcpi_record * record;
		bcpi_load_file(u->file_names[i], &record);
		records.push_back(record);
		//bcpi_print_summary(record);

		u->counter_index = bcpi_get_index_from_name(records[i], u->counter_name);
		if (u->counter_index == -1) {
			printf("%s does not exist!\n", u->counter_name);
			return;
		}
		if (u->object_name) {
			bcpi_collect_object(records[i], objects, u->object_name);
			//here only the objects that we are interested in are loaded into
			//objects
			for (auto o: objects) {
				bcpi_collect_node_from_object(records[i], nodes, o);
			}
		} else {
			bcpi_collect_node(records[i], nodes);
		}
	}
	//call node merge here
	nodes=vec2hash_merge_nodes(u->counter_index, nodes);
	bcpi_node_sort(u->counter_index, nodes);
	int traverse_node = std::min(u->top_n_node, (int)nodes.size());
	std::string filename="address_info.csv";
	FILE *f = fopen(filename.c_str(), "w");
	if (!f) {
		perror("fopen");
		printf("error in openfile");
	}

	for (int i = 0; i < traverse_node; ++i) {
		struct bcpi_node *n = nodes[i];
		uint64_t value = n->terminal_counters[u->counter_index];
		if (!value) {
			break;
		}

		//cout <<hex<<get_revised_addr(n->object->path, n->node_address) << endl;
		printf("* %ld: %lx (%s) ", value, get_revised_addr(n->object->path, n->node_address), n->object->path);
		fprintf(f, "%ld, %lx\n", value, get_revised_addr(n->object->path, n->node_address));
		//printf("* %ld: %lx (%s) ", value, n->node_address, n->object->path);
		//fprintf(f, "%ld, %lx\n", value, n->node_address); 
		//string debug_info = util_get_object_path(n->object->path);
		//cout<<"This is T"<<endl;
		bcpi_show_node_info(records[0], n, u->counter_name);//ino khodam hazf 
		//kardam,vali ba code e taghir yafte ham kar mikone
		//cout<<"This is TT"<<endl;
		//util_traverse(u, 1, n);
	}
	int status = fclose(f);
	if (status) {
		perror("fclose");
		printf("error in closefile");
	}
}

void
util_show_help()
{
	fprintf(stderr, "Help: "
		"  -h (Show this help)\n"
		"  -n n (show top n nodes)\n"
		"  -d d (traverse up to d levels deep)\n"
		"  -e e (show top e edges)\n"
		"  -o o (only show object at o)\n"
		"  -c c (show callchain concerning counter name c)\n"
		"  -k file (compute checksum of file)\n"
		"  -f name (process file with name)\n");
}

int
main(int argc, char **argv)
{
	struct util_query_parameter _util_conf, *util_conf = &_util_conf;

	//util_conf->file_name = 0;
	util_conf->counter_name = 0;
	util_conf->object_name = 0;
	util_conf->top_n_node = 5;
	util_conf->top_n_edge = 5;
	util_conf->max_depth = 5;
	util_conf->do_checksum = false;

	int c = 1;
	while (c) {
		c = getopt(argc, argv, "hf:n:d:e:c:o:k:");
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			util_show_help();
			break;
		case 'f':
			//util_conf->file_name = strdup(optarg);
			util_conf->file_names.push_back(strdup(optarg));
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
			//util_conf->file_name = strdup(optarg);
			util_conf->file_names.push_back(strdup(optarg));
			util_conf->do_checksum = true;
			break;
		default:
			break;
		}
	}

	if (argc == 1) {
		util_show_help();
		return 0;
	}

	std::cout << "size of file name vector: " << util_conf->file_names.size() << "\n";
	//cout<<"print vector file name: "<<util_conf->file_names[0]<<endl;
	//cout<<"print vector file name: "<<util_conf->file_names[1]<<endl;
	util_process(util_conf);
}
