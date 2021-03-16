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
#include <set>
#include <string>

#include "../libbcpi/crc32.h"
#include "../libbcpi/libbcpi.h"
#include "elfutil.h"
#include "util.h"

#define BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH "/usr/lib/debug"

static bool verbose = false;

struct util_query_parameter {
	std::vector<std::string> files;
	size_t top_n;
	const char *counter_name;
	const char *object_name;
};

static std::string
lookup_function(const std::string &objname, Dwarf_Addr addr)
{
	return search_symbol(objname, addr);
}

struct Sample {
	std::string object;
	std::unordered_map<std::string, uint64_t> counters;
	void add(const std::string &counter, uint64_t count = 1)
	{
		if (counters.contains(counter))
			counters[counter] += count;
		else
			counters[counter] = count;
	}
	uint64_t total()
	{
		int total = 0;
		for (auto &c : counters) {
			total += c.second;
		}
		return total;
	}
};

static void
util_process(util_query_parameter &u)
{
	std::vector<struct bcpi_node *> nodes;
	std::unordered_map<std::string, Sample> samples;
	std::set<std::string> all_counters;

	for (auto &f : u.files) {
		std::vector<struct bcpi_object *> objects;
		std::vector<std::string> counters;

		struct bcpi_record *record;

		if (bcpi_load_file(f.c_str(), &record) < 0) {
			fprintf(stderr, "Failed to load bcpi file '%s'\n",
			    f.c_str());
		}

		counters.resize(record->num_counter);
		for (int i = 0; i < record->num_counter; i++) {
			counters[i] = record->counter_name[i];
			if (!all_counters.contains(counters[i]))
				all_counters.insert(counters[i]);
		}

		if (verbose)
			bcpi_print_summary(record);

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

		// Examine all nodes in a file
		for (auto &n : nodes) {
			std::string func = lookup_function(
			    n->object->path, n->node_address);

			for (int c = 0; c < counters.size(); c++) {
				uint64_t value = n->terminal_counters[c];
				samples[func].add(counters[c], value);
			}

			if (verbose)
				bcpi_show_node_info(record, n, u.counter_name);
		}

		flush_objcache();
		nodes.clear();
		objects.clear();
		counters.clear();
		bcpi_free(record);
	}

	if (u.counter_name) {
		all_counters.clear();
		all_counters.insert(u.counter_name);
	}

	int objwidth = 0;
	std::vector<int> fieldwidth;
	for (auto &s : samples)
		objwidth = std::max(objwidth, (int)s.first.size());

	printf("%-*s | ", objwidth, "Functions");
	for (auto &c : all_counters)
		printf("%-*s | ", (int)c.size(), c.c_str());
	printf("\n");

	for (int i = 0; i < objwidth; i++)
		printf("-");
	for (auto &c : all_counters) {
		printf("-+-");
		for (int i = 0; i < c.size(); i++)
			printf("-");
	}
	printf("-+\n");

	std::vector<Sample> sorted_samples;
	for (auto &s : samples) {
		s.second.object = s.first;
		sorted_samples.push_back(s.second);
	}
	sort(sorted_samples.begin(), sorted_samples.end(),
	    [&u](Sample a, Sample b) {
		    if (u.counter_name)
			    return (a.counters[u.counter_name] >
				b.counters[u.counter_name]);
		    else
			    return (a.total() > b.total());
	    });

	size_t count = 0;
	for (auto &s : sorted_samples) {
		printf("%-*s | ", objwidth, s.object.c_str());
		for (auto &c : all_counters)
			if (s.counters.contains(c))
				printf("%*lu | ", (int)c.size(), s.counters[c]);
			else
				printf("%*s | ", (int)c.size(), "-");
		printf("\n");
		count++;
		if (count > u.top_n)
			break;
	}
}

void
functions_usage()
{
	fprintf(stderr,
	    "Usage: bcpiquery -c [COUNTER] [OPTIONS]\n"
	    "\nOptions:\n"
	    "\t-h -- Show this help\n"
	    "\t-n n -- Show top n functions\n"
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
functions_cmd(int argc, char **argv)
{
	int opt;
	struct util_file_filter f;
	struct util_query_parameter u;

	f.bcpi_path = BCPID_DEFAULT_PATH;
	f.filter_hostname = "";
	f.filter_begin = "";
	f.filter_end = "";

	u.counter_name = nullptr;
	u.object_name = nullptr;
	u.top_n = 25;

	while ((opt = getopt_long(
		    argc, argv, "hf:n:d:e:c:o:k:p:v", longopts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			u.counter_name = strdup(optarg);
			break;
		case 'f':
			u.files.push_back(optarg);
			break;
		case 'h':
			functions_usage();
			return (EX_OK);
		case 'n':
			u.top_n = atol(optarg);
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
		default:
			break;
		}
	}

	if (!u.object_name) {
		fprintf(stderr, "Specify a program to examine\n");
		functions_usage();
		exit(EX_USAGE);
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
