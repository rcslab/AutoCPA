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

#include "../libbcpi/libbcpi.h"
#include "elfutil.h"
#include "util.h"

struct util_query_parameter {
	std::vector<std::string> files;
};

/*
 * Do not visit the same node twice; do not go too deep when traversing.
 */

static void
util_process(util_query_parameter &u)
{
	std::vector<bcpi_node *> nodes;

	for (size_t i = 0; i < u.files.size(); i++) {
		bcpi_record record;

		if (bcpi_load_file(u.files[i].c_str(), &record) < 0) {
			fprintf(stderr, "Failed to load bcpi file '%s'\n",
			    u.files[i].c_str());
		}

		std::cout << "File " << u.files[i] << std::endl;
		bcpi_print_summary(record);
		bcpi_dump_nodes(record);
	}
}

void
dump_usage()
{
	fprintf(stderr,
	    "Usage: bcpiquery dump -c [COUNTER] [OPTIONS]\n"
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
	{ NULL, 0, NULL, 0 },
};

int
dump_cmd(int argc, char **argv)
{
	int opt;
	struct util_file_filter f;
	struct util_query_parameter u;

	f.bcpi_path = BCPID_DEFAULT_PATH;
	f.filter_hostname = "";
	f.filter_begin = "";
	f.filter_end = "";

	while ((opt = getopt_long(
		    argc, argv, "hf:n:d:e:c:o:k:p:v", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			dump_usage();
			return (EX_OK);
		case 'f':
			u.files.push_back(optarg);
			break;
		case 'p':
			f.bcpi_path = optarg;
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
