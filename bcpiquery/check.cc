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

int
check_file(const std::string &f)
{
	int fd;
	off_t filesz;
	void *buf;

	if ((fd = open(f.c_str(), O_RDONLY)) == -1) {
		perror("open");
		return (1);
	}

	filesz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	buf = mmap(0, filesz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return (1);
	}

	uint32_t hash = bcpi_crc32(buf, filesz);

	if (munmap(buf, filesz) == -1) {
		perror("munmap");
	}

	if (close(fd) == -1) {
		perror("close");
	}

	fprintf(stdout, "%s %x\n", f.c_str(), hash);

	return (0);
}

void
check_usage()
{
	fprintf(stderr,
	    "Usage: bcpiquery checksum [OPTIONS]\n"
	    "\nOptions:\n"
	    "\t-h -- Show this help\n"
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
check_cmd(int argc, char **argv)
{
	int opt;
	int errors = 0;
	std::vector<std::string> files;
	struct util_file_filter f;

	f.verbose = false;
	f.bcpi_path = BCPID_DEFAULT_PATH;
	f.filter_hostname = "";
	f.filter_begin = "";
	f.filter_end = "";

	while ((opt = getopt_long(argc, argv, "hf:", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			check_usage();
			break;
		case 'f':
			files.push_back(optarg);
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

	if (files.size() == 0) {
		files = util_filter_files(&f);
	}

	if (files.size() == 0) {
		fprintf(stderr, "No file names specified or found in '%s'\n",
		    f.bcpi_path.c_str());
		return (EX_USAGE);
	}

	for (auto &f : files) {
		errors += check_file(f);
	}
	if (errors) {
		fprintf(stderr, "Found %d errors\n", errors);
		return (EX_DATAERR);
	}

	return (EX_OK);
}
