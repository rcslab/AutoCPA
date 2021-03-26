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

#define DECL_COMMAND(_x)                      \
	int _x##_cmd(int argc, char *argv[]); \
	void _x##_usage();

DECL_COMMAND(check);
DECL_COMMAND(dump);
DECL_COMMAND(extract);
DECL_COMMAND(functions);
DECL_COMMAND(help);
DECL_COMMAND(programs);

struct command {
	std::string name;
	std::string desc;
	int (*cmd)(int argc, char *argv[]);
	void (*usage)(void);
};

static std::vector<command> commands = {
	{ "check", "Validate bcpi dumps", check_cmd, check_usage },
	{ "dump", "Dump bcpi internal structures for debugging", dump_cmd,
	    dump_usage },
	{ "extract", "Extract address info for analysis", extract_cmd,
	    extract_usage },
	{ "functions", "Show top functions", functions_cmd, functions_usage },
	{ "help", "Show display help", help_cmd, help_usage },
	{ "programs", "Show top programs and libraries", programs_cmd,
	    programs_usage },
};

static command *
find_command(const std::string &cmd)
{
	for (auto &c : commands) {
		if (cmd == c.name)
			return &c;
	}

	return (nullptr);
}

int
help_cmd(int argc, char *argv[])
{
	if (argc > 2) {
		command *c = find_command(argv[2]);
		if (c) {
			c->usage();
			return (EX_OK);
		}
		fprintf(stderr, "Unknown command '%s'\n", argv[2]);
	}

	fprintf(stderr, "Usage: bcpiquery COMMAND ...\n");
	fprintf(stderr, "\nCommands:\n");
	for (auto &c : commands)
		fprintf(stderr, "\t%-10s %s\n", c.name.c_str(), c.desc.c_str());

	fprintf(stderr, "\nEnvironment Variables:\n");
	fprintf(stderr,
	    "\tBCPI_SYSROOT -- Sysroot path for binaries and symbols\n");
	fprintf(stderr, "\tBCPI_SYMPATH -- Absolute path to symbols\n");

	return ((argc > 2) ? EX_USAGE : EX_OK);
}

void
help_usage()
{
	help_cmd(0, nullptr);
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		help_usage();
		return (EX_OK);
	}

	command *c = find_command(argv[1]);
	if (c) {
		return (c->cmd(argc, argv));
	}

	fprintf(stderr, "Unknown command '%s'\n", argv[1]);
	help_usage();

	return (EX_USAGE);
}
