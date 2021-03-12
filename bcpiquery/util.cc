
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <filesystem>
#include <string>

#include "../libbcpi/libbcpi.h"
#include "util.h"

#define BCPI_UTIL_SYSTEM_DEBUG_INFO_PATH "/usr/lib/debug"

std::vector<std::string>
util_filter_files(struct util_file_filter *u)
{
	time_t begin_time, end_time;
	struct tm t {
	};
	std::vector<std::string> files;

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

		files.push_back(p.path());
		if (u->verbose)
			printf("Found match %s\n", p.path().c_str());
	}

	printf("Querying %lu files\n", files.size());

	return (files);
}
