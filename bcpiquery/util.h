
#pragma once

struct util_file_filter {
	bool verbose;
	std::string bcpi_path;
	std::string filter_hostname;
	std::string filter_begin;
	std::string filter_end;
};

std::vector<std::string> util_filter_files(struct util_file_filter *u);
