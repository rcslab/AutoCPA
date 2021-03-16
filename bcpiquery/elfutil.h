
#ifndef _BCPI_ELFUTIL_H_
#define _BCPI_ELFUTIL_H_

void flush_objcache();
int search_addr(
    const std::string &objpath, Dwarf_Addr address, uint64_t *revised_addr);
std::string search_symbol(const std::string &objpath, Dwarf_Addr addr);

#endif /* _BCPI_ELFUTIL_H_ */
