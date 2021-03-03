
#ifndef __FIND_AN_ADDRESS_H__
#define __FIND_AN_ADDRESS_H__

uint64_t change_offset(uint64_t num, Elf *e);
struct section *load_sections(Elf *e, size_t shnum);
uint64_t calculate_nums(uint64_t address, uint64_t offset, uint64_t num);
int search_addr(
    const char *progname, Dwarf_Addr address, uint64_t *revised_addr);

#endif /* __ FIND_AN_ADDRESS_H__ */
