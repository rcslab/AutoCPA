#include <string>
#include <dwarf.h>
#include <libdwarf.h>

struct section;

uint64_t change_offset(uint64_t num, Elf *e);

struct section* load_sections(Elf *e, size_t shnum);

uint64_t calculate_nums(uint64_t address, uint64_t offset, uint64_t num);

void list_func_in_die(Dwarf_Debug dgb, Dwarf_Die the_die,Dwarf_Addr address, Dwarf_Addr *low_pc, Dwarf_Addr *high_pc, std::string *diename, int *valid);

void list_funcs_in_file(Dwarf_Debug dbg, Dwarf_Addr address, Dwarf_Addr *low, Dwarf_Addr *high, std::string *namedie, int *valid);

int search_addr(const char* progname, Dwarf_Addr address, uint64_t *revised_addr);


