#include <sys/types.h>
#include <sys/stat.h>

#include <dwarf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "find_an_address.h"

struct section {
	const char *name; /* section name */
	Elf_Scn *scn;	  /* section scn */
	uint64_t off;	  /* section offset */
	uint64_t sz;	  /* section size */
	uint64_t entsize; /* section entsize */
	uint64_t align;	  /* section alignment */
	uint64_t type;	  /* section type */
	uint64_t flags;	  /* section flags */
	uint64_t addr;	  /* section virtual addr */
	uint32_t link;	  /* section link ndx */
	uint32_t info;	  /* section info ndx */
};

// need a function  to process the new offset based on the two numbers
uint64_t
calculate_nums(uint64_t address, uint64_t offset, uint64_t num)
{
	uint64_t temp, finaladdr;
	temp = num - offset;
	finaladdr = temp + address;
	return finaladdr;
}

// loading sections
struct section *
load_sections(Elf *e, size_t shnum)
{
	struct section *sl = NULL;
	size_t shstrndx, ndx;
	Elf_Scn *scn;
	GElf_Shdr sh;
	const char *name;
	int elferr;
	struct section *s;

	if (sl != NULL)
		free(sl);
	if ((sl = (struct section *)calloc(shnum, sizeof(*sl))) ==
	    NULL) // calloc also set the allocated mem to zero
		err(EXIT_FAILURE, "calloc failed");
	/* Get the index of .shstrtab section. */
	if (!elf_getshstrndx(e, &shstrndx))
		errx(EXIT_FAILURE, "elf_getshstrndx() failed: %s.",
		    elf_errmsg(-1));
	if ((scn = elf_getscn(e, 0)) == NULL)
		return NULL;

	(void)elf_errno();

	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("gelf_getshdr failed: %s", elf_errmsg(-1));
			(void)elf_errno();
			continue;
		}

		if ((name = elf_strptr(e, shstrndx, sh.sh_name)) == NULL) {
			(void)elf_errno();
			name = "<no-name>";
		}

		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF) {
			if ((elferr = elf_errno()) != 0) {
				warnx("elf_ndxscn failed: %s",
				    elf_errmsg(elferr));
				continue;
			}
		}

		if (ndx >= shnum) {
			warnx("section index of '%s' out of range", name);
			continue;
		}

		if (sh.sh_link >= shnum)
			warnx("section link %llu of '%s' out of range",
			    (unsigned long long)sh.sh_link, name);

		s = &sl[ndx];
		s->name = name;
		s->scn = scn;
		s->sz = sh.sh_size;
		s->entsize = sh.sh_entsize;
		s->type = sh.sh_type;
		s->link = sh.sh_link;
		s->addr = sh.sh_addr;
		s->off = sh.sh_offset;
	} while ((scn = elf_nextscn(e, scn)) != NULL);
	elferr = elf_errno();
	if (elferr != 0)
		warnx("elf_nextscn failed: %s", elf_errmsg(elferr));
	return sl;
}

uint64_t
change_offset(uint64_t num, Elf *e)
{
	uintmax_t newnum, address, dwarfoff;
	struct section *s, *snext, *sl = NULL;
	int i;
	size_t shnum;

	if (!elf_getshnum(e, &shnum))
		errx(EXIT_FAILURE, " elf_getshnum() failed : %s. ",
		    elf_errmsg(-1));
	if (shnum == 0) {
		printf("\nThere are no sections in this file.\n");
		// return;
	}
	sl = load_sections(e, shnum);

	for (i = 0; (size_t)i < shnum - 1; i++) {
		s = &sl[i]; // current s
		snext = &sl[i + 1];
		if ((s->off <= num) && (num < snext->off)) {
			newnum = s->off;
			address = s->addr;
		} // here we dont consider the case that num corresponds to the
		  // last section offset
	}

	dwarfoff = calculate_nums(address, newnum, num);

	return dwarfoff;
}

int
search_addr(const char *progname, Dwarf_Addr address, uint64_t *revised_addr)
{
	int fd = -1;
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE,
		    "ELF library initialization"
		    "failed : %s ",
		    elf_errmsg(-1));

	if ((fd = open(progname, O_RDONLY)) < 0) {
		perror("open");
		std::cerr << "error in fd_elf " << progname << std::endl;
		return 1;
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed : %s.", elf_errmsg(-1));

	*revised_addr = change_offset(address, e);

	elf_end(e);
	close(fd);

	return 0;
}
