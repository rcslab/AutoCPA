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
#include <sysexits.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include "elfutil.h"

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

static std::string
find_dwarf(const std::string &objpath)
{
	std::string symbolpath;
	bool hassymroot = false;
	char *symroot;

	// Try SYMROOT first
	symroot = getenv("BCPI_SYMROOT");
	if (symroot) {
		symbolpath = symroot + objpath + ".debug";
		if (access(symbolpath.c_str(), R_OK) == 0) {
			return (symbolpath);
		}

		hassymroot = true;
	}

	// Try /full/path.debug and /usr/lib/debug/full/path.debug in SYSROOT
	symroot = getenv("BCPI_SYSROOT");
	if (symroot) {
		symbolpath = symroot;
		symbolpath += "/usr/lib/debug" + objpath + ".debug";
		if (access(symbolpath.c_str(), R_OK) == 0) {
			return (symbolpath);
		}

		symbolpath = symroot + objpath + ".debug";
		if (access(symbolpath.c_str(), R_OK) == 0) {
			return (symbolpath);
		}

		hassymroot = true;
	}

	// Don't search local machine if either is defined
	if (hassymroot) {
		fprintf(stderr,
		    "Cannot find debugging symbols for %s in SYSROOT or SYMROOT!\n",
		    objpath.c_str());
		exit(EX_OSFILE);
	}

	symbolpath = "/usr/lib/debug" + objpath + ".debug";
	if (access(symbolpath.c_str(), R_OK) == 0) {
		return (symbolpath);
	}

	symbolpath = objpath + ".debug";
	if (access(symbolpath.c_str(), R_OK) == 0) {
		return (symbolpath);
	}

	return (objpath);
}

static std::string
find_object(const std::string &objpath)
{
	std::string path;
	char *sysroot = getenv("BCPI_SYSROOT");

	if (!sysroot)
		return (objpath);

	path = sysroot + objpath;

	if (access(path.c_str(), R_OK) == 0) {
		return (path);
	}

	fprintf(stderr, "Cannot find object %s in SYSROOT!\n", path.c_str());
	exit(EX_OSFILE);
}

static struct section *
load_sections(Elf *e, size_t shnum)
{
	struct section *sl;
	size_t shstrndx, ndx;
	Elf_Scn *scn;
	GElf_Shdr sh;
	const char *name;
	int elferr;
	struct section *s;

	sl = (struct section *)calloc(shnum, sizeof(*sl));
	if (sl == NULL)
		err(EXIT_FAILURE, "calloc failed");

	/* Get the index of .shstrtab section. */
	if (!elf_getshstrndx(e, &shstrndx))
		errx(EXIT_FAILURE, "elf_getshstrndx() failed: %s.",
		    elf_errmsg(-1));
	if ((scn = elf_getscn(e, 0)) == NULL) {
		free(sl);
		return (NULL);
	}

	(void)elf_errno();

	int i = 0;
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

		i++;
	} while ((scn = elf_nextscn(e, scn)) != NULL);

	if ((unsigned int)i != shnum) {
		printf("error i = %d, shnum = %zu\n", i, shnum);
	}

	elferr = elf_errno();
	if (elferr != 0)
		warnx("elf_nextscn failed: %s", elf_errmsg(elferr));

	return (sl);
}

static uint64_t
change_offset(Elf *e, uint64_t addr)
{
	size_t shnum;
	struct section *s;

	if (!elf_getshnum(e, &shnum))
		errx(EXIT_FAILURE, " elf_getshnum() failed : %s. ",
		    elf_errmsg(-1));
	if (shnum == 0) {
		printf("\nThere are no sections in this file.\n");
		return (0);
	}

	s = load_sections(e, shnum);
	if (!s) {
		warnx("load_sections returned null: failed to load sections!");
		return (0);
	}

	for (size_t i = 0; i < shnum; i++) {
		if ((s[i].off <= addr) && (addr < s[i].off + s[i].sz)) {
			/*uint64_t rval = (addr - s[i].off) + s[i].addr;
			printf("%lx %lx %lx = %lx\n", addr, s[i].off, s[i].addr,
			rval);*/
			return (addr - s[i].off) + s[i].addr;
		}
	}

	return (0);
}

int
search_addr(
    const std::string &objpath, Dwarf_Addr address, uint64_t *revised_addr)
{
	int fd = -1;
	Elf *e;
	std::string path = find_object(objpath);

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE,
		    "ELF library initialization"
		    "failed : %s ",
		    elf_errmsg(-1));

	if ((fd = open(path.c_str(), O_RDONLY)) < 0) {
		perror("open");
		std::cerr << "error in fd_elf " << objpath << std::endl;
		return (1);
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed : %s.", elf_errmsg(-1));

	*revised_addr = change_offset(e, address);

	elf_end(e);
	close(fd);

	return (0);
}

/*
 * List a function if it's in the given DIE.
 */
static void
list_func_in_die(
    Dwarf_Die the_die, Dwarf_Addr address, std::string *diename, int *valid)
{
	int rc;
	char *die_name = 0;
	Dwarf_Error err;
	Dwarf_Half tag;
	Dwarf_Addr lowpc, highpc;

	if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK)
		std::cout << "Error in dwarf_tag" << std::endl;

	/* Only interested in subprogram DIEs here */
	if (tag != DW_TAG_subprogram)
		return;

	/* Grab the DIEs attributes for display */
	if (dwarf_lowpc(the_die, &lowpc, &err) != DW_DLV_OK) {
		return;
	}

	if (dwarf_highpc(the_die, &highpc, &err) != DW_DLV_OK) {
		return;
	}

	/*
	 * Retrieving the diename after comparing the PC is about 10% faster
	 */

	if ((lowpc >= address) || (address <= highpc)) {
		rc = dwarf_diename(the_die, &die_name, &err);
		if (rc == DW_DLV_ERROR)
			std::cout << "Error in dwarf_diename" << std::endl;
		else if (rc == DW_DLV_NO_ENTRY)
			return;

		*diename = die_name;
		*valid = 1;
	}
}

/*
 * List all the functions from the file represented by the given descriptor.
 */
static void
find_func(Dwarf_Debug dbg, Dwarf_Addr addr, std::string *namedie, int *valid)
{
	Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
	Dwarf_Half version_stamp, address_size;
	Dwarf_Error err;
	Dwarf_Die no_die = 0, cu_die, child_die, new_die;
	Dwarf_Addr lowpc, highpc;

	while (1) {
		int temp;

		/* Find a compilation unit header */
		temp = dwarf_next_cu_header(dbg, &cu_header_length,
		    &version_stamp, &abbrev_offset, &address_size,
		    &next_cu_header, &err);
		if (temp == DW_DLV_ERROR)
			std::cout << "Error reading DWARF cu header"
				  << std::endl;
		if (temp == DW_DLV_NO_ENTRY) {
			break;
		}

		/* Find the CU DIE of current CU */
		if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR)
			std::cout << "Error getting sibling of CU" << std::endl;

		/* Grab the DIEs attributes for display */
		if (dwarf_lowpc(cu_die, &lowpc, &err) != DW_DLV_OK) {
			dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
			continue;
		}

		if (dwarf_highpc(cu_die, &highpc, &err) != DW_DLV_OK) {
			dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
			continue;
		}

		if ((lowpc > addr) || (addr > highpc)) {
			dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
			continue;
		}

		/* Expect the CU DIE to have children- children at level 1 */
		if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR)
			std::cout << "Error getting child of CU DIE"
				  << std::endl;

		dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);

		/* Now go over all children DIEs */
		while (1) {
			int rc;

			/*
			 * XXX: Should return here but it seems we need to
			 * iterate all CUs anyways?
			 */
			*valid = 0;
			list_func_in_die(child_die, addr, namedie, valid);
			if (*valid) {
				break;
			}

			rc = dwarf_siblingof(dbg, child_die, &new_die, &err);
			if (rc == DW_DLV_ERROR)
				std::cout << "Error getting sibling of DIE"
					  << std::endl;
			else if (rc == DW_DLV_NO_ENTRY)
				break; /* done */

			dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
			child_die = new_die;
		}

		dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
	}
}

struct ObjectCache {
	std::string dwarfpath;
	std::string binpath;
	int fd;
	Elf *e;
	Dwarf_Debug dbg;
	int bfd;
	Elf *be; // Original ELF needed for address conversion calculations
};

static std::unordered_map<std::string, ObjectCache> objcache;

static ObjectCache *
lookup_object(std::string object)
{
	ObjectCache obj;
	Dwarf_Error derr;

	if (!objcache.contains(object)) {
		obj.dwarfpath = find_dwarf(object);
		obj.binpath = find_object(object);

		if (elf_version(EV_CURRENT) == EV_NONE)
			errx(EX_SOFTWARE, "libelf version is too old");

		if ((obj.fd = open(obj.dwarfpath.c_str(), O_RDONLY)) < 0)
			err(EX_NOINPUT, "Failed to open dwarf object\n");

		if ((obj.e = elf_begin(obj.fd, ELF_C_READ, NULL)) == NULL)
			errx(EX_SOFTWARE, "elf_begin() failed : %s",
			    elf_errmsg(-1));

		if (dwarf_init(obj.fd, DW_DLC_READ, 0, 0, &obj.dbg, &derr) !=
		    DW_DLV_OK)
			err(EX_SOFTWARE, "dwarf_init failed");

		if ((obj.bfd = open(obj.binpath.c_str(), O_RDONLY)) < 0)
			err(EX_NOINPUT, "Failed to open original binary");

		if ((obj.be = elf_begin(obj.bfd, ELF_C_READ, NULL)) == NULL)
			errx(EX_SOFTWARE, "elf_begin() failed : %s",
			    elf_errmsg(-1));

		objcache[object] = obj;
	}

	return (&objcache[object]);
}

void
flush_objcache()
{
	for (auto &o : objcache) {
		if (o.second.e) {
			dwarf_finish(o.second.dbg, nullptr);
			elf_end(o.second.e);
		}
		if (o.second.fd != -1)
			close(o.second.fd);
		if (o.second.be)
			elf_end(o.second.be);
		if (o.second.bfd != -1)
			close(o.second.bfd);
	}
	objcache.clear();
}

std::string
search_symbol(const std::string &objpath, Dwarf_Addr addr)
{
	ObjectCache *obj = lookup_object(objpath);
	uint64_t pc;
	std::string src_file, namedie;
	int valid = 0;

	pc = change_offset(obj->be, addr);

	find_func(obj->dbg, pc, &namedie, &valid);

	if (valid) {
		return (namedie);
	} else {
		std::stringstream s;
		s << "0x" << std::hex << pc;
		return (s.str());
	}
}
