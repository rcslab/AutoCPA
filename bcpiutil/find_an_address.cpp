
#include <err.h>
#include <libelf.h>
#include <gelf.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <libgen.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dwarf.h>
#include <libdwarf.h>


#include <iostream>


#include "find_an_address.h"

using namespace std;

struct section {
  const char  *name;    /* section name */
  Elf_Scn    *scn;    /* section scn */
  uint64_t   off;    /* section offset */
  uint64_t   sz;    /* section size */
  uint64_t   entsize;  /* section entsize */
  uint64_t   align;    /* section alignment */
  uint64_t   type;    /* section type */
  uint64_t   flags;    /* section flags */
  uint64_t   addr;    /* section virtual addr */
  uint32_t   link;    /* section link ndx */
  uint32_t   info;    /* section info ndx */
};
//need a function  to process the new offset based on the two numbers
uint64_t calculate_nums(uint64_t address, uint64_t offset, uint64_t num){

  uint64_t temp, finaladdr;
  temp = num - offset;
  finaladdr= temp + address;
  return finaladdr;
}

struct section* load_sections(Elf *e, size_t shnum) {

  struct section* sl=NULL;
  size_t     shstrndx,ndx;
  Elf_Scn    *scn;
  GElf_Shdr   sh;
  const char  *name;
  int     elferr;
  struct section  *s;
  if (sl != NULL)
    free(sl);
  if ((sl =(struct section *) calloc(shnum, sizeof(*sl))) == NULL)//calloc also set the allocated mem to zero
    err(EXIT_FAILURE, "calloc failed");
  /* Get the index of .shstrtab section. */
  if (!elf_getshstrndx(e, &shstrndx))
    errx (EXIT_FAILURE , "elf_getshstrndx() failed: %s." ,
          elf_errmsg (-1));
  if ((scn = elf_getscn(e, 0)) == NULL)
    return NULL;

  (void) elf_errno();

  do {
    if (gelf_getshdr(scn, &sh) == NULL) {
      warnx("gelf_getshdr failed: %s", elf_errmsg(-1));
      (void) elf_errno();
      continue;
    }

    if ((name = elf_strptr(e, shstrndx, sh.sh_name)) == NULL) {
      (void) elf_errno();
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

uint64_t change_offset (uint64_t num, Elf *e){

  uintmax_t newnum, address, dwarfoff ;
  struct section	*s, *snext, *sl=NULL;
  int i;
  size_t shnum;

  if (!elf_getshnum(e, &shnum))
      errx (EXIT_FAILURE, " elf_getshnum() failed : %s. ",
          elf_errmsg(-1));
  if (shnum == 0) {
      printf("\nThere are no sections in this file.\n");
       // return;
    }
  sl=load_sections(e, shnum);

  for (i = 0; (size_t)i < shnum-1; i++) {

  		s = &sl[i]; //current s
      snext = &sl[i+1];
      if ((s->off <= num) && (num < snext->off )) {
          newnum= s->off;
          address= s->addr;
      }//here we dont consider the case that num corresponds to the last section offset
  	}
  dwarfoff=calculate_nums(address, newnum, num);
  return dwarfoff;
}

/* List a function if it's in the given DIE.
*/
void list_func_in_die(Dwarf_Debug dgb, Dwarf_Die the_die,Dwarf_Addr address, Dwarf_Addr *low_pc, Dwarf_Addr *high_pc, string *diename, int *valid)
{
    char* die_name = 0;
    const char* tag_name = 0;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute* attrs;
    Dwarf_Addr lowpc, highpc;
    Dwarf_Signed attrcount, i;
    int rc = dwarf_diename(the_die, &die_name, &err);

    if (rc == DW_DLV_ERROR)
        cout<<"Error in dwarf_diename"<<endl;
    else if (rc == DW_DLV_NO_ENTRY)
        return;

    if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK)
        cout<<"Error in dwarf_tag"<<endl;

    /* Only interested in subprogram DIEs here */
    if (tag != DW_TAG_subprogram)
        return;

    if (dwarf_get_TAG_name(tag, &tag_name) != DW_DLV_OK)
        cout<<"Error in dwarf_get_TAG_name"<<endl;

   // printf("DW_TAG_subprogram: '%s'\n", die_name);

    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
        cout<<"Error in dwarf_attlist"<<endl;

    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
            cout<<"Error in dwarf_whatattr"<<endl;

        /* We only take some of the attributes for display here.
        ** More can be picked with appropriate tag constants.
        */
        if (attrcode == DW_AT_low_pc)
            dwarf_formaddr(attrs[i], &lowpc, 0);
        else if (attrcode == DW_AT_high_pc)
            dwarf_formaddr(attrs[i], &highpc, 0);
    }

    if ((lowpc==address)||(address==highpc)){
        //chon man fght esme function ha ro mikham dar nahayat, pas sharte if
        //ro age fght address == lowpc ya address ==highpc bezaram okeye
        *low_pc=lowpc;
        *high_pc=highpc;
        *diename=die_name;
        *valid=0;
        //printf("DW_TAG_subprogram: '%s'\n", die_name);
        //printf("low pc  : 0x%08llx\n",(unsigned long long) lowpc);
        //printf("high pc : 0x%08llx\n",(unsigned long long) highpc);


    }
}


/* List all the functions from the file represented by the given descriptor.
*/
void list_funcs_in_file(Dwarf_Debug dbg, Dwarf_Addr address, Dwarf_Addr *low, Dwarf_Addr *high, string *namedie, int *valid)
{
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;


    while (1){
    /* Find a compilation unit header */
       // cerr<<"haha"<<endl;
        int temp;
        temp= dwarf_next_cu_header(
                dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err);
         if (temp==DW_DLV_ERROR)
             cout<<"Error reading DWARF cu header"<<endl;
         if (temp==DW_DLV_NO_ENTRY){
           // cerr<<"here we are at the end of all CUs"<<endl;
             break;}

         /* Find the CU DIE of current CU */
         if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR)
             cout<<"Error getting sibling of CU"<<endl;

         /* Expect the CU DIE to have children- children at level 1 */
         if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR)
              cout<<"Error getting child of CU DIE"<<endl;

    /* Now go over all children DIEs */
    while (1) {
        int rc;

        list_func_in_die(dbg, child_die, address, low, high, namedie, valid);
        rc = dwarf_siblingof(dbg, child_die, &child_die, &err);

        if (rc == DW_DLV_ERROR)
            cout<<"Error getting sibling of DIE"<<endl;
        else if (rc == DW_DLV_NO_ENTRY)
            break; /* done */
    }
    }
}

static void dump_dw_line_sfile(Dwarf_Debug dbg, Dwarf_Addr address, Dwarf_Unsigned *line_num, string *src_file){

	Dwarf_Die die;
	Dwarf_Line *linebuf, ln;
	Dwarf_Addr lineaddr;
	Dwarf_Signed linecount, srccount;
	Dwarf_Unsigned lineno, fn;
	Dwarf_Error de;
	const char *dir, *file;
	char **srcfiles;
	int i, ret;

	while ((ret = dwarf_next_cu_header(dbg, NULL, NULL, NULL, NULL,
	    NULL, &de)) == DW_DLV_OK) {
		if (dwarf_siblingof(dbg, NULL, &die, &de) != DW_DLV_OK)
			continue;
		if (dwarf_attrval_string(die, DW_AT_name, &file, &de) !=
		    DW_DLV_OK)
			file = NULL;
		if (dwarf_attrval_string(die, DW_AT_comp_dir, &dir, &de) !=
		    DW_DLV_OK)
			dir = NULL;
		//printf("%-37s %11s   %s\n", "Filename", "Line Number",
		  //  "Starting Address");
		if (dwarf_srclines(die, &linebuf, &linecount, &de) != DW_DLV_OK)
			continue;
		if (dwarf_srcfiles(die, &srcfiles, &srccount, &de) != DW_DLV_OK)
			continue;
		for (i = 0; i < linecount; i++) {
			ln = linebuf[i];
			if (dwarf_line_srcfileno(ln, &fn, &de) != DW_DLV_OK)
				continue;
			if (dwarf_lineno(ln, &lineno, &de) != DW_DLV_OK)
				continue;
			if (dwarf_lineaddr(ln, &lineaddr, &de) != DW_DLV_OK)
				continue;
      if(address==lineaddr){
        *line_num=lineno;
        //printf("%-37s", basename(srcfiles[fn-1]));
        *src_file=basename(srcfiles[fn - 1]);
      }
			//printf("%-37s %11ju %#18jx\n",
			  //  basename(srcfiles[fn - 1]), (uintmax_t) lineno,
			    //(uintmax_t) lineaddr);
		}
	}
}

int search_symbol(const char* progname, Dwarf_Addr address, string *dwarf_data)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Error err;
    int fd = -1;
    Dwarf_Arange *aranges;
    Dwarf_Signed cnt;
    Dwarf_Error de;
    Elf *e;
    uint64_t pc;
    Dwarf_Unsigned line_num;
    string src_file, namedie, line_numstr;
    Dwarf_Addr low, high;
    int valid=1;

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx (EXIT_FAILURE, "ELF library initialization"
                "failed : %s ", elf_errmsg(-1));

    if ((fd = open(progname, O_RDONLY)) < 0) {
        perror("open");
        cerr<<"error in fd"<<endl;
        return 1;
    }

    if ((e = elf_begin(fd , ELF_C_READ, NULL)) == NULL)
         errx (EXIT_FAILURE , "elf_begin() failed : %s." ,
               elf_errmsg (-1));

    if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF initialization\n");
        return 1;
    }

    pc=change_offset(address, e);

    list_funcs_in_file(dbg, pc, &low, &high, &namedie, &valid);

    dump_dw_line_sfile(dbg, pc, &line_num, &src_file);

    line_numstr = to_string(line_num);
    *dwarf_data="src file name: "+src_file+" line num: "+line_numstr;
    if (valid==0){
      *dwarf_data = *dwarf_data +" name of subprogram: "+ namedie;
    }
    //cout<<*dwarf_data<<endl;
    if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF finalization\n");
        return 1;
    }

    elf_end(e);
    close(fd);

    return 0;
}
