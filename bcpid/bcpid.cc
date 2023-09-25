#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/utsname.h>

#include <err.h>
#include <fcntl.h>
#include <kenv.h>
#include <libprocstat.h>
#include <pmc.h>
#include <pmclog.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../libbcpi/libbcpi.h"
#include "debug.h"

// Special kqueue identifier for periodic timer
#define BCPID_TIMER_MAGIC 0xbcd1d

// Interval for running periodic tasks (garbage collect samples, for example)
#define BCPID_INTERVAL 1000

// Macro for doing 8 byte alignment. Unused currently
#define BCPID_ROUND_UP_8(x) (((x) + (7)) & (~7))

// Upper bound for number of event types that PMCLOG interface delivers
// Shouldn't require modification
#define BCPID_MAX_NUM_PMCLOG_EVENTS 32

// Max number of CPUs supported
#define BCPID_MAX_CPU 128

// A hack to know the beginning of kernel inside address space
// of a process, since this information is not present in
// procstat API.
#define BCPID_KERN_BASE 0x7fff00000000UL

// A writable directory to place compressed sample data
#define BCPID_OUTPUT_DIRECTORY "/var/tmp"

// Force sample data to be saved on disk and
// purged from main memory when number of call graph
// edges exceeds this number
#define BCPID_EDGE_GC_THRESHOLD 100000

// Force sample data to be saved on disk and
// purged from main memory when number of call graph
// nodes exceeds this number
#define BCPID_NODE_GC_THRESHOLD 100000

// For performance reasons, hashes of object files are cached
// To prevent cache from growing unbounded, it is cleared
// when hashes of this many object files are cached
#define BCPID_OBJECT_HASH_GC_THRESHOLD 2000

// Default sampling interval
#define BCPID_DEFAULT_COUNT 65536

struct bcpid;
typedef void (*bcpid_event_handler)(bcpid *b, const struct pmclog_ev *);

// Keep track of event received from PMCLOG interface
struct bcpid_pmclog_event {
	bool is_valid;
	const char *name;
	uint64_t num_fire;
	bcpid_event_handler handler;
};

// Store ID of PMC counters allocated per CPU.
struct bcpid_pmc_cpu {
	pmc_id_t pmcs[BCPI_MAX_NUM_COUNTER];
};

// Keep track of counters allocated
struct bcpid_pmc_counter {
	bool is_valid;
	uint64_t hits;
	std::string name;
	std::string label;
	int sample_rate;
	int sample_ratio;
	bool callchain;
	bool usercallchain;
};

// Represent a distinct object file (executable or dynamic library)
struct bcpid_object {
	std::string path;
	struct timespec last_modified;
	bcpi_hash hash;

	std::unordered_map<uint64_t, struct bcpid_pc_node *> node_map;

	// Used during compression
	int tmp_archive_object_index;
};

// Represent a mapping inside a process
struct bcpid_program_mapping {
	uint64_t start;
	uint64_t end;
	// offset of this section in the corresponding ELF file
	uint64_t file_offset;
	uint32_t protection;
	bcpid_object *obj;
};

// A routine to sort mappings according to their beginning address
// to facilitate binary search
// undefined behavior when mapping overlaps
bool
bcpid_program_mapping_sort(const struct bcpid_program_mapping &me,
    const struct bcpid_program_mapping &other)
{
	return me.start < other.start;
}

// Represent a distinct process
struct bcpid_program {
	int pid;
	std::vector<bcpid_program_mapping> mappings;
};

struct bcpid_pc_node;

// An edge in a call chain graph
struct bcpid_pc_edge {
	uint64_t hits[BCPI_MAX_NUM_COUNTER];
	bcpid_pc_node *from;
	bcpid_pc_node *to;
};

// A vertex in a call chain graph
struct bcpid_pc_node {
	uint64_t value;
	uint64_t flag;
	bcpid_object *obj;
	uint64_t end_ctr[BCPI_MAX_NUM_COUNTER];

	// Map downstream node to the edge between nodes, where
	// counter numbers are actually stored
	std::unordered_map<bcpid_pc_node *, bcpid_pc_edge> incoming_edge_map;

	// Used during compression
	int tmp_archive_node_index;
};

// various debug counters
enum bcpid_debug_counter {
	bcpid_debug_empty_mapin_name,
	bcpid_debug_empty_mapping_pc,
	bcpid_debug_pc_before_mapping,
	bcpid_debug_pc_after_mapping,
	bcpid_debug_getprocs_fail,
	bcpid_debug_getvmmap_fail,
	bcpid_debug_callchain_self_fire,
	bcpid_debug_callchain_proc_init_fail,
	bcpid_debug_callchain_counter_gone,
	bcpid_debug_callchain_pc_skip,
	bcpid_debug_counter_max,
};

/*
 * Kernel objects are announced only once
 * by PMCLOG during program start up,
 * therefore they need to be cached to
 * facilitate garbage collection
 */
struct bcpid_kernel_object {
	std::string path;
	uint64_t start;
};

// Number of kqueue events batched in a
// single kqueue call
#define BCPID_KEVENT_MAX_BATCH_SIZE 16

// A cache entry for an object file
struct bcpid_hash_cache {
	struct timespec last_modified;
	bcpi_hash hash;
};

struct bcpid_statistics {
	int num_object;
	int num_program;
	int num_node;
	int num_edge;
	int num_object_hash;
};

struct bcpid {
	int num_pmclog_event;
	int num_cpu;

	int selfpid;
	struct procstat *procstat;
	void *pmclog_handle;

	int pipefd[2];
	int non_block_pipefd[2];
	int kqueue_fd;
	int g_quit;

	pthread_t pmclog_forward_thr;

	/* Whether this is the first time
	 * that we received call chain event from PMCLOG or not.
	 * Used for kernel object handling. (See replay_kernel_objects)
	 */
	bool first_callchain;

	uint64_t debug_counter[bcpid_debug_counter_max];

	bcpid_pmc_counter pmc_ctrs[BCPI_MAX_NUM_COUNTER];
	bcpid_pmc_cpu pmc_cpus[BCPID_MAX_CPU];
	bcpid_pmclog_event pmclog_events[BCPID_MAX_NUM_PMCLOG_EVENTS];

	int kevent_in_size;
	int kevent_out_size;
	struct kevent kevent_in_batch[BCPID_KEVENT_MAX_BATCH_SIZE];
	struct kevent kevent_out_batch[BCPID_KEVENT_MAX_BATCH_SIZE];

	std::unordered_map<pmc_id_t, bcpid_pmc_counter *> pmcid_to_counter;
	std::unordered_map<int, bcpid_program *> pid_to_program;
	std::unordered_map<std::string, bcpid_object *> path_to_object;

	std::string config_file;
	int default_count;
	std::string default_pmc;
	std::string default_output_dir;
	bool pmc_override;
	int64_t target_cpu;

	bool adaptive;

	std::vector<bcpid_kernel_object> kernel_objects;

	int num_node;
	int num_edge;

	std::unordered_map<std::string, bcpid_hash_cache> object_hash_cache;

	int node_collect_threshold;
	int edge_collect_threshold;
	int object_hash_collect_threshold;
};

static bool foreground = false;
static int verbose = 0;

static const char *g_bcpid_pmclog_name[] = { "PMCLOG_TYPE_PADDING",
	"PMCLOG_TYPE_CLOSEMSG", "PMCLOG_TYPE_DROPNOTIFY",
	"PMCLOG_TYPE_INITIALIZE", "PMCLOG_TYPE_PADDING",
	"PMCLOG_TYPE_PMCALLOCATE", "PMCLOG_TYPE_PMCATTACH",
	"PMCLOG_TYPE_PMCDETACH", "PMCLOG_TYPE_PROCCSW", "PMCLOG_TYPE_PROCEXEC",
	"PMCLOG_TYPE_PROCEXIT", "PMCLOG_TYPE_PROCFORK", "PMCLOG_TYPE_SYSEXIT",
	"PMCLOG_TYPE_USERDATA", "PMCLOG_TYPE_MAP_IN", "PMCLOG_TYPE_MAP_OUT",
	"PMCLOG_TYPE_CALLCHAIN", "PMCLOG_TYPE_PMCALLOCATEDYN",
	"PMCLOG_TYPE_THR_CREATE", "PMCLOG_TYPE_THR_EXIT",
	"PMCLOG_TYPE_PROC_CREATE", nullptr };

static const char *g_bcpid_pmclog_state_name[] = { "PMCLOG_OK", "PMCLOG_EOF",
	"PMCLOG_REQUIRE_DATA", "PMCLOG_ERROR", nullptr };

static const char *g_bcpid_debug_counter_name[] = {
	"bcpid_debug_empty_mapin_name", "bcpid_debug_empty_mapping_pc",
	"bcpid_debug_pc_before_mapping", "bcpid_debug_pc_after_mapping",
	"bcpid_debug_getprocs_fail", "bcpid_debug_getvmmap_fail",
	"bcpid_debug_callchain_self_fire",
	"bcpid_debug_callchain_proc_init_fail",
	"bcpid_debug_callchain_counter_gone", "bcpid_debug_callchain_pc_skip",
	"bcpid_debug_counter_max", nullptr
};

static void
bcpid_debug_counter_increment(bcpid *b, enum bcpid_debug_counter ctr)
{
	++b->debug_counter[ctr];
}

/*
 * Initialize an object.
 * Main objective is to calculate its hash
 */
static void
bcpid_object_init(bcpid *b, bcpid_object *obj, const std::string &path)
{
	obj->path = path;
	obj->hash = 0;
	memset(&obj->last_modified, 0, sizeof(obj->last_modified));

	struct stat s;
	int status = stat(path.c_str(), &s);
	if (status == -1) {
		if (errno != ENOENT) {
			PERROR("stat");
		}
		return;
	}

	obj->last_modified = s.st_mtim;

	auto oit = b->object_hash_cache.find(std::string(path));
	if (oit != b->object_hash_cache.end()) {
		bcpid_hash_cache *cache = &oit->second;
		if (!memcmp(&cache->last_modified, &obj->last_modified,
			sizeof(obj->last_modified))) {
			obj->hash = cache->hash;
			return;
		}
	}

#ifdef BCPID_HASH_OBJECTS
	int file_fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (file_fd == -1) {
		if (errno != ENOENT && errno != EPERM && errno != EACCES) {
			PERROR("open");
		}
		return;
	}

	off_t file_size = s.st_size;
	void *file_content = mmap(
	    0, file_size, PROT_READ, MAP_NOCORE | MAP_SHARED, file_fd, 0);
	if (file_content == MAP_FAILED) {
		PERROR("mmap");
		close(file_fd);
		return;
	}

	uint32_t hash = crc32(
	    0, (const unsigned char *)file_content, file_size);

	status = munmap(file_content, file_size);
	if (status == -1) {
		PERROR("munmap");
	}

	status = close(file_fd);
	if (status == -1) {
		PERROR("close");
	}

	obj->hash = hash;
#endif

	if (oit == b->object_hash_cache.end()) {
		bcpid_hash_cache cache;
		cache.last_modified = s.st_mtim;
		cache.hash = obj->hash;

		b->object_hash_cache.emplace(std::string(path), cache);
	} else {
		oit->second.hash = obj->hash;
		oit->second.last_modified = s.st_mtim;
	}
}

/*
 * Due to a possible HWPMC bug, event notification
 * does not work when the pipe for PMCLOG is marked
 * non-blocking. Non-blocking pipe is required for
 * main thread in order to handle tasks in addition
 * to receiving from PMCLOG.
 * As a work around, a separate thread with blocking
 * pipe is spawned, and it forwards data to non-blocking
 * end as is.
 */
void *
bcpid_pmclog_thread_main(void *arg)
{
	bcpid *b = (bcpid *)arg;

	int pmclog_fd = b->pipefd[0];
	int non_block_pmclog_fd = b->non_block_pipefd[1];
	const int single_read_size = 4096;
	for (;;) {
		char buffer[single_read_size];
		int n = read(pmclog_fd, buffer, single_read_size);
		if (n < 0) {
			PERROR("read");
			break;
		}

		for (int cursor = 0; cursor < n;) {
			int nw = write(
			    non_block_pmclog_fd, &buffer[cursor], n - cursor);
			if (nw < 0) {
				if (errno != EAGAIN && errno != EWOULDBLOCK) {
					PERROR("write");
					return 0;
				}
			} else {
				cursor += nw;
			}
		}
	}
	return 0;
}

/*
 * Print diagnostic information at program
 * termination
 */
static void
bcpid_report_pmc_ctr(bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		if (!b->pmc_ctrs[i].is_valid) {
			continue;
		}

		bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
		MSG("%s: %ld", spec->name.c_str(), spec->hits);
	}
}

/*
 * Get the kernel module search path.
 */
static std::vector<std::string>
bcpid_module_path()
{
	char value[KENV_MVALLEN + 1];
	if (kenv(KENV_GET, "module_path", value, sizeof(value)) < 0) {
		perror("kenv");
		return { "/boot/kernel", "/boot/modules" };
	}

	std::vector<std::string> ret;
	std::string paths = value;
	size_t i = 0;
	do {
		size_t j = paths.find(';', i);
		ret.push_back(paths.substr(i, j - i));
		i = j + 1;
	} while (i > 0);

	return ret;
}

/*
 * Initialize object after receives MAP_IN event from PMCLOG
 */
static void
bcpid_event_handler_mapin(bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_map_in *mi = &ev->pl_u.pl_mi;
	if (mi->pl_pid != -1) {
		return;
	}

	std::string path = mi->pl_pathname;
	if (path.find('/') == std::string::npos) {
		// Before FreeBSD commit 53d0b9e438bc ("pmc: Provide full path
		// to modules from kernel linker"), the path contains only the
		// basename, so look up the full path in the module search path
		static auto dirs = bcpid_module_path();
		for (const auto &dir : dirs) {
			auto full_path = dir + "/" + path;
			if (access(full_path.c_str(), F_OK) == 0) {
				path = full_path;
				break;
			}
		}
	}

	bcpid_kernel_object ko;
	ko.path = path;
	ko.start = mi->pl_start;

	b->kernel_objects.push_back(ko);
}

static void
bcpid_event_handler_mapout(bcpid *b __unused, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_map_out *mo = &ev->pl_u.pl_mo;
	pid_t pid __unused = mo->pl_pid;
	uintfptr_t start __unused = mo->pl_start;
	uintfptr_t end __unused = mo->pl_end;
}

/*
 * Since a save to disk obliterates all in memory sample data and kernel
 * objects are reported only once by PMCLOG, we need to re-establish
 * them from caches.
 */
static void
bcpid_replay_kernel_objects(bcpid *b)
{
	int pid = -1;
	bcpid_program *proc;
	auto pit = b->pid_to_program.find(pid);
	if (pit == b->pid_to_program.end()) {
		proc = new bcpid_program;
		proc->pid = pid;
		b->pid_to_program.emplace(pid, proc);
	} else {
		proc = pit->second;
	}

	for (const bcpid_kernel_object &ko : b->kernel_objects) {
		auto oit = b->path_to_object.find(ko.path);
		bcpid_object *obj;
		if (oit == b->path_to_object.end()) {
			obj = new bcpid_object;
			bcpid_object_init(b, obj, ko.path);
			b->path_to_object.emplace(ko.path, obj);
		} else {
			obj = oit->second;
		}

		bcpid_program_mapping m;
		m.start = ko.start;
		m.file_offset = 0;
		m.protection = 0;
		m.obj = obj;

		proc->mappings.emplace_back(m);
	}

	sort(proc->mappings.begin(), proc->mappings.end(),
	    bcpid_program_mapping_sort);
}

/*
 * Remove all in-memory sample data and tracking data
 */
static void
bcpid_garbage_collect(bcpid *b)
{
	for (auto p : b->path_to_object) {
		bcpid_object *o = p.second;
		for (auto np : o->node_map) {
			bcpid_pc_node *n = np.second;
			delete n;
		}
		delete o;
	}

	b->path_to_object.clear();

	for (auto p : b->pid_to_program) {
		bcpid_program *prog = p.second;
		delete prog;
	}

	b->pid_to_program.clear();
	b->num_edge = 0;
	b->num_node = 0;

	bcpid_replay_kernel_objects(b);
}

// Calculate number of active counters
static int
bcpid_num_active_counter(bcpid *b)
{
	int num_counter = 0;
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];
		if (!ctr->is_valid) {
			continue;
		}

		++num_counter;
	}
	return num_counter;
}

/*
 * Save sample data on disk. All in-memory data
 * are obliterated
 */

static void
bcpid_save(bcpid *b)
{
	bcpi_record record;

	record.major_version = BCPI_MAJOR_VERSION;
	record.minor_version = BCPI_MINOR_VERSION;
	record.flags = BCPI_DEFAULT_FLAGS;

	record.epoch_end = time(nullptr);

	// Embed system description in the file
	struct utsname uts;
	int status = uname(&uts);
	if (status < 0) {
		PERROR("uname");
		record.system_name = "";
	} else {
		char system_name[255];
		snprintf(system_name, 255, "%s %s %s %s %s", uts.sysname,
		    uts.release, uts.version, uts.nodename, uts.machine);
		record.system_name = system_name;
	}

	int name_index = 0;
	int index_mapping[BCPI_MAX_NUM_COUNTER];
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];
		if (!ctr->is_valid) {
			continue;
		}

		record.counters.emplace_back(ctr->label);
		index_mapping[name_index] = i;
		++name_index;
	}

	int num_object __unused = 0;
	for (auto &object_it : b->path_to_object) {
		bcpid_object *object = object_it.second;

		if (!object->node_map.size()) {
			continue;
		}

		++num_object;
	}

	int object_index = 0;
	record.objects.resize(b->path_to_object.size());
	for (auto &object_it : b->path_to_object) {
		bcpid_object *object = object_it.second;
		bcpi_object &ro = record.objects[object_index];

		if (!object->node_map.size()) {
			continue;
		}

		object->tmp_archive_object_index = object_index;

		ro.path = object->path;
		ro.object_index = object_index;

		int node_index = 0;
		ro.nodes.resize(object->node_map.size());
		for (auto &node_it : object->node_map) {
			bcpid_pc_node *node = node_it.second;
			bcpi_node &rn = ro.nodes[node_index];

			node->tmp_archive_node_index = node_index;

			rn.object = &ro;
			rn.node_address = node->value;
			rn.node_index = node_index;

			for (int i = 0; i < name_index; ++i) {
				rn.terminal_counters[i] =
				    node->end_ctr[index_mapping[i]];
			}

			int edge_index = 0;
			rn.edges.resize(node->incoming_edge_map.size());
			for (auto &edge_it : node->incoming_edge_map) {
				bcpid_pc_edge *edge = &edge_it.second;
				bcpi_edge &re = rn.edges[edge_index];

				re.to = &rn;
				/*
				 * Temporarily use this field to hold pointer to
				 * the originating node that is part of daemon
				 * data structure (as opposed to record data
				 * structure), since the latter may not have
				 * been allocated yet. Will be corrected during
				 * second pass.
				 */
				re.from = (bcpi_node *)edge->from;
				for (int i = 0; i < name_index; ++i) {
					re.counters[i] =
					    edge->hits[index_mapping[i]];
				}
				++edge_index;
			}
			++node_index;
		}
		++object_index;
	}
	record.objects.resize(object_index);

	for (auto &ro : record.objects) {
		for (auto &rn : ro.nodes) {
			for (auto &re : rn.edges) {
				/*
				 * Here we correct this field to point to record
				 * data structure using indexes that were set up
				 * during first pass
				 */
				bcpid_pc_node *node_from = (bcpid_pc_node *)
							       re.from;

				int from_index_object =
				    node_from->obj->tmp_archive_object_index;
				int from_index_node =
				    node_from->tmp_archive_node_index;

				bcpi_object &from_object =
				    record.objects[from_index_object];
				bcpi_node &from_node =
				    from_object.nodes[from_index_node];
				re.from = &from_node;
			}
		}
	}

	struct tm *t = gmtime((time_t *)&record.epoch_end);
	char time_buffer[128];

	strftime(time_buffer, 127, "%F_%T", t);

	char file_name[256];
	snprintf(file_name, 255, "%s/bcpi_%s_%s.bin",
	    b->default_output_dir.c_str(), time_buffer, uts.nodename);
	status = bcpi_save_file(record, file_name);
	if (status) {
		SYSERROR("File save failed!");
		return;
	}

#ifdef BCPID_DEBUG
	{
		bcpi_record reverse_record;

		status = bcpi_load_file(file_name, &reverse_record);
		if (status) {
			SYSERROR("File save corrupt!");
			return;
		}
		bcpi_is_equal(record, reverse_record);
	}
#endif

	bcpid_garbage_collect(b);

	MSG("saved at %s", file_name);
}

/*
 * Obtain pointer to the node, given a program counter and a process.
 * This routine first finds the object that is mapped at that address,
 * it then retreives the node, and creates one if necessary.
 */
static bcpid_pc_node *
bcpid_get_node_from_pc(bcpid *b, bcpid_program *proc, uint64_t pc)
{
	// Until there is a better way to distinguish kernel address,
	// this is currently used. Note that '-1' is PMCLOG's way of
	// saying 'kernel processes', and is perpetuated here.
	if (pc > BCPID_KERN_BASE) {
		proc = b->pid_to_program[-1];
	}

	bcpid_program_mapping m = { pc, 0, 0, 0, 0 };
	// Upper bound performs binary search. It is assumed that
	// there is no overlap in address spaces.
	auto it = upper_bound(proc->mappings.begin(), proc->mappings.end(), m,
	    bcpid_program_mapping_sort);
	if (it == proc->mappings.end()) {
		if (!proc->mappings.size()) {
			bcpid_debug_counter_increment(
			    b, bcpid_debug_empty_mapping_pc);
			return nullptr;
		}
	}
	if (it != proc->mappings.begin()) {
		--it;
	}

	bcpid_program_mapping *mapping = &*it;
	if (pc < mapping->start) {
		bcpid_debug_counter_increment(b, bcpid_debug_pc_before_mapping);
		return nullptr;
	}

	if (pc > mapping->end && proc->pid != -1) {
		bcpid_debug_counter_increment(b, bcpid_debug_pc_after_mapping);
		return nullptr;
	}

	bcpid_object *obj = mapping->obj;
	bcpid_pc_node *node;
	// Turn raw program counter into an address that can be located
	// in an ELF file.
	uint64_t real_addr = pc - mapping->start + mapping->file_offset;
	auto nit = obj->node_map.find(real_addr);
	if (nit == obj->node_map.end()) {
		b->num_node++;
		node = new bcpid_pc_node();
		memset(node->end_ctr, 0, sizeof(node->end_ctr));
		node->value = real_addr;
		node->obj = obj;

		obj->node_map.emplace(real_addr, node);
	} else {
		node = nit->second;
	}

	return node;
}

/*
 * Initialize and return pointer to the process structure.
 * Main objective is to read address space mappings and to create
 * index for them using procstat API.
 */
static bcpid_program *
bcpid_init_proc(bcpid *b, int pid)
{
	uint32_t count;
	bcpid_program *exec;
	struct kinfo_proc *kproc = procstat_getprocs(
	    b->procstat, KERN_PROC_PID, pid, &count);
	if (!count || !kproc) {
		bcpid_debug_counter_increment(b, bcpid_debug_getprocs_fail);
		return nullptr;
	}

	if (kproc->ki_flag & P_SYSTEM) {
		/*
		 * Make a fake process for Kernel processes so we don't waste
		 * time calling procstat.
		 */

		exec = new bcpid_program();
		exec->pid = pid;

		procstat_freeprocs(b->procstat, kproc);
		return exec;
	}

	struct kinfo_vmentry *vm = procstat_getvmmap(
	    b->procstat, kproc, &count);
	if (!count || !vm) {
		/*
		 * XXX: We could use the image name, track mmap/munmap, and our
		 * cache to solve the racey samples where programs exited.
		 */
		bcpid_debug_counter_increment(b, bcpid_debug_getvmmap_fail);
		procstat_freeprocs(b->procstat, kproc);
		return nullptr;
	}

	exec = new bcpid_program();
	exec->pid = pid;

	struct kinfo_vmentry *cur_vm = vm;
	for (unsigned int i = 0; i < count; ++i, ++cur_vm) {
		if (cur_vm->kve_start > BCPID_KERN_BASE) {
			break;
		}

		std::string path(cur_vm->kve_path);
		auto oit = b->path_to_object.find(path);
		bcpid_object *obj;
		if (oit == b->path_to_object.end()) {
			obj = new bcpid_object();
			bcpid_object_init(b, obj, cur_vm->kve_path);
			b->path_to_object.emplace(path, obj);
		} else {
			obj = oit->second;
		}

		bcpid_program_mapping m;
		m.start = cur_vm->kve_start;
		m.end = cur_vm->kve_end;
		m.file_offset = cur_vm->kve_offset;
		m.protection = cur_vm->kve_protection;
		m.obj = obj;

		exec->mappings.emplace_back(m);
	}

	// Sorting mappings allows binary search
	sort(exec->mappings.begin(), exec->mappings.end(),
	    bcpid_program_mapping_sort);

	procstat_freevmmap(b->procstat, vm);
	procstat_freeprocs(b->procstat, kproc);

	return exec;
}

// Get counter index using pointer arithmetic.
static int
bcpid_get_pmc_counter_index(bcpid *b, bcpid_pmc_counter *c)
{
	return c - b->pmc_ctrs;
}

/*
 * Handle a call chain event received from PMCLOG. Main objective
 * is to walk the entire call chain, possibly creating vertices and
 * edges in the meantime, and increment counters along the way.
 */
static void
bcpid_event_handler_callchain(bcpid *b, const struct pmclog_ev *ev)
{
	if (!b->first_callchain) {
		bcpid_replay_kernel_objects(b);
		b->first_callchain = true;
	}

	const struct pmclog_ev_callchain *cc = &ev->pl_u.pl_cc;

	int pid = cc->pl_pid;
	if (pid == b->selfpid) {
		bcpid_debug_counter_increment(
		    b, bcpid_debug_callchain_self_fire);
		return;
	}

	bcpid_program *proc;
	auto it = b->pid_to_program.find(pid);
	if (it == b->pid_to_program.end()) {
		proc = bcpid_init_proc(b, pid);
		if (!proc) {
			bcpid_debug_counter_increment(
			    b, bcpid_debug_callchain_proc_init_fail);
			return;
		}
		b->pid_to_program.emplace(pid, proc);
	} else {
		proc = it->second;
	}

	bcpid_pmc_counter *spec;
	auto sit = b->pmcid_to_counter.find(cc->pl_pmcid);
	if (sit == b->pmcid_to_counter.end()) {
		bcpid_debug_counter_increment(
		    b, bcpid_debug_callchain_counter_gone);
		return;
	}

	spec = sit->second;
	++spec->hits;

	int spec_index = bcpid_get_pmc_counter_index(b, spec);

	int chain_len = cc->pl_npc;
	bcpid_pc_node *to_node;
	bcpid_pc_node *from_node;

	if (chain_len == 1) {
		uint64_t pc = cc->pl_pc[0];

		to_node = bcpid_get_node_from_pc(b, proc, pc);
		if (to_node) {
			++to_node->end_ctr[spec_index];
		} else {
			bcpid_debug_counter_increment(
			    b, bcpid_debug_callchain_pc_skip);
		}

		return;
	}

	for (int i = 1; i < chain_len; ++i) {
		uint64_t to_pc = cc->pl_pc[i - 1];
		uint64_t from_pc = cc->pl_pc[i];

		if (i > 1) {
			to_node = from_node;
		} else {
			to_node = bcpid_get_node_from_pc(b, proc, to_pc);
		}

		from_node = bcpid_get_node_from_pc(b, proc, from_pc);
		if (!to_node || !from_node) {
			bcpid_debug_counter_increment(
			    b, bcpid_debug_callchain_pc_skip);
			continue;
		}

		if (i == 1) {
			++to_node->end_ctr[spec_index];
		}

		auto *map = &to_node->incoming_edge_map;
		auto eit = map->find(from_node);
		bcpid_pc_edge *e;
		if (eit == map->end()) {
			bcpid_pc_edge edge;
			memset(edge.hits, 0, sizeof(edge.hits));
			edge.from = from_node;
			edge.to = to_node;

			b->num_edge++;
			auto res = map->emplace(from_node, edge);
			e = &res.first->second;
		} else {
			e = &eit->second;
		}

		++e->hits[spec_index];
	}
}

/*
 * Handle process exec event from PMCLOG. Main objective is to
 * initialize process data structure for tracking.
 */
static void
bcpid_event_handler_proc_exec(bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_procexec *pe = &ev->pl_u.pl_x;
	const char *main_object_path = pe->pl_pathname;

	auto prog = b->pid_to_program.find(pe->pl_pid);
	if (prog != b->pid_to_program.end()) {
		delete prog->second;
		b->pid_to_program.erase(prog);
	}

	auto obj = b->path_to_object.find(std::string(main_object_path));
	if (obj != b->path_to_object.end()) {
		struct stat s;
		int status = stat(main_object_path, &s);
		if (status == -1) {
			return;
		}

		struct timespec *ts = &s.st_mtim;
		if (!memcmp(ts, &obj->second->last_modified, sizeof(*ts))) {
			return;
		}

		MSG("Saving because of updated executable: %s",
		    main_object_path);
		bcpid_save(b);
	}
}

static void
bcpid_event_handler_proc_fork(bcpid *b __unused,
    const struct pmclog_ev *ev __unused)
{
}

static void
bcpid_event_handler_proc_create(bcpid *b __unused,
    const struct pmclog_ev *ev __unused)
{
}

/*
 * Handle process exit.
 */
static void
bcpid_event_handler_sysexit(bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_sysexit *ex = &ev->pl_u.pl_se;

	auto pit = b->pid_to_program.find(ex->pl_pid);
	if (pit == b->pid_to_program.end()) {
		return;
	}

	bcpid_program *prog = pit->second;

	b->pid_to_program.erase(pit);
	delete prog;
}

static void
bcpid_register_handlers(bcpid *b)
{
	int n = 0;
	for (const char **name = g_bcpid_pmclog_name; *name; ++name, ++n) {
		bcpid_pmclog_event *ev = &b->pmclog_events[n];
		ev->is_valid = true;
		ev->name = *name;
	}

	b->num_pmclog_event = n;

	bcpid_pmclog_event *ev;
	ev = &b->pmclog_events[PMCLOG_TYPE_MAP_IN];
	ev->handler = bcpid_event_handler_mapin;

	ev = &b->pmclog_events[PMCLOG_TYPE_MAP_OUT];
	ev->handler = bcpid_event_handler_mapout;

	ev = &b->pmclog_events[PMCLOG_TYPE_CALLCHAIN];
	ev->handler = bcpid_event_handler_callchain;

	ev = &b->pmclog_events[PMCLOG_TYPE_PROC_CREATE];
	ev->handler = bcpid_event_handler_proc_create;

	ev = &b->pmclog_events[PMCLOG_TYPE_SYSEXIT];
	ev->handler = bcpid_event_handler_sysexit;

	ev = &b->pmclog_events[PMCLOG_TYPE_PROCFORK];
	ev->handler = bcpid_event_handler_proc_fork;

	ev = &b->pmclog_events[PMCLOG_TYPE_PROCEXEC];
	ev->handler = bcpid_event_handler_proc_exec;
}

/*
 * A wrapper to batch kqueue event updates and to reduce number of calls to
 * kqueue
 */
static void
bcpid_kevent_set(bcpid *b, uintptr_t ident, short filter, u_short flags,
    u_int fflags, int64_t data, void *udata)
{
	int cur_size = b->kevent_in_size;
	assert(cur_size < BCPID_KEVENT_MAX_BATCH_SIZE);
	EV_SET(&b->kevent_in_batch[cur_size], ident, filter, flags, fflags,
	    data, udata);
	b->kevent_in_size++;
}

static void
bcpid_pmc_init(bcpid *b __unused)
{
	int status;

	status = pmc_init();
	if (status < 0) {
		PERROR("pmc_init");
		exit(1);
	}
}

static std::vector<std::string>
string_split(const std::string &str, const std::string &delim)
{
	size_t last = 0;
	size_t next;
	std::vector<std::string> retval;

	while ((next = str.find(delim, last)) != std::string::npos) {
		retval.push_back(str.substr(last, next - last));
		last = next + delim.length();
	}

	retval.push_back(str.substr(last, -1));

	return retval;
}

static std::string
string_join(const std::vector<std::string> &vstr, const std::string &delim)
{
	std::string str = "";

	for (auto &c : vstr) {
		if (str.length() != 0)
			str += delim;
		str += c;
	}

	return str;
}

/*
 * Allocate a PMC counter on all CPUs.
 */
static void
bcpid_alloc_pmc(bcpid *b, const std::string &name, int count = -1)
{
	bcpid_pmc_counter *ctr = nullptr;
	int counter_index = 0;

	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (c->is_valid) {
			continue;
		}

		ctr = c;
		counter_index = i;
		break;
	}

	if (!ctr) {
		MSG("cannot add %s: all %d pmcs allocated", name.c_str(),
		    BCPI_MAX_NUM_COUNTER);
		return;
	}
	MSG("allocating %s", name.c_str());

	ctr->hits = 0;
	ctr->sample_rate = (count == -1) ? b->default_count : count;
	ctr->sample_ratio = 1;
	ctr->label = "";
	ctr->callchain = false;
	ctr->usercallchain = false;

	auto vname = string_split(name, ",");
	for (auto p = vname.begin(); p != vname.end(); p++) {
		size_t val = p->find("=") + 1;
		if (p->starts_with("sample_rate=")) {
			ctr->sample_rate = std::stoll(p->substr(val));
			ctr->sample_ratio = 0;
			vname.erase(p--);
		}
		if (p->starts_with("sample_ratio=")) {
			ctr->sample_ratio = std::stoll(p->substr(val));
			vname.erase(p--);
		}
		if (p->starts_with("label=")) {
			ctr->label = p->substr(val);
			vname.erase(p--);
		}
		if (p->starts_with("callchain")) {
			ctr->callchain = true;
			vname.erase(p--);
		}
		if (p->starts_with("usercallchain")) {
			ctr->usercallchain = true;
			vname.erase(p--);
		}
	}

	if (ctr->sample_ratio) {
		b->adaptive = true;
	}

	ctr->name = string_join(vname, ",");
	if (ctr->label == "") {
		ctr->label = ctr->name;
	}

	for (int i = 0; i < b->num_cpu; ++i) {
		bcpid_pmc_cpu *cpu = &b->pmc_cpus[i];
		pmc_id_t pmc_id;
		uint32_t flags = 0;

		flags |= (ctr->callchain) ? PMC_F_CALLCHAIN : 0;
		flags |= (ctr->usercallchain) ?
			  (PMC_F_USERCALLCHAIN | PMC_F_CALLCHAIN) :
			  0;

		int status = pmc_allocate(ctr->name.c_str(), PMC_MODE_SS, flags,
		    i, &pmc_id, ctr->sample_rate);
		if (status < 0) {
			PERROR("pmc_allocate");
			goto fail;
		}

		status = pmc_start(pmc_id);
		if (status < 0) {
			PERROR("pmc_start");
			goto fail;
		}

		cpu->pmcs[counter_index] = pmc_id;
		b->pmcid_to_counter.emplace(pmc_id, ctr);
	}

	ctr->is_valid = true;
fail:
	return;
}

/*
 * Release an allocated PMC counter on all CPUs.
 */
static void
bcpid_release_pmc(bcpid *b, const std::string &name)
{
	bcpid_pmc_counter *ctr = nullptr;
	int counter_index = 0;

	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}
		if (c->name != name) {
			continue;
		}
		ctr = c;
		counter_index = i;
		break;
	}

	if (!ctr) {
		MSG("cannot release %s: does not exist", name.c_str());
		return;
	}

	MSG("releasing %s", name.c_str());

	for (int i = 0; i < b->num_cpu; ++i) {
		bcpid_pmc_cpu *cpu = &b->pmc_cpus[i];
		pmc_id_t pmc_id = cpu->pmcs[counter_index];
		int status = pmc_stop(pmc_id);
		if (status < 0) {
			PERROR("pmc_stop");
		}

		status = pmc_release(pmc_id);
		if (status < 0) {
			PERROR("pmc_release");
		}

		cpu->pmcs[counter_index] = 0;

		auto it = b->pmcid_to_counter.find(pmc_id);
		if (it != b->pmcid_to_counter.end()) {
			b->pmcid_to_counter.erase(it);
		}
	}

	ctr->is_valid = false;
	ctr->hits = 0;
	ctr->name = "*invalid*";
}

void
bcpid_release_all(bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (c->is_valid)
			bcpid_release_pmc(b, c->name);
	}
}

void
bcpid_update_adaptive(bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];

		// Ignore invalid or fixed sample rate counters
		if (!ctr->is_valid || ctr->sample_ratio == 0) {
			continue;
		}

		for (int j = 0; j < b->num_cpu; ++j) {
			int status;
			bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
			pmc_id_t pmc_id = cpu->pmcs[i];

			status = pmc_stop(pmc_id);
			if (status < 0) {
				PERROR("pmc_stop");
			}

			status = pmc_set(pmc_id, ctr->sample_rate);
			if (status < 0) {
				PERROR("pmc_set");
			}

			status = pmc_start(pmc_id);
			if (status < 0) {
				PERROR("pmc_start");
			}
		}
	}
}

static int
bcpid_parse_config(bcpid *b)
{
	int status;
	const struct pmc_cpuinfo *cpuinfo;

	status = pmc_cpuinfo(&cpuinfo);
	if (status < 0) {
		PERROR("pmc_cpuinfo");
	}

	// Read name of counters from configuration file named by CPU type
	// by default
	const char *cpu_name = pmc_name_of_cputype(cpuinfo->pm_cputype);
	const char *suffix = ".conf";
	char conf_name[128];

	strcpy(conf_name, "conf/");
	strcat(conf_name, cpu_name);
	strcat(conf_name, suffix);

	MSG("Reading config %s...", conf_name);
	FILE *file = fopen(conf_name, "r");
	if (!file) {
		SYSERROR("Could not open configuration file '%s'", conf_name);
		exit(EX_NOINPUT);
	}

	b->adaptive = false;

	for (;;) {
		char ctr[128];
		char *s = fgets(ctr, 127, file);
		if (!s) {
			break;
		}
		ctr[strcspn(ctr, "\r\n")] = 0;

		if (ctr[0] == '#')
			continue;

		bcpid_alloc_pmc(b, ctr);
	}

	if (bcpid_num_active_counter(b) == 0) {
		SYSERROR("No active counters!");
		exit(EX_CONFIG);
	}

	return 0;
}

static void
bcpid_setup_pmc(bcpid *b)
{
	int status;
	b->num_cpu = pmc_ncpu();
	b->selfpid = getpid();
	b->procstat = procstat_open_sysctl();
	b->kevent_in_size = 0;
	b->kevent_out_size = BCPID_KEVENT_MAX_BATCH_SIZE;

	memset(b->pmc_ctrs, 0, sizeof(b->pmc_ctrs));
	memset(b->pmc_cpus, 0, sizeof(b->pmc_cpus));
	memset(b->pmclog_events, 0, sizeof(b->pmclog_events));

	status = pipe(b->pipefd);
	if (status < 0) {
		PERROR("pipe");
	}

	status = pipe2(b->non_block_pipefd, O_NONBLOCK);
	if (status < 0) {
		PERROR("pipe2");
	}

	status = pmc_configure_logfile(b->pipefd[1]);
	if (status < 0) {
		PERROR("pmc_configure_logfile");
	}

	b->pmclog_handle = pmclog_open(b->non_block_pipefd[0]);
	if (!b->pmclog_handle) {
		PERROR("pmclog_open");
	}

	bcpid_register_handlers(b);

	int f = fcntl(STDIN_FILENO, F_GETFL);
	status = fcntl(STDIN_FILENO, F_SETFL, f | O_NONBLOCK);
	if (status < 0) {
		PERROR("fcntl");
	}

	b->kqueue_fd = kqueue();
	if (b->kqueue_fd < 0) {
		PERROR("kqueue");
	}

	bcpid_kevent_set(
	    b, b->non_block_pipefd[0], EVFILT_READ, EV_ADD, 0, 0, 0);
	bcpid_kevent_set(b, STDIN_FILENO, EVFILT_READ, EV_ADD, 0, 0, 0);
	bcpid_kevent_set(
	    b, BCPID_TIMER_MAGIC, EVFILT_TIMER, EV_ADD, 0, BCPID_INTERVAL, 0);
	bcpid_kevent_set(b, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	bcpid_kevent_set(b, SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	bcpid_kevent_set(b, SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	bcpid_kevent_set(b, SIGINFO, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);

	status = pthread_create(
	    &b->pmclog_forward_thr, 0, bcpid_pmclog_thread_main, b);
	if (status != 0) {
		SYSERROR("pthred_create: %s", strerror(status));
	}

	// Read name of counters from argv, if present
	if (b->pmc_override) {
		std::vector<std::string> pmcs = string_split(
		    b->default_pmc, ";");
		for (auto &p : pmcs) {
			bcpid_alloc_pmc(b, p);
		}
		return;
	}

	bcpid_parse_config(b);

	b->first_callchain = false;
}

/*
 * PMCLOG event dispatcher
 */
static void
bcpid_handle_pmclog(bcpid *b)
{
	struct pmclog_ev ev;
	for (;;) {
		pmclog_read(b->pmclog_handle, &ev);
		if (ev.pl_state != PMCLOG_OK) {
			if (ev.pl_state != PMCLOG_REQUIRE_DATA) {
				const char *state_name =
				    g_bcpid_pmclog_state_name[ev.pl_state];
				SYSERROR("pmclog broken: %s", state_name);
			}
			break;
		}

		bcpid_pmclog_event *bpev = &b->pmclog_events[ev.pl_type];
		++bpev->num_fire;

		bcpid_event_handler handler = bpev->handler;

		if (handler) {
			handler(b, &ev);
		}
	}
}

static void
bcpid_start_all(bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		for (int j = 0; j < b->num_cpu; ++j) {
			bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
			int status = pmc_start(cpu->pmcs[i]);
			if (status < 0) {
				PERROR("pmc_start");
			}
		}
	}
}

static void
bcpid_stop_all(bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		for (int j = 0; j < b->num_cpu; ++j) {
			bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
			int status = pmc_stop(cpu->pmcs[i]);
			if (status < 0) {
				PERROR("pmc_stop");
			}
		}
	}
}

static void
bcpid_print_stats(bcpid *b)
{
	MSG("Statistics:");
	MSG("\t%ld processes", b->pid_to_program.size());

	MSG("\t%ld objects", b->path_to_object.size());
	MSG("\t%d nodes", b->num_node);
	MSG("\t%d edges", b->num_edge);
	for (int i = 0; i < bcpid_debug_counter_max; ++i) {
		MSG("\t%s: %ld", g_bcpid_debug_counter_name[i],
		    b->debug_counter[i]);
	}

	MSG("Active counters:");
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		MSG("\t%s sample_rate=%d sample_ratio=%d %lu", c->name.c_str(),
		    c->sample_rate, c->sample_ratio, c->hits);
	}
}

void
bcpid_collect_struct_stat(bcpid *b, bcpid_statistics *s)
{
	s->num_edge = b->num_edge;
	s->num_node = b->num_node;
	s->num_object = b->path_to_object.size();
	s->num_program = b->pid_to_program.size();
	s->num_object_hash = b->object_hash_cache.size();
}

static uint64_t
tv_to_usec(const struct timeval *r)
{
	uint64_t t = 0;

	t += r->tv_usec;
	t += r->tv_sec * 1000000;

	return t;
}

/*
 * Periodically run piece of code. See BCPID_INTERVAL for period.
 * Currently it collects performance metrics of daemon, and
 * save sample data to disk if they become too big.
 */
static void
bcpid_handle_timer(bcpid *b)
{
	static uint64_t timer_counter = 0;
	static rusage r_old;
	struct rusage r;
	int status;
	uint64_t new_time, old_time, time_diff;
	bcpid_statistics stats;

#define PID_Ku 1
#define PID_Tu 2
#define PID_Kp (5000 * PID_Ku)
#define PID_Ki (5400 * PID_Ku / PID_Tu)
#define PID_Kd (300 * PID_Ku * PID_Tu / 40)
#define PID_Ks (2)
#define PID_DIVIDER (100)
#define PID_GAIN (25)
#define PID_BOUND (100000)

	if (b->adaptive) {
		static int64_t pid_int = 0;
		static int64_t pid_deriv = 0;
		static int64_t pid_old = 0;
		static rusage r_prev = { { 0, 0 } };
		int64_t pid_err, pid_out;

		getrusage(RUSAGE_SELF, &r);

		new_time = tv_to_usec(&r.ru_utime) + tv_to_usec(&r.ru_stime);
		old_time = tv_to_usec(&r_prev.ru_utime) +
		    tv_to_usec(&r_prev.ru_stime);
		time_diff = new_time - old_time;

		pid_err = time_diff -
		    (1000LL * BCPID_INTERVAL * b->target_cpu) / 100;

		/*
		 * Negative errors tend to be smaller than positive errors.  We
		 * can compensate for this skew by multiplying negative values
		 * and dividing positive values by a small integer constant.
		 */
		pid_err = (pid_err < 0) ? (pid_err * PID_Ks) :
						(pid_err / PID_Ks);

		pid_out = pid_err * PID_Kp + pid_int * PID_Ki +
		    (pid_deriv - pid_err) * PID_Kd;
		pid_out /= (PID_DIVIDER * PID_GAIN);

		LOG("pid_int %ld pid_deriv %ld time_diff %ld pid_err %ld pid_out %ld",
		    pid_int, pid_deriv - pid_err, time_diff, pid_err, pid_out);

		pid_int += pid_err;
		pid_deriv = pid_err;
		r_prev = r;

		/*
		 * Bound final sample rate by 1k and 100M.
		 */
		if (pid_out > 100000000)
			pid_out = 100000000;
		if (pid_out < 1000)
			pid_out = 1000;

		uint64_t sample_total = 0;
		for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
			bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];

			// Ignore invalid or fixed sample rate counters
			if (!ctr->is_valid || ctr->sample_ratio == 0) {
				continue;
			}

			sample_total += ctr->sample_ratio;
		}

		for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
			bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];

			if (!ctr->is_valid || ctr->sample_ratio == 0) {
				continue;
			}

			ctr->sample_rate = pid_out * ctr->sample_ratio /
			    sample_total;
		}

		/*
		 * Reduce the number of changes to the sample rate
		 */
		if ((pid_old < pid_out) ? (pid_old < pid_out + PID_BOUND) :
						(pid_old > pid_out + PID_BOUND)) {
			DLOG("Update sample rate");
			bcpid_update_adaptive(b);
		}

		pid_old = pid_out;
	}

	if (verbose && ((timer_counter++ % 60) == 0)) {
		status = getrusage(RUSAGE_SELF, &r);
		if (status != 0) {
			PERROR("getrusage");
			abort();
		}

		new_time = tv_to_usec(&r.ru_utime) + tv_to_usec(&r.ru_stime);
		old_time = tv_to_usec(&r_old.ru_utime) +
		    tv_to_usec(&r_old.ru_stime);
		time_diff = new_time - old_time;

		r_old = r;

		MSG("Memory Max RSS %lu MiB, CPU %lu ms", r.ru_maxrss / 1024,
		    time_diff / 1000);
	}

	bcpid_collect_struct_stat(b, &stats);
	if (stats.num_edge > b->edge_collect_threshold ||
	    stats.num_node > b->node_collect_threshold) {
		MSG("saving...");
		bcpid_save(b);
	}

	if (stats.num_object_hash > b->object_hash_collect_threshold) {
		b->object_hash_cache.clear();
	}
}

static void
bcpid_shutdown(bcpid *b)
{
	pmclog_close(b->pmclog_handle);

	bcpid_release_all(b);

	int status = pmc_configure_logfile(-1);
	if (status < 0) {
		PERROR("pmc_configure_logfile");
	}
}

static void
bcpid_report(bcpid *b)
{
	for (int i = 0; i < b->num_pmclog_event; ++i) {
		bcpid_pmclog_event *spec = &b->pmclog_events[i];
		if (!spec->name) {
			continue;
		}
		MSG("%s fired %lu times", spec->name, spec->num_fire);
	}

	bcpid_report_pmc_ctr(b);
}

static void
bcpid_print_pmcs()
{
	int status;
	const struct pmc_cpuinfo *cpuinfo;

	status = pmc_cpuinfo(&cpuinfo);
	if (status < 0) {
		PERROR("pmc_cpuinfo");
		exit(1);
	}

	fprintf(stderr, "CPU Type: %s, CPUs: %d, PMCs: %d, Classes: %d\n",
	    pmc_name_of_cputype(cpuinfo->pm_cputype), cpuinfo->pm_ncpu,
	    cpuinfo->pm_npmc, cpuinfo->pm_nclass);
	for (unsigned int i = 0; i < cpuinfo->pm_nclass; i++) {
		const struct pmc_classinfo *c = &cpuinfo->pm_classes[i];
		fprintf(stderr, "Class %d %s: Width: %d, PMCS: %d, Caps: ", i,
		    pmc_name_of_class(c->pm_class), c->pm_width, c->pm_num);
		for (int j = 0; j < 31; ++j) {
			if (c->pm_caps & (1 << j)) {
				fprintf(stderr, "%s ",
				    pmc_name_of_capability(
					(enum pmc_caps)(1 << j)));
			}
		}
		fprintf(stderr, "\nEvent Names: \n");
		int evts;
		const char **evtlst;
		enum pmc_class pc = c->pm_class;
		if (pc == PMC_CLASS_IAP) {
			pmc_pmu_print_counters(NULL);
			continue;
		}

		status = pmc_event_names_of_class(pc, &evtlst, &evts);
		if (status < 0) {
			PERROR("pmc_event_names_of_class");
			exit(1);
		}

		for (int j = 0; j < evts; j++) {
			fprintf(stderr, "\t%s\n", evtlst[j]);
		}
		free(evtlst);
	}
}

static void
bcpid_help()
{
	printf("alloc       Allocate a new PMC\n");
	printf("release     Release a PMC\n");
	printf("pmcs        Show all supported PMCs\n");
	printf("reload      Reload configuration file\n");
	printf("stats       Show statistics\n");
	printf("save        Save collected data\n");
	printf("start       Start all PMCs\n");
	printf("stop        Stop all PMCs\n");
	printf("quit        Exit bcpid\n");
	printf("help        Show this message\n");
}

static void
bcpid_handle_stdin(bcpid *b)
{
	char line[128];
	int r = read(STDIN_FILENO, line, 128);
	if (r <= 0) {
		PERROR("read");
		return;
	}

	const char *delim = " \n";
	char *arg = strtok(line, delim);
	if (!arg) {
		goto fail;
	}

	if (!strcmp(arg, "alloc")) {
		char *name = strtok(0, delim);
		if (!name) {
			goto fail;
		}

		char *ctr = strtok(0, delim);
		bcpid_alloc_pmc(b, name, ctr ? atoi(ctr) : b->default_count);
	} else if (!strcmp(arg, "release")) {
		char *name = strtok(0, delim);
		if (!name) {
			goto fail;
		}
		bcpid_release_pmc(b, name);
	} else if (!strcmp(arg, "pmcs")) {
		bcpid_print_pmcs();
	} else if (!strcmp(arg, "stats")) {
		bcpid_print_stats(b);
	} else if (!strcmp(arg, "save")) {
		bcpid_save(b);
	} else if (!strcmp(arg, "stop")) {
		bcpid_stop_all(b);
	} else if (!strcmp(arg, "start")) {
		bcpid_start_all(b);
	} else if (!strcmp(arg, "reload")) {
		bcpid_save(b);
		bcpid_release_all(b);
		bcpid_parse_config(b);
	} else if (!strcmp(arg, "quit")) {
		b->g_quit = 1;
	} else if (!strcmp(arg, "help")) {
		bcpid_help();
	} else {
		MSG("unknown command: %s", arg);
	}

	return;
fail:
	(void)0;
}

static void
bcpid_main_loop(bcpid *b)
{
	while (!b->g_quit) {
		int r = kevent(b->kqueue_fd, b->kevent_in_batch,
		    b->kevent_in_size, b->kevent_out_batch, b->kevent_out_size,
		    0);
		b->kevent_in_size = 0;
		if (r < 0) {
			PERROR("kqueue");
			break;
		}

		for (int i = 0; i < r; ++i) {
			struct kevent *ke = &b->kevent_out_batch[i];
			if (ke->filter == EVFILT_READ) {
				if (ke->ident ==
				    (unsigned long)b->non_block_pipefd[0]) {
					bcpid_handle_pmclog(b);
				}

				if (ke->ident == STDIN_FILENO) {
					bcpid_handle_stdin(b);
				}
			}

			if (ke->filter == EVFILT_TIMER) {
				if (ke->ident == BCPID_TIMER_MAGIC) {
					bcpid_handle_timer(b);
				}
			}

			if (ke->filter == EVFILT_SIGNAL) {
				if (ke->ident == SIGTERM ||
				    ke->ident == SIGINT) {
					MSG("Received SIGTERM");
					b->g_quit = 1;
				}
				if (ke->ident == SIGHUP) {
					MSG("Received SIGHUP");
					bcpid_save(b);
					bcpid_release_all(b);
					bcpid_parse_config(b);
				}
				if (ke->ident == SIGINFO) {
					bcpid_print_stats(b);
				}
			}
		}
	}

	bcpid_save(b);
}

static void
usage()
{
	fprintf(stderr,
	    "Usage: bcpid [-c count] [-p pmc1;pmc2;...] [-o dir]\n"
	    "\t-L            List PMCs\n"
	    "\t-a %%cpu       Target CPU usage (default: 5%%)\n"
	    "\t-c config     Configuration file\n"
	    "\t-f            Foreground\n"
	    "\t-h            Help\n"
	    "\t-n rate       Sampling rate\n"
	    "\t-o dir        Output directory\n"
	    "\t-p pmc        PMCs to monitor\n"
	    "\t-l logfile    Log bcpi daemon\n"
	    "\t-v            Verbose\n");
}

static bool
bcpid_parse_options(bcpid *b, int argc, const char *argv[])
{
	int opt;
	struct stat s;

	b->config_file = "";
	b->default_count = BCPID_DEFAULT_COUNT;
	b->default_pmc = "";
	b->default_output_dir = BCPID_OUTPUT_DIRECTORY;
	b->target_cpu = 5;
	b->adaptive = true;
	b->pmc_override = false;
	b->edge_collect_threshold = BCPID_EDGE_GC_THRESHOLD;
	b->node_collect_threshold = BCPID_NODE_GC_THRESHOLD;
	b->object_hash_collect_threshold = BCPID_OBJECT_HASH_GC_THRESHOLD;

	while ((opt = getopt(argc, (char **)argv, "Lc:fhn:o:p:l:va:")) != -1) {
		switch (opt) {
		case 'L': {
			bcpid_print_pmcs();
			exit(EX_OK);
		}
		case 'a': {
			b->target_cpu = atoi(optarg);
			break;
		}
		case 'c': {
			b->config_file = optarg;
			break;
		}
		case 'f': {
			foreground = true;
			break;
		}
		case 'h': {
			usage();
			exit(EX_OK);
		}
		case 'n':
			b->default_count = atoi(optarg);
			break;
		case 'o': {
			b->default_output_dir = optarg;
			break;
		}
		case 'p': {
			b->pmc_override = true;
			b->default_pmc = optarg;
			break;
		}
		case 'l': {
			Debug_OpenLog(optarg);
			break;
		}
		case 'v': {
			verbose++;
			break;
		}
		default:
			usage();
			exit(EX_USAGE);
		}
	}

	if (!verbose) {
		/*
		 * XXX: Hack since we get lots of errors in libpmcstat, but
		 * this also hides some important errors!
		 */
		err_set_file(fopen("/dev/null", "w"));
	}

	if (stat(BCPID_OUTPUT_DIRECTORY, &s) == -1) {
		WARNING("Please create directory %s", BCPID_OUTPUT_DIRECTORY);
		return false;
	}

	MSG("Default sampling rate is %d", b->default_count);
	if (b->pmc_override) {
		MSG("Overriding pmc counters to %s", b->default_pmc.c_str());
	}

	return true;
}

int
main(int argc, const char *argv[])
{
	bcpid b = bcpid();
	struct sigaction sa;

	/*
	 * Ignore SIGTERM, SIGINT and SIGHUP that will be handled in the kevent
	 * loop.  SIGTERM and SIGINT will gracefully exit saving all state,
	 * while SIGHUP allows the user to reload the configuration file.
	 */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGTERM, &sa, nullptr);
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGHUP, &sa, nullptr);

	bcpid_pmc_init(&b);

	if (!bcpid_parse_options(&b, argc, argv)) {
		return EX_OK;
	}

	if (!foreground) {
		pid_t p = fork();
		if (p < 0) {
			PERROR("fork");
			exit(EX_OSERR);
		}
		if (p != 0)
			exit(EX_OK);
		Debug_Detach();
	}

	bcpid_setup_pmc(&b);
	bcpid_main_loop(&b);
	bcpid_shutdown(&b);
	bcpid_report(&b);

	return EX_OK;
}

