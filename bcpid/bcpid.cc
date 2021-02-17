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

#include <fcntl.h>
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

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../libbcpi/crc32.h"
#include "../libbcpi/libbcpi.h"
#include "debug.h"

/*
 * Set up signal handlers so that the program doesn't get
 * terminated right away and has a chance to handle signals.
 * This is especially useful when taking care of user pressing
 * Ctrl-C on the program
 *
 * @param signal_handler function to call when SIGTERM, SIGINT or
 * SIGHUP is delivered
 */

void
bcpid_signal_init(void (*signal_handler)(int num))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);

	sa.sa_handler = signal_handler;
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGHUP, &sa, 0);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, 0);
	sigaction(SIGXCPU, &sa, 0);

	// Currently we don't spawn children, but may as well leave this here
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
	sigaction(SIGCHLD, &sa, 0);
}

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
#define BCPID_OUTPUT_DIRECTORY "/var/tmp/"

// Force sample data to be saved on disk and
// purged from main memory when number of call graph
// edges exceeds this number
#define BCPID_EDGE_GC_THRESHOLD 10000

// Force sample data to be saved on disk and
// purged from main memory when number of call graph
// nodes exceeds this number
#define BCPID_NODE_GC_THRESHOLD 10000

// For performance reasons, hashes of object files are cached
// To prevent cache from growing unbounded, it is cleared
// when hashes of this many object files are cached
#define BCPID_OBJECT_HASH_GC_THRESHOLD 2000

// Default sampling interval
#define BCPID_DEFAULT_COUNT 16384

// Path to kernel object
#define BCPID_KERNEL_PATH "/boot/kernel/"

typedef void (*bcpid_event_handler)(struct bcpid *b, const struct pmclog_ev *);

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
	const char *name;
};

// Represent a distinct object file (executable or dynamic library)
struct bcpid_object {
	const char *path;
	struct timespec last_modified;
	bcpi_hash hash;

	// This has to be a map, because its ordinality is exploited
	// during compression
	std::map<uint64_t, struct bcpid_pc_node *> node_map;

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
	struct bcpid_object *obj;
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
	std::vector<struct bcpid_program_mapping> mappings;
};

struct bcpid_pc_node;

// An edge in a call chain graph
struct bcpid_pc_edge {
	uint64_t hits[BCPI_MAX_NUM_COUNTER];
	struct bcpid_pc_node *from;
	struct bcpid_pc_node *to;
};

// A vertex in a call chain graph
struct bcpid_pc_node {
	uint64_t value;
	uint64_t flag;
	struct bcpid_object *obj;
	uint64_t end_ctr[BCPI_MAX_NUM_COUNTER];

	// Map downstream node to the edge between nodes, where
	// counter numbers are actually stored
	std::unordered_map<struct bcpid_pc_node *, struct bcpid_pc_edge>
	    incoming_edge_map;

	// Used during compression
	int tmp_archive_node_index;
};

extern const char *g_bcpid_pmclog_name[];
extern const char *g_bcpid_pmclog_state_name[];
extern const char *g_bcpid_debug_counter_name[];

int g_quit;

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

struct bcpid {
	int num_pmclog_event;
	int num_cpu;

	int selfpid;
	struct procstat *procstat;
	void *pmclog_handle;

	int pipefd[2];
	int non_block_pipefd[2];
	int kqueue_fd;

	pthread_t pmclog_forward_thr;

	/* Whether this is the first time
	 * that we received call chain event from PMCLOG or not.
	 * Used for kernel object handling. (See replay_kernel_objects)
	 */
	bool first_callchain;

	uint64_t debug_counter[bcpid_debug_counter_max];

	struct bcpid_pmc_counter pmc_ctrs[BCPI_MAX_NUM_COUNTER];
	struct bcpid_pmc_cpu pmc_cpus[BCPID_MAX_CPU];
	struct bcpid_pmclog_event pmclog_events[BCPID_MAX_NUM_PMCLOG_EVENTS];

	int kevent_in_size;
	int kevent_out_size;
	struct kevent kevent_in_batch[BCPID_KEVENT_MAX_BATCH_SIZE];
	struct kevent kevent_out_batch[BCPID_KEVENT_MAX_BATCH_SIZE];

	std::unordered_map<pmc_id_t, struct bcpid_pmc_counter *>
	    pmcid_to_counter;
	std::unordered_map<int, struct bcpid_program *> pid_to_program;
	std::unordered_map<std::string, struct bcpid_object *> path_to_object;

	int default_count;
	const char *default_pmc;
	const char *default_output_dir;
	bool pmc_override;

	std::vector<bcpid_kernel_object> kernel_objects;

	struct rusage last_usage;

	int num_node;
	int num_edge;

	std::unordered_map<std::string, bcpid_hash_cache> object_hash_cache;

	int node_collect_threshold;
	int edge_collect_threshold;
	int object_hash_collect_threshold;
};

void
bcpid_debug_counter_increment(struct bcpid *b, enum bcpid_debug_counter ctr)
{
	++b->debug_counter[ctr];
}

/*
 * Initialize an object.
 * Main objective is to calculate its hash
 */
void
bcpid_object_init(bcpid *b, bcpid_object *obj, const char *path)
{
	obj->path = strdup(path);
	obj->hash = 0;
	memset(&obj->last_modified, 0, sizeof(obj->last_modified));

	struct stat s;
	int status = stat(path, &s);
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

	int file_fd = open(path, O_RDONLY | O_CLOEXEC);
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

	uint32_t hash = bcpi_crc32(file_content, file_size);

	status = munmap(file_content, file_size);
	if (status == -1) {
		PERROR("munmap");
	}

	status = close(file_fd);
	if (status == -1) {
		PERROR("close");
	}

	obj->hash = hash;
	if (oit == b->object_hash_cache.end()) {
		bcpid_hash_cache cache;
		cache.last_modified = s.st_mtim;
		cache.hash = hash;

		b->object_hash_cache.emplace(std::string(path), cache);
	} else {
		oit->second.hash = hash;
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
bcpid_pmglog_thread_main(void *arg)
{
	struct bcpid *b = (struct bcpid *)arg;

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
void
bcpid_report_pmc_ctr(struct bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		if (!b->pmc_ctrs[i].is_valid) {
			continue;
		}

		struct bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
		MSG("%s: %ld", spec->name, spec->hits);
	}
}

/*
 * Initialize object after receives MAP_IN event from PMCLOG
 */
void
bcpid_event_handler_mapin(struct bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_map_in *mi = &ev->pl_u.pl_mi;
	pid_t pid = mi->pl_pid;
	uintfptr_t start = mi->pl_start;
	const char *path = mi->pl_pathname;

	if (pid != -1) {
		return;
	}

	std::string object_path;

	// Path provided by PMCLOG is erroneous for kernel modules and kernel
	// itself This is fixed by prepending top level path to kernel and
	// modules
	if (!strcmp(path, "kernel") || strstr(path, ".ko")) {
		object_path = std::string(BCPID_KERNEL_PATH) +
		    std::string(path);
	}

	bcpid_kernel_object ko;
	ko.path = object_path;
	ko.start = start;

	b->kernel_objects.push_back(ko);
}

/*
 * Since a save to disk obliterates all in memory sample data and kernel
 * objects are reported only once by PMCLOG, we need to re-establish
 * them from caches.
 */
void
bcpid_replay_kernel_objects(struct bcpid *b)
{
	int pid = -1;
	struct bcpid_program *proc;
	auto pit = b->pid_to_program.find(pid);
	if (pit == b->pid_to_program.end()) {
		proc = new struct bcpid_program;
		proc->pid = pid;
		b->pid_to_program.emplace(pid, proc);
	} else {
		proc = pit->second;
	}

	for (const bcpid_kernel_object &ko : b->kernel_objects) {
		auto oit = b->path_to_object.find(ko.path);
		struct bcpid_object *obj;
		if (oit == b->path_to_object.end()) {
			obj = new struct bcpid_object;
			bcpid_object_init(b, obj, ko.path.c_str());
			b->path_to_object.emplace(ko.path, obj);
		} else {
			obj = oit->second;
		}

		struct bcpid_program_mapping m;
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
void
bcpid_garbage_collect(struct bcpid *b)
{
	for (auto p : b->path_to_object) {
		bcpid_object *o = p.second;
		for (auto np : o->node_map) {
			bcpid_pc_node *n = np.second;
			delete n;
		}
		free((void *)o->path);
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
int
bcpid_num_active_counter(struct bcpid *b)
{
	int num_counter = 0;
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];
		if (!ctr->is_valid) {
			continue;
		}

		++num_counter;
	}
	return num_counter;
}

void bcpid_stop_all(struct bcpid *);

/*
 * Save sample data on disk. All in-memory data
 * are obliterated
 */

void
bcpid_save(struct bcpid *b)
{
	struct bcpi_record *record = (struct bcpi_record *)malloc(
	    sizeof(*record));
	record->epoch = time(0);

	// Embed system description in the file
	struct utsname uts;
	int status = uname(&uts);
	if (status < 0) {
		PERROR("uname");
		record->system_name = strdup("");
	} else {
		char system_name[512];
		snprintf(system_name, 511, "%s %s %s %s %s", uts.sysname,
		    uts.release, uts.version, uts.nodename, uts.machine);
		record->system_name = strdup(system_name);
	}

	int num_counter = bcpid_num_active_counter(b);
	record->num_counter = num_counter;
	record->counter_name = (const char **)malloc(
	    sizeof(*record->counter_name) * num_counter);

	int name_index = 0;
	int index_mapping[BCPI_MAX_NUM_COUNTER];
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *ctr = &b->pmc_ctrs[i];
		if (!ctr->is_valid) {
			continue;
		}

		record->counter_name[name_index] = strdup(ctr->name);
		index_mapping[name_index] = i;
		++name_index;
	}

	int num_object = 0;
	for (auto &object_it : b->path_to_object) {
		struct bcpid_object *object = object_it.second;

		if (!object->node_map.size()) {
			continue;
		}

		++num_object;
	}

	record->num_object = num_object;
	record->object_list = (struct bcpi_object *)malloc(
	    sizeof(*record->object_list) * record->num_object);

	int object_index = 0;
	for (auto &object_it : b->path_to_object) {
		struct bcpid_object *object = object_it.second;
		struct bcpi_object *ro = &record->object_list[object_index];

		if (!object->node_map.size()) {
			continue;
		}

		object->tmp_archive_object_index = object_index;

		ro->path = strdup(object->path);
		ro->function_list = 0;
		ro->num_function = 0;
		ro->num_node = object->node_map.size();
		ro->node_list = (struct bcpi_node *)malloc(
		    sizeof(*ro->node_list) * ro->num_node);
		ro->object_index = object_index;

		int node_index = 0;
		for (auto &node_it : object->node_map) {
			struct bcpid_pc_node *node = node_it.second;
			struct bcpi_node *rn = &ro->node_list[node_index];

			node->tmp_archive_node_index = node_index;

			rn->object = ro;
			rn->node_address = node->value;
			rn->num_incoming_edge = node->incoming_edge_map.size();
			rn->edge_list = (struct bcpi_edge *)malloc(
			    sizeof(*rn->edge_list) * rn->num_incoming_edge);
			rn->node_index = node_index;

			for (int i = 0; i < name_index; ++i) {
				rn->terminal_counters[i] =
				    node->end_ctr[index_mapping[i]];
			}

			int edge_index = 0;
			for (auto &edge_it : node->incoming_edge_map) {
				struct bcpid_pc_edge *edge = &edge_it.second;
				struct bcpi_edge *re =
				    &rn->edge_list[edge_index];

				re->to = rn;
				/*
				 * Temporarily use this field to hold pointer to
				 * the originating node that is part of daemon
				 * data structure (as opposed to record data
				 * structure), since the latter may not have
				 * been allocated yet. Will be corrected during
				 * second pass.
				 */
				re->from = (struct bcpi_node *)edge->from;
				for (int i = 0; i < name_index; ++i) {
					re->counters[i] =
					    edge->hits[index_mapping[i]];
				}
				++edge_index;
			}
			++node_index;
		}
		++object_index;
	}

	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];
			for (int k = 0; k < rn->num_incoming_edge; ++k) {
				struct bcpi_edge *re = &rn->edge_list[k];
				/*
				 * Here we correct this field to point to record
				 * data structure using indexes that were set up
				 * during first pass
				 */
				struct bcpid_pc_node *node_from =
				    (struct bcpid_pc_node *)re->from;

				int from_index_object =
				    node_from->obj->tmp_archive_object_index;
				int from_index_node =
				    node_from->tmp_archive_node_index;

				struct bcpi_object *from_object =
				    &record->object_list[from_index_object];
				struct bcpi_node *from_node =
				    &from_object->node_list[from_index_node];
				re->from = from_node;
			}
		}
	}

	struct tm *t = gmtime((time_t *)&record->epoch);
	char time_buffer[128];

	strftime(time_buffer, 127, "%F_%T", t);

	char file_name[256];
	snprintf(file_name, 255, "%s/bcpi_%s_%s.bin", b->default_output_dir,
	    time_buffer, uts.nodename);
	status = bcpi_save_file(record, file_name);
	if (status) {
		bcpi_free(record);
		return;
	}

	struct bcpi_record *reverse_record;

	status = bcpi_load_file(file_name, &reverse_record);
	if (status) {
		bcpi_free(record);
		return;
	}

	bcpi_is_equal(record, reverse_record);

	bcpi_free(record);
	bcpi_free(reverse_record);

	bcpid_garbage_collect(b);

	MSG("saved at %s", file_name);
}

void
bcpid_program_mapping_dump(const std::vector<bcpid_program_mapping> &mappings)
{
	for (const bcpid_program_mapping &m : mappings) {
		fprintf(stderr, "%lx, %lx, %lx, %x\n", m.start, m.end,
		    m.file_offset, m.protection);
	}
}

/*
 * Obtain pointer to the node, given a program counter and a process.
 * This routine first finds the object that is mapped at that address,
 * it then retreives the node, and creates one if necessary.
 */
struct bcpid_pc_node *
bcpid_get_node_from_pc(struct bcpid *b, struct bcpid_program *proc, uint64_t pc)
{
	// Until there is a better way to distinguish kernel address,
	// this is currently used. Note that '-1' is PMCLOG's way of
	// saying 'kernel processes', and is perpetuated here.
	if (pc > BCPID_KERN_BASE) {
		proc = b->pid_to_program[-1];
	}

	struct bcpid_program_mapping m = { pc, 0, 0, 0, 0 };
	// Upper bound performs binary search. It is assumed that
	// there is no overlap in address spaces.
	auto it = upper_bound(proc->mappings.begin(), proc->mappings.end(), m,
	    bcpid_program_mapping_sort);
	if (it == proc->mappings.end()) {
		if (!proc->mappings.size()) {
			bcpid_debug_counter_increment(
			    b, bcpid_debug_empty_mapping_pc);
			return 0;
		}
	}
	if (it != proc->mappings.begin()) {
		--it;
	}

	struct bcpid_program_mapping *mapping = &*it;
	if (pc < mapping->start) {
		bcpid_debug_counter_increment(b, bcpid_debug_pc_before_mapping);
		return 0;
	}

	if (pc > mapping->end && proc->pid != -1) {
		bcpid_debug_counter_increment(b, bcpid_debug_pc_after_mapping);
		return 0;
	}

	struct bcpid_object *obj = mapping->obj;
	struct bcpid_pc_node *node;
	// Turn raw program counter into an address that can be located
	// in an ELF file.
	uint64_t real_addr = pc - mapping->start + mapping->file_offset;
	auto nit = obj->node_map.find(real_addr);
	if (nit == obj->node_map.end()) {
		b->num_node++;
		node = new struct bcpid_pc_node;
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
struct bcpid_program *
bcpid_init_proc(struct bcpid *b, int pid)
{
	uint32_t count;
	struct kinfo_proc *kproc = procstat_getprocs(
	    b->procstat, KERN_PROC_PID, pid, &count);
	if (!count || !kproc) {
		bcpid_debug_counter_increment(b, bcpid_debug_getprocs_fail);
		return 0;
	}

	struct kinfo_vmentry *vm = procstat_getvmmap(
	    b->procstat, kproc, &count);
	if (!count || !vm) {
		bcpid_debug_counter_increment(b, bcpid_debug_getvmmap_fail);
		procstat_freeprocs(b->procstat, kproc);
		return 0;
	}

	struct bcpid_program *exec = new struct bcpid_program;
	exec->pid = pid;

	struct kinfo_vmentry *cur_vm = vm;
	for (int i = 0; i < count; ++i, ++cur_vm) {
		if (cur_vm->kve_start > BCPID_KERN_BASE) {
			break;
		}

		std::string path(cur_vm->kve_path);
		auto oit = b->path_to_object.find(path);
		struct bcpid_object *obj;
		if (oit == b->path_to_object.end()) {
			obj = new struct bcpid_object;
			bcpid_object_init(b, obj, cur_vm->kve_path);
			b->path_to_object.emplace(path, obj);
		} else {
			obj = oit->second;
		}

		struct bcpid_program_mapping m;
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
int
bcpid_get_pmc_counter_index(struct bcpid *b, struct bcpid_pmc_counter *c)
{
	return c - b->pmc_ctrs;
}

/*
 * Handle a call chain event received from PMCLOG. Main objective
 * is to walk the entire call chain, possibly creating vertices and
 * edges in the meantime, and increment counters along the way.
 */
void
bcpid_event_handler_callchain(struct bcpid *b, const struct pmclog_ev *ev)
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

	struct bcpid_program *proc;
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

	struct bcpid_pmc_counter *spec;
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
	struct bcpid_pc_node *to_node;
	struct bcpid_pc_node *from_node;

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
		struct bcpid_pc_edge *e;
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
void
bcpid_event_handler_proc_exec(struct bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_procexec *pe = &ev->pl_u.pl_x;
	const char *main_object_path = pe->pl_pathname;

	auto oit = b->path_to_object.find(std::string(main_object_path));
	if (oit == b->path_to_object.end()) {
		return;
	}

	struct stat s;
	int status = stat(main_object_path, &s);
	if (status == -1) {
		return;
	}

	struct timespec *ts = &s.st_mtim;
	if (!memcmp(ts, &oit->second->last_modified, sizeof(*ts))) {
		return;
	}

	MSG("saving due to newer executable: %s", main_object_path);
	bcpid_save(b);
}

void
bcpid_event_handler_proc_fork(struct bcpid *b, const struct pmclog_ev *ev)
{
}

void
bcpid_event_handler_proc_create(struct bcpid *b, const struct pmclog_ev *ev)
{
}

/*
 * Handle process exit.
 */
void
bcpid_event_handler_sysexit(struct bcpid *b, const struct pmclog_ev *ev)
{
	const struct pmclog_ev_sysexit *ex = &ev->pl_u.pl_se;

	auto pit = b->pid_to_program.find(ex->pl_pid);
	if (pit == b->pid_to_program.end()) {
		return;
	}

	struct bcpid_program *prog = pit->second;

	b->pid_to_program.erase(pit);
	delete prog;
}

void
bcpid_register_handlers(struct bcpid *b)
{
	int n = 0;
	for (const char **name = g_bcpid_pmclog_name; *name; ++name, ++n) {
		struct bcpid_pmclog_event *ev = &b->pmclog_events[n];
		ev->is_valid = true;
		ev->name = *name;
	}

	b->num_pmclog_event = n;

	struct bcpid_pmclog_event *ev;
	ev = &b->pmclog_events[PMCLOG_TYPE_MAP_IN];
	ev->handler = bcpid_event_handler_mapin;

	ev = &b->pmclog_events[PMCLOG_TYPE_CALLCHAIN];
	ev->handler = bcpid_event_handler_callchain;

	ev = &b->pmclog_events[PMCLOG_TYPE_PROC_CREATE];
	ev->handler = bcpid_event_handler_proc_create;

	ev = &b->pmclog_events[PMCLOG_TYPE_SYSEXIT];
	ev->handler = bcpid_event_handler_sysexit;

	ev = &b->pmclog_events[PMCLOG_TYPE_PROCFORK];
	ev->handler = bcpid_event_handler_proc_fork;
}

/*
 * A wrapper to batch kqueue event updates and to reduce number of calls to
 * kqueue
 */
void
bcpid_kevent_set(struct bcpid *b, uintptr_t ident, short filter, u_short flags,
    u_int fflags, int64_t data, void *udata)
{
	int cur_size = b->kevent_in_size;
	assert(cur_size < BCPID_KEVENT_MAX_BATCH_SIZE);
	EV_SET(&b->kevent_in_batch[cur_size], ident, filter, flags, fflags,
	    data, udata);
	b->kevent_in_size++;
}

void
bcpid_pmc_init(struct bcpid *b)
{
	int status;

	status = pmc_init();
	if (status < 0) {
		PERROR("pmc_init");
		exit(1);
	}
}

/*
 * Allocate a PMC counter on all CPUs.
 */
void
bcpid_alloc_pmc(struct bcpid *b, const char *name, int count)
{
	struct bcpid_pmc_counter *ctr = 0;
	int counter_index = 0;
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (c->is_valid) {
			continue;
		}

		ctr = c;
		counter_index = i;
		break;
	}

	if (!ctr) {
		MSG("cannot add %s: all %d pmcs allocated", name,
		    BCPI_MAX_NUM_COUNTER);
		return;
	}
	MSG("allocating %s", name);

	for (int i = 0; i < b->num_cpu; ++i) {
		struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[i];
		pmc_id_t pmc_id;
		int status = pmc_allocate(
		    name, PMC_MODE_SS, PMC_F_CALLCHAIN, i, &pmc_id, count);
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
	ctr->name = strdup(name);
	ctr->hits = 0;
fail:
	return;
}

/*
 * Release an allocated PMC counter on all CPUs.
 */
void
bcpid_release_pmc(struct bcpid *b, const char *name, bool invalidate)
{
	struct bcpid_pmc_counter *ctr = 0;
	int counter_index = 0;
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}
		if (strcmp(c->name, name)) {
			continue;
		}
		ctr = c;
		counter_index = i;
		break;
	}

	if (!ctr) {
		MSG("cannot release %s: does not exist", name);
		return;
	}

	MSG("releasing %s", name);

	for (int i = 0; i < b->num_cpu; ++i) {
		struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[i];
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
		b->pmcid_to_counter.erase(it);
	}

	if (invalidate) {
		ctr->is_valid = false;
		ctr->hits = 0;
		free((void *)ctr->name);
		ctr->name = 0;
	}
}

void
bcpid_setup_pmc(struct bcpid *b)
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

	status = pthread_create(
	    &b->pmclog_forward_thr, 0, bcpid_pmglog_thread_main, b);
	if (status != 0) {
		SYSERROR("pthred_create: %s", strerror(status));
	}

	// Read name of counters from argv, if present
	if (b->pmc_override) {
		char *pmc_name_cpy = strdup(b->default_pmc);
		const char *delim = ", ";
		const char *pmc_name = strtok(pmc_name_cpy, delim);
		while (pmc_name) {
			bcpid_alloc_pmc(b, pmc_name, b->default_count);
			pmc_name = strtok(0, delim);
		}
		free(pmc_name_cpy);
		return;
	}

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

	FILE *file = fopen(conf_name, "r");
	if (!file) {
		return;
	}

	for (;;) {
		char ctr[128];
		char *s = fgets(ctr, 127, file);
		if (!s) {
			break;
		}
		ctr[strcspn(ctr, "\r\n")] = 0;
		bcpid_alloc_pmc(b, ctr, b->default_count);
	}

	b->first_callchain = false;
}

/*
 * PMCLOG event dispatcher
 */
void
bcpid_handle_pmclog(struct bcpid *b)
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

		struct bcpid_pmclog_event *bpev = &b->pmclog_events[ev.pl_type];
		++bpev->num_fire;

		bcpid_event_handler handler = bpev->handler;

		if (handler) {
			handler(b, &ev);
		}
	}
}

void bcpid_printcpu();

void
bcpid_stop_all(struct bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		for (int j = 0; j < b->num_cpu; ++j) {
			struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
			int status = pmc_stop(cpu->pmcs[i]);
			if (status < 0) {
				PERROR("pmc_stop");
			}
		}
	}
}

void
bcpid_start_all(struct bcpid *b)
{
	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		for (int j = 0; j < b->num_cpu; ++j) {
			struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
			int status = pmc_start(cpu->pmcs[i]);
			if (status < 0) {
				PERROR("pmc_start");
			}
		}
	}
}

void
bcpid_handle_stdin(struct bcpid *b)
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
		int count = b->default_count;
		char *ctr = strtok(0, delim);
		if (ctr) {
			count = atoi(ctr);
		}
		bcpid_alloc_pmc(b, name, count);
	} else if (!strcmp(arg, "release")) {
		char *name = strtok(0, delim);
		if (!name) {
			goto fail;
		}
		bcpid_release_pmc(b, name, true);
	} else if (!strcmp(arg, "pmcs")) {
		bcpid_printcpu();
	} else if (!strcmp(arg, "debug")) {
		fprintf(stderr, "%ld processes\n", b->pid_to_program.size());

		fprintf(stderr, "%ld objects\n", b->path_to_object.size());
		fprintf(stderr, "%d nodes\n", b->num_node);
		fprintf(stderr, "%d edges\n", b->num_edge);
		for (int i = 0; i < bcpid_debug_counter_max; ++i) {
			fprintf(stderr, "%s: %ld\n",
			    g_bcpid_debug_counter_name[i], b->debug_counter[i]);
		}
	} else if (!strcmp(arg, "save")) {
		bcpid_save(b);
	} else if (!strcmp(arg, "stop")) {
		bcpid_stop_all(b);
	} else if (!strcmp(arg, "start")) {
		bcpid_start_all(b);
	} else if (!strcmp(arg, "quit")) {
		g_quit = 1;
	} else if (!strcmp(arg, "leak")) {
		char *times = strtok(0, delim);
		if (!times) {
			goto fail;
		}
		int time = atoi(times);
		for (int i = 0; i < time; ++i) {
			bcpid_save(b);
		}
	} else {
		MSG("unknown command: %s", arg);
	}

	return;
fail:
	(void)0;
}

struct bcpid_statistics {
	int num_object;
	int num_program;
	int num_node;
	int num_edge;
	int num_object_hash;
};

void
bcpid_collect_struct_stat(bcpid *b, bcpid_statistics *s)
{
	s->num_edge = b->num_edge;
	s->num_node = b->num_node;
	s->num_object = b->path_to_object.size();
	s->num_program = b->pid_to_program.size();
	s->num_object_hash = b->object_hash_cache.size();
}

uint64_t
tv_to_sec(const struct timeval *r)
{
	uint64_t t = 0;
	t += r->tv_usec;
	t += r->tv_usec;
	t += r->tv_sec * 1000000;
	t += r->tv_sec * 1000000;
	return t;
}

/*
 * Periodically run piece of code. See BCPID_INTERVAL for period.
 * Currently it collects performance metrics of daemon, and
 * save sample data to disk if they become too big.
 */
void
bcpid_handle_timer(bcpid *b)
{
	struct rusage r;
	int status;
	uint64_t new_time, old_time, time_diff;

	status = getrusage(RUSAGE_SELF, &r);
	if (status != 0) {
		PERROR("getrusage");
		abort();
	}

	new_time = tv_to_sec(&r.ru_utime) + tv_to_sec(&r.ru_stime);
	old_time = tv_to_sec(&b->last_usage.ru_utime) +
	    tv_to_sec(&b->last_usage.ru_stime);
	time_diff = new_time - old_time;
	/*
	fprintf(stderr, "%f\n", (double)time_diff/(double)1000000);

	fprintf(stderr, "%lu (d %lu) M %lu T %lu D %lu S %lu\n", new_time,
		new_time - old_time, r.ru_maxrss, r.ru_ixrss, r.ru_idrss,
		r.ru_isrss);
	*/
	bcpid_statistics stats;
	bcpid_collect_struct_stat(b, &stats);
	/*
	fprintf(stderr, "%d %d %d %d %d\n", stats.num_object, stats.num_program,
		stats.num_node, stats.num_edge, stats.num_object_hash);
	*/
	if (stats.num_edge > b->edge_collect_threshold ||
	    stats.num_node > b->node_collect_threshold) {
		MSG("saving...");
		bcpid_save(b);
	}

	if (stats.num_object_hash > b->object_hash_collect_threshold) {
		b->object_hash_cache.clear();
	}

	b->last_usage = r;
}

void
bcpid_main_loop(struct bcpid *b)
{
	while (!g_quit) {
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
		}
	}

	bcpid_save(b);
}

void
bcpid_shutdown(struct bcpid *b)
{
	pmclog_close(b->pmclog_handle);

	for (int i = 0; i < BCPI_MAX_NUM_COUNTER; ++i) {
		struct bcpid_pmc_counter *c = &b->pmc_ctrs[i];
		if (!c->is_valid) {
			continue;
		}

		bcpid_release_pmc(b, c->name, false);
	}

	int status = pmc_configure_logfile(-1);
	if (status < 0) {
		PERROR("pmc_configure_logfile");
	}
}

void
bcpid_report(struct bcpid *b)
{
	for (int i = 0; i < b->num_pmclog_event; ++i) {
		struct bcpid_pmclog_event *spec = &b->pmclog_events[i];
		if (!spec->name) {
			continue;
		}
		MSG("%s fired %lu times", spec->name, spec->num_fire);
	}

	bcpid_report_pmc_ctr(b);
}

void bcpid_printcpu();
void bcpid_print_pmcs();
void bcpid_print_events();
void bcpid_term_handler(int);

void
bcpid_parse_global_config(struct bcpid *b)
{
	MSG("bcpid_parse_global_config() is unimplemented");
	abort();
}

static void
usage()
{
	fprintf(stderr,
	    "Usage: bcpid [-c count] [-p pmc] [-o dir]\n"
	    "\t-c count -- Sampling interval\n"
	    "\t-h -- Help\n"
	    "\t-o dir -- Output director\n"
	    "\t-l -- List PMCs\n"
	    "\t-p pmc[, ...] -- List of pmc to monitor\n");
}

bool
bcpid_parse_options(struct bcpid *b, int argc, const char *argv[])
{
	int opt;
	struct stat s;

	b->default_count = BCPID_DEFAULT_COUNT;
	b->default_pmc = "";
	b->default_output_dir = BCPID_OUTPUT_DIRECTORY;
	b->pmc_override = false;
	b->edge_collect_threshold = BCPID_EDGE_GC_THRESHOLD;
	b->node_collect_threshold = BCPID_NODE_GC_THRESHOLD;
	b->object_hash_collect_threshold = BCPID_OBJECT_HASH_GC_THRESHOLD;

	while ((opt = getopt(argc, (char **)argv, "hc:p:lo:")) != -1) {
		switch (opt) {
		case 'c':
			b->default_count = atoi(optarg);
			break;
		case 'h': {
			usage();
			exit(EX_OK);
		}
		case 'l': {
			bcpid_printcpu();
			exit(EX_OK);
		}
		case 'p': {
			b->pmc_override = true;
			b->default_pmc = strdup(optarg);
			break;
		}
		case 'o': {
			b->default_output_dir = strdup(optarg);
			break;
		}
		default:
			usage();
			exit(EX_USAGE);
		}
	}

	if (stat(BCPID_OUTPUT_DIRECTORY, &s) == -1) {
		MSG("Please create directory %s", BCPID_OUTPUT_DIRECTORY);
		return false;
	}

	MSG("count set to %d", b->default_count);
	if (b->pmc_override) {
		MSG("overriding pmc counters to %s", b->default_pmc);
	}
	return true;
}

int
main(int argc, const char *argv[])
{
	bcpid_signal_init(bcpid_term_handler);

	struct bcpid b;

	bcpid_pmc_init(&b);

	if (!bcpid_parse_options(&b, argc, argv)) {
		return 0;
	}

	bcpid_setup_pmc(&b);
	bcpid_main_loop(&b);
	bcpid_shutdown(&b);
	bcpid_report(&b);
	return 0;
}

void
bcpid_printcpu()
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
	for (int i = 0; i < cpuinfo->pm_nclass; i++) {
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

void
bcpid_print_pmcs()
{
	int status;
	int npmcs = pmc_npmc(0);
	struct pmc_pmcinfo *pmcinfo;

	status = pmc_pmcinfo(0, &pmcinfo);
	if (status < 0) {
		PERROR("pmc_pmcinfo");
		exit(1);
	}

	MSG("---Dump PMCs---");
	MSG("# of PMCs: %d", npmcs);

	for (int i = 0; i < npmcs; i++) {
		struct pmc_info *p = &pmcinfo->pm_pmcs[i];
		MSG("Name: %s, Class: %s, Mode: %s", p->pm_name,
		    pmc_name_of_class(p->pm_class),
		    pmc_name_of_mode(p->pm_mode));
	}
}

void
bcpid_print_events()
{
	int status;
	const struct pmc_cpuinfo *cpuinfo;

	status = pmc_cpuinfo(&cpuinfo);
	if (status < 0) {
		PERROR("pmc_cpuinfo");
		exit(1);
	}

	MSG("--- Dump Events ---");
	for (int i = 0; i < cpuinfo->pm_nclass; i++) {
		int evts;
		const char **evtlst;
		enum pmc_class c = cpuinfo->pm_classes[i].pm_class;

		status = pmc_event_names_of_class(c, &evtlst, &evts);
		if (status < 0) {
			PERROR("pmc_event_names_of_class");
			return;
		}

		MSG("Class: %s", pmc_name_of_class(c));
		for (int j = 0; j < evts; j++) {
			fprintf(stderr, "  %s\n", evtlst[j]);
		}
	}
}

void
bcpid_term_handler(int num)
{
	g_quit = 1;
	MSG("received %s", strsignal(num));
}

const char *g_bcpid_pmclog_name[] = { "PMCLOG_TYPE_PADDING",
	"PMCLOG_TYPE_CLOSEMSG", "PMCLOG_TYPE_DROPNOTIFY",
	"PMCLOG_TYPE_INITIALIZE", "PMCLOG_TYPE_PADDING",
	"PMCLOG_TYPE_PMCALLOCATE", "PMCLOG_TYPE_PMCATTACH",
	"PMCLOG_TYPE_PMCDETACH", "PMCLOG_TYPE_PROCCSW", "PMCLOG_TYPE_PROCEXEC",
	"PMCLOG_TYPE_PROCEXIT", "PMCLOG_TYPE_PROCFORK", "PMCLOG_TYPE_SYSEXIT",
	"PMCLOG_TYPE_USERDATA", "PMCLOG_TYPE_MAP_IN", "PMCLOG_TYPE_MAP_OUT",
	"PMCLOG_TYPE_CALLCHAIN", "PMCLOG_TYPE_PMCALLOCATEDYN",
	"PMCLOG_TYPE_THR_CREATE", "PMCLOG_TYPE_THR_EXIT",
	"PMCLOG_TYPE_PROC_CREATE", 0 };

const char *g_bcpid_pmclog_state_name[] = { "PMCLOG_OK", "PMCLOG_EOF",
	"PMCLOG_REQUIRE_DATA", "PMCLOG_ERROR", 0 };

const char *g_bcpid_debug_counter_name[] = {
	"bcpid_debug_empty_mapin_name",
	"bcpid_debug_empty_mapping_pc",
	"bcpid_debug_pc_before_mapping",
	"bcpid_debug_pc_after_mapping",
	"bcpid_debug_getprocs_fail",
	"bcpid_debug_getvmmap_fail",
	"bcpid_debug_callchain_self_fire",
	"bcpid_debug_callchain_proc_init_fail",
	"bcpid_debug_callchain_counter_gone",
	"bcpid_debug_callchain_pc_skip",
	"bcpid_debug_counter_max",
};
