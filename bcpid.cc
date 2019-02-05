#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>

#include <sys/event.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <pmc.h>
#include <pmclog.h>

#include <libprocstat.h>

#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <set>
#include <algorithm>

#include "debug.h"

using namespace std;

// Return the symbol that corresponds to object file
// located at object_path locally, at offset.
// Offset is measured from the beginning of the section
// that is usually mapped as read and execute 
// (or code section)

const char *
bcpid_get_symbol(const char *object_path, uint64_t offset)
{
    return "";
}

uint64_t 
os_get_milli() 
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec/1000000;
}

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

    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, 0);
}

#define BCPID_MAX_PMC 16
#define BCPID_MAX_PMCLOG_EVENTS 32
#define BCPID_MAX_CPU 128
#define BCPID_KERN_BASE 0x7fff00000000UL
#define BCPID_MAX_DEPTH 10
#define BCPID_TOP_ENTRIES 5

typedef void (*bcpid_event_handler)(struct bcpid *b, const struct pmclog_ev *);

struct bcpid_pmclog_event 
{
    bool is_valid;
    const char *name;
    uint64_t num_fire;
    bcpid_event_handler handler;
};

struct bcpid_pmc_cpu 
{
    uint32_t pmc_valid;
    pmc_id_t pmcs[BCPID_MAX_PMC];
};

struct bcpid_pmc_counter 
{
    bool is_valid;
    int id;
    uint64_t hits;
    const char *name;
};

struct bcpid_object 
{
    const char *path;
    unordered_map<uint64_t, struct bcpid_pc_node *> node_map; 
};

struct bcpid_program_mapping 
{
    uint64_t start;
    struct bcpid_object *obj;
};

bool 
bcpid_program_mapping_sort(const struct bcpid_program_mapping &me, 
        const struct bcpid_program_mapping &other) 
{
    return me.start < other.start;
}

struct bcpid_program 
{
    int pid;
    vector<struct bcpid_program_mapping> mappings;
};

struct bcpid_pc_node;

struct bcpid_pc_edge 
{
    uint64_t hits[BCPID_MAX_PMC];
    struct bcpid_pc_node *from;
    struct bcpid_pc_node *to;
};

int g_bcpid_pc_edge_sort_counter_id;

bool 
bcpid_pc_edge_sort(const struct bcpid_pc_edge *me, 
        const struct bcpid_pc_edge *other) 
{ 
    return me->hits[g_bcpid_pc_edge_sort_counter_id] > 
        other->hits[g_bcpid_pc_edge_sort_counter_id]; 
}

struct bcpid_pc_node 
{
    uint64_t value;
    uint64_t flag;
    struct bcpid_object *obj;
    unordered_map<struct bcpid_pc_node *, struct bcpid_pc_edge *> edge_map;
};

extern const char *g_bcpid_pmc_event_name[];
extern const char *g_bcpid_pmclog_name[];
extern const char *g_bcpid_pmclog_state_name[];

int g_quit;

#define BCPID_KEVENT_MAX_BATCH_SIZE 16

struct bcpid 
{
    int num_pmclog_event;
    int num_pmc_event;
    int num_cpu;

    int selfpid;
    struct procstat* procstat;
    void *pmclog_handle;

    int pipefd[2];
    int non_block_pipefd[2];
    int kqueue_fd;

    pthread_t pmclog_forward_thr;

    int default_count;

    struct bcpid_pmc_counter pmc_ctrs[BCPID_MAX_PMC];
    struct bcpid_pmclog_event pmclog_events[BCPID_MAX_PMCLOG_EVENTS];
    struct bcpid_pmc_cpu pmc_cpus[BCPID_MAX_CPU];

    int kevent_in_size;
    int kevent_out_size;
    struct kevent kevent_in_batch[BCPID_KEVENT_MAX_BATCH_SIZE];
    struct kevent kevent_out_batch[BCPID_KEVENT_MAX_BATCH_SIZE];

    unordered_map<pmc_id_t, struct bcpid_pmc_counter *> pmcid_to_counter;
    unordered_map<int, struct bcpid_program *> pid_to_program; 
    unordered_map<string, struct bcpid_object *> path_to_object; 
};


void *bcpid_pmglog_thread_main(void *arg) {
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
            int nw = write(non_block_pmclog_fd, &buffer[cursor], n - cursor);
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

void 
report_single_node(struct bcpid *b, struct bcpid_pc_node *node, int depth) 
{
    int cur_counter_id = g_bcpid_pc_edge_sort_counter_id;
    if (node->flag & (1 << cur_counter_id)) {
        return; 
    }
    node->flag |= (1 << cur_counter_id);
    if (depth < 0) {
        fprintf(stderr, "%*c ......\n", BCPID_MAX_DEPTH, ' ');
        return;
    }
    vector<struct bcpid_pc_edge *> edges;
    for (auto &p: node->edge_map) {
        struct bcpid_pc_edge *edge = p.second;
        edges.emplace_back(edge);
    }
    sort(edges.begin(), edges.end(), bcpid_pc_edge_sort);
    int top = edges.size() < BCPID_TOP_ENTRIES ? edges.size() : 
        BCPID_TOP_ENTRIES; 
    double spec_total = b->pmc_ctrs[cur_counter_id].hits; 
    for (int i = 0; i < top; ++i) {
        struct bcpid_pc_edge *edge = edges[i]; 

        uint64_t hit = edge->hits[cur_counter_id];
        if (!hit) {
            break;
        }
        struct bcpid_pc_node *from_node = edge->from;
        struct bcpid_object *from_obj = from_node->obj;
        struct bcpid_pc_node *to_node = edge->to;
        struct bcpid_object *to_obj = to_node->obj;
        fprintf(stderr, "%*c", BCPID_MAX_DEPTH - depth, ' ');
        fprintf(stderr, "%.2f (%ld) %lx (%s) (%s) -> %lx (%s) (%s)\n", 
                hit/spec_total, hit, from_node->value, 
                bcpid_get_symbol(from_obj->path, from_node->value), 
                from_obj->path, to_node->value, 
                bcpid_get_symbol(to_obj->path, to_node->value), 
                to_obj->path);
        report_single_node(b, to_node, depth - 1);
    }
}

void 
bcpid_report_edge(struct bcpid *b) 
{
    uint64_t num_obj = 0, num_node = 0, num_edge = 0;
    vector<struct bcpid_pc_edge *> edges;
    for (auto &it: b->path_to_object) {
        ++num_obj;
        struct bcpid_object *obj = it.second;
        for (auto &it2: obj->node_map) {
            ++num_node;
            struct bcpid_pc_node *pc = it2.second;
            for (auto &it3: pc->edge_map) {
                ++num_edge;
                struct bcpid_pc_edge *edge = it3.second;
                edges.emplace_back(edge);
            }
        }
    }
    MSG("%ld obj, %ld node, %ld edge", num_obj, num_node, num_edge);
    for (int i = 0; i < b->num_pmc_event; ++i) {
        g_bcpid_pc_edge_sort_counter_id = i;
        sort(edges.begin(), edges.end(), bcpid_pc_edge_sort); 
        struct bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
        double spec_total = spec->hits;
        MSG("top %d %s", BCPID_TOP_ENTRIES, spec->name);
        int end = num_edge < BCPID_TOP_ENTRIES ? num_edge : BCPID_TOP_ENTRIES;
        for (int j = 0; j < end; ++j) {
            struct bcpid_pc_edge *edge = edges[j];       
            uint64_t hit = edge->hits[i];
            if (!hit) {
                break;
            }

            struct bcpid_pc_node *from_node = edge->from;
            struct bcpid_object *from_obj = from_node->obj;
            struct bcpid_pc_node *to_node = edge->to;
            struct bcpid_object *to_obj = to_node->obj;
            
            report_single_node(b, edge->from, BCPID_MAX_DEPTH-1);
        }    
    }
}

void 
bcpid_report_pmc_ctr(struct bcpid *b) 
{
    for (int i = 0; i < b->num_pmc_event; ++i) {
        struct bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
        MSG("%s: %ld", spec->name, spec->hits);
    }
}

void 
bcpid_event_handler_mapin(struct bcpid *b, const struct pmclog_ev *ev) 
{
    const struct pmclog_ev_map_in *mi = &ev->pl_u.pl_mi;
    pid_t pid = mi->pl_pid;
    uintfptr_t start = mi->pl_start;
   
    if (!mi->pl_pathname[0]) {
        return;
    }

    string path(mi->pl_pathname); 
    auto oit = b->path_to_object.find(path);
    struct bcpid_object *obj;
    if (oit == b->path_to_object.end()) {
        obj = new struct bcpid_object;
        obj->path = strdup(mi->pl_pathname);
        b->path_to_object.emplace(make_pair(path, obj));
    } else {
        obj = oit->second;
    }

    if (pid != -1) {
        return;
    }

    struct bcpid_program *proc; 
    auto pit = b->pid_to_program.find(pid);
    if (pit == b->pid_to_program.end()) {
        proc = new struct bcpid_program;
        proc->pid = pid;
        b->pid_to_program.emplace(make_pair(pid, proc));
    } else {
        proc = pit->second;
    }

    struct bcpid_program_mapping m;
    m.start = mi->pl_start;
    m.obj = obj;

    proc->mappings.emplace_back(m);
    sort(proc->mappings.begin(), proc->mappings.end(), 
            bcpid_program_mapping_sort);
}

struct bcpid_pc_node *
bcpid_get_node_from_pc(struct bcpid *b, struct bcpid_program *proc, 
        uint64_t pc) 
{
    if (pc > BCPID_KERN_BASE) {
       proc = b->pid_to_program[-1]; 
    }

    struct bcpid_program_mapping m = {pc, 0};
    auto it = upper_bound(proc->mappings.begin(), proc->mappings.end(), m, 
            bcpid_program_mapping_sort);
    if (it == proc->mappings.end()) {
        if (!proc->mappings.size()) {
            return 0;
        }
    }
    if (it != proc->mappings.begin()) {
        --it;
    }

    struct bcpid_program_mapping *mapping = &*it;
    if (pc < mapping->start) {
        return 0;
    }

    struct bcpid_object *obj = mapping->obj;
    struct bcpid_pc_node *node;
    uint64_t real_addr = pc-mapping->start;
    auto nit = obj->node_map.find(real_addr);
    if (nit == obj->node_map.end()) {
        node = new struct bcpid_pc_node;
        node->value = real_addr;
        node->obj = obj;

        obj->node_map.emplace(make_pair(real_addr, node));
    } else {
        node = nit->second;
    }

    return node;
}

struct bcpid_program *
bcpid_init_proc(struct bcpid *b, int pid) 
{
    uint32_t count;
    struct kinfo_proc *kproc = procstat_getprocs(b->procstat, KERN_PROC_PID, 
            pid, &count);
    if (!count || !kproc) {
        return 0;
    }

    struct kinfo_vmentry *vm = procstat_getvmmap(b->procstat, kproc, &count);
    if (!count || !vm) {
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

        if (cur_vm->kve_protection != (KVME_PROT_READ | KVME_PROT_EXEC)) {
            continue;
        }

        string path(cur_vm->kve_path);
        auto oit = b->path_to_object.find(path);
        struct bcpid_object *obj;
        if (oit == b->path_to_object.end()) {
            obj = new struct bcpid_object;
            obj->path = strdup(cur_vm->kve_path);
            b->path_to_object.insert(make_pair(path, obj));
        } else {
            obj = oit->second;
        }

        struct bcpid_program_mapping m;
        m.start = cur_vm->kve_start;
        m.obj = obj;

        exec->mappings.emplace_back(m);
    }

    sort(exec->mappings.begin(), exec->mappings.end(), 
            bcpid_program_mapping_sort);

    procstat_freevmmap(b->procstat, vm);
    procstat_freeprocs(b->procstat, kproc);
    return exec;    
}

void 
bcpid_event_handler_callchain(struct bcpid *b, const struct pmclog_ev *ev) 
{
    const struct pmclog_ev_callchain *cc = &ev->pl_u.pl_cc; 

    int pid = cc->pl_pid;
    if (pid == b->selfpid) {
        return;
    }

    struct bcpid_program *proc;
    auto it = b->pid_to_program.find(pid);
    if (it == b->pid_to_program.end()) {
        proc = bcpid_init_proc(b, pid);
        if (!proc) {
            return;
        }
        b->pid_to_program.emplace(make_pair(pid, proc));
    } else {
        proc = it->second; 
    }

    struct bcpid_pmc_counter *spec;
    auto sit = b->pmcid_to_counter.find(cc->pl_pmcid);
    spec = sit->second;
    ++spec->hits;

    int chain_len = cc->pl_npc;
    struct bcpid_pc_node *to_node; 
    struct bcpid_pc_node *from_node; 

    for (int i = 1; i < chain_len; ++i) {
        uint64_t to_pc = cc->pl_pc[i-1];
        uint64_t from_pc = cc->pl_pc[i];

        if (i > 1) {
            from_node = to_node;
        } else { 
            from_node = bcpid_get_node_from_pc(b, proc, from_pc);
        }
        to_node = bcpid_get_node_from_pc(b, proc, to_pc);
        if (!to_node || !from_node) {
            continue;
        }
 
        auto *map = &from_node->edge_map;
        auto eit = map->find(to_node);
        struct bcpid_pc_edge *e;
        if (eit == map->end()) {
            e = new struct bcpid_pc_edge; 
            memset(e->hits, 0, sizeof(e->hits));
            e->from = from_node;
            e->to = to_node;
 
            map->insert(make_pair(to_node, e));
        } else {
            e = eit->second; 
        }

        ++e->hits[spec->id];
    }
}

void 
bcpid_event_handler_proc_create(struct bcpid *b, const struct pmclog_ev *ev) 
{
    const struct pmclog_ev_proccreate *pc  = &ev->pl_u.pl_pc;
    int pid = pc->pl_pid;
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
}

void 
bcpid_kevent_set(struct bcpid *b, uintptr_t ident, short filter, u_short flags,
        u_int fflags, int64_t data, void *udata) 
{
    int cur_size = b->kevent_in_size;
    assert(cur_size < BCPID_KEVENT_MAX_BATCH_SIZE);
    EV_SET(&b->kevent_in_batch[cur_size], ident, filter, flags, fflags, data,
            udata);
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
    memset(b->pmclog_events, 0, sizeof(b->pmclog_events));
    memset(b->pmc_cpus, 0, sizeof(b->pmc_cpus));

    int n = 0;
    for (const char **event_name = g_bcpid_pmc_event_name; *event_name; 
            ++event_name, ++n) {
        struct bcpid_pmc_counter *spec = &b->pmc_ctrs[n];
        spec->id = n;
        spec->name = *event_name;

        bool has_valid = false;
        for (int i = 0; i < b->num_cpu; ++i) {
            struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[i];
            pmc_id_t pmc;
            status = pmc_allocate(spec->name, PMC_MODE_SS, PMC_F_CALLCHAIN, 
                    i, &pmc, b->default_count);
            if (status < 0) {
                PERROR("pmc_allocate");
                break;
            } else {
                b->pmcid_to_counter.insert(make_pair(pmc, spec));
                cpu->pmcs[n] = pmc;
                cpu->pmc_valid |= (1 << n);
                has_valid = true;
            }
        }

        spec->is_valid = has_valid;
    }

    b->num_pmc_event = n;
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

    for (int i = 0; i < b->num_pmc_event; ++i) {
        struct bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
        if (!spec->is_valid) {
            continue;
        }
        for (int j = 0; j < b->num_cpu; ++j) {
            struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
            if (!(cpu->pmc_valid & (1 << i))) {
                continue;
            }
            status = pmc_start(cpu->pmcs[i]);
            if (status < 0) {
                PERROR("pmc_start");
            }
        }
    }

    b->pmclog_handle = pmclog_open(b->non_block_pipefd[0]);
    if (!b->pmclog_handle) {
        PERROR("pmclog_open");
    }

    bcpid_register_handlers(b);

    b->kqueue_fd = kqueue();
    if (b->kqueue_fd < 0) {
        PERROR("kqueue");
    }
    
    bcpid_kevent_set(b, b->non_block_pipefd[0], EVFILT_READ, EV_ADD, 0, 0, 0);

    status = pthread_create(&b->pmclog_forward_thr, 0, bcpid_pmglog_thread_main, b);
    if (status != 0) {
        SYSERROR("pthred_create: %s", strerror(status));
    }
}

void
bcpid_handle_pmclog(struct bcpid *b)
{
    struct pmclog_ev ev;
    for (;;) {
        pmclog_read(b->pmclog_handle, &ev);
        if (ev.pl_state != PMCLOG_OK) {
            if (ev.pl_state != PMCLOG_REQUIRE_DATA) {
                const char *state_name = g_bcpid_pmclog_state_name[ev.pl_state];
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

void 
bcpid_main_loop(struct bcpid *b) 
{
    while (!g_quit) {
        int r = kevent(b->kqueue_fd, b->kevent_in_batch, b->kevent_in_size,
                b->kevent_out_batch, b->kevent_out_size, 0);
        b->kevent_in_size = 0;
        if (r < 0) {
            PERROR("kqueue");
            break;
        }

        for (int i = 0; i < r; ++i) {
            struct kevent *ke = &b->kevent_out_batch[i];
            if (ke->filter == EVFILT_READ) {
                if (ke->ident == (unsigned long )b->non_block_pipefd[0]) {
                    bcpid_handle_pmclog(b);
                }
            }
        }
    }
}

void
bcpid_shutdown(struct bcpid *b)
{
    pmclog_close(b->pmclog_handle);

    int status;
    for (int i = 0; i < b->num_pmc_event; ++i) {
        struct bcpid_pmc_counter *spec = &b->pmc_ctrs[i];
        if (!spec->is_valid) {
            continue;
        }
        for (int j = 0; j < b->num_cpu; ++j) {
            struct bcpid_pmc_cpu *cpu = &b->pmc_cpus[j];
            if (!(cpu->pmc_valid & (1 << i))) {
                continue;
            }
            status = pmc_stop(cpu->pmcs[i]);
            if (status < 0) {
                PERROR("pmc_stop");
            }

            status = pmc_release(cpu->pmcs[i]);
            if (status < 0) {
                PERROR("pmc_release");
            }

        }
    }

    status = pmc_configure_logfile(-1);
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
    bcpid_report_edge(b);
}

void bcpid_printcpu();
void bcpid_print_pmcs();
void bcpid_print_events();
void bcpid_term_handler(int);

bool
bcpid_parse_options(struct bcpid *b, int argc, const char *argv[]) 
{
    int c = 1;
    int count = 4096;

    while (c) {
        c = getopt(argc, (char **)argv, "hc:l");
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'h': {
                fprintf(stderr, "Help: \n  -c count "
                        "(Number of counter increments between interrupt)\n"
                        "  -h (Show this help)\n"
                        "  -l (List names of PMCs)\n");
                return false;
                break;}
            case 'l': {
                bcpid_printcpu();
                return false;
                break; }
            default:
                break;
        }
    } 

    b->default_count = count;
    MSG("count set to %d", b->default_count);
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
    int ncpus = pmc_ncpu();
    const struct pmc_cpuinfo *cpuinfo;

    status = pmc_cpuinfo(&cpuinfo);
    if (status < 0) {
        PERROR("pmc_cpuinfo");
        exit(1);
    }

    MSG("---Dump CPU Info--");
    MSG("CPU Type: %s, CPUs: %d, PMCs: %d, Classes: %d", 
      pmc_name_of_cputype(cpuinfo->pm_cputype), cpuinfo->pm_ncpu, 
      cpuinfo->pm_npmc, cpuinfo->pm_nclass);
    for (int i = 0; i < cpuinfo->pm_nclass; i++) {
        const struct pmc_classinfo *c = &cpuinfo->pm_classes[i];
        MSG("Class %d %s: Width: %d, PMCS: %d, Caps:", i, 
                pmc_name_of_class(c->pm_class), c->pm_width, c->pm_num);
        for (int j = 0; j < 31; ++j) {
            if (c->pm_caps & (1 << j)) {
                fprintf(stderr, "%s ", 
                        pmc_name_of_capability((enum pmc_caps)(1 << j)));
            }
        }
        MSG("Event Names");
        int evts;
        const char **evtlst;
        enum pmc_class pc = c->pm_class;
        status = pmc_event_names_of_class(pc, &evtlst, &evts);
        if (status < 0) {
            PERROR("pmc_event_names_of_class");
            return;
        }

        for (int j = 0; j < evts; j++) {
            fprintf(stderr, "  %s\n", evtlst[j]);
        }
    }
}

void 
bcpid_print_pmcs() 
{
    int status;
    int ncpu = pmc_ncpu();
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
                pmc_name_of_class(p->pm_class), pmc_name_of_mode(p->pm_mode));
    }
}

void 
bcpid_print_events() 
{
    int status;
    int ncpus = pmc_ncpu();
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

const char *g_bcpid_pmc_event_name[] = 
{
    "branches",
    "dc-misses",
    "ic-misses",
    "instructions",
    "unhalted-cycles",
    0
};

const char *g_bcpid_pmclog_name[] = 
{
    "PMCLOG_TYPE_PADDING",
    "PMCLOG_TYPE_CLOSEMSG",
    "PMCLOG_TYPE_DROPNOTIFY",
    "PMCLOG_TYPE_INITIALIZE",
    "PMCLOG_TYPE_PADDING",
    "PMCLOG_TYPE_PMCALLOCATE",
    "PMCLOG_TYPE_PMCATTACH",
    "PMCLOG_TYPE_PMCDETACH",
    "PMCLOG_TYPE_PROCCSW",
    "PMCLOG_TYPE_PROCEXEC",
    "PMCLOG_TYPE_PROCEXIT",
    "PMCLOG_TYPE_PROCFORK",
    "PMCLOG_TYPE_SYSEXIT",
    "PMCLOG_TYPE_USERDATA",
    "PMCLOG_TYPE_MAP_IN",
    "PMCLOG_TYPE_MAP_OUT",
    "PMCLOG_TYPE_CALLCHAIN",
    "PMCLOG_TYPE_PMCALLOCATEDYN",
    "PMCLOG_TYPE_THR_CREATE",
    "PMCLOG_TYPE_THR_EXIT",
    "PMCLOG_TYPE_PROC_CREATE",
   0 
};

const char *g_bcpid_pmclog_state_name[] = 
{
	"PMCLOG_OK",
	"PMCLOG_EOF",
	"PMCLOG_REQUIRE_DATA",
	"PMCLOG_ERROR",
    0
};

