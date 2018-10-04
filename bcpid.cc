
#include <iostream>

#include <unistd.h>

#include <pmc.h>
#include <pmclog.h>

using namespace std;

void
printcpu()
{
    int status;
    int ncpus = pmc_ncpu();
    const struct pmc_cpuinfo *cpuinfo;

    status = pmc_cpuinfo(&cpuinfo);
    if (status < 0) {
	perror("pmc_cpuinfo");
	exit(1);
    }

    cout << "--- Dump CPU Info ---" << endl;
    cout << "CPU Type: " << pmc_name_of_cputype(cpuinfo->pm_cputype) << endl;
    cout << "# CPUs: " << cpuinfo->pm_ncpu << endl;
    cout << "# PMCs: " << cpuinfo->pm_npmc << endl;
    cout << "# Classes " << cpuinfo->pm_nclass << endl;

    for (int i = 0; i < cpuinfo->pm_nclass; i++) {
	const struct pmc_classinfo *c = &cpuinfo->pm_classes[i];
	cout << "Class: " << pmc_name_of_class(c->pm_class) << endl;
	cout << "  Caps: " << c->pm_caps << endl;
	cout << "  Width: " << c->pm_width << endl;
	cout << "  PMCs: " << c->pm_num << endl;
    }
}

void
printpmcs()
{
    int status;
    int npmcs = pmc_npmc(0);
    struct pmc_pmcinfo *pmcinfo;

    status = pmc_pmcinfo(0, &pmcinfo);
    if (status < 0) {
	perror("pmc_pmcinfo");
	exit(1);
    }

    cout << "--- Dump PMCs ---" << endl;
    cout << "# of PMCs: " << npmcs << endl;

    for (int i = 0; i < npmcs; i++) {
	struct pmc_info *p = &pmcinfo->pm_pmcs[i];
	cout << "Name: " << &p->pm_name[0] << endl;
	if (p->pm_class < PMC_CLASS_FIRST || p->pm_class > PMC_CLASS_LAST) {
	    cout << "  Class: " << p->pm_class << endl;
	} else {
	    cout << "  Class: " << pmc_name_of_class(p->pm_class) << endl;
	}
	if (p->pm_mode < PMC_MODE_FIRST || p->pm_mode > PMC_MODE_LAST) {
	    cout << "  Mode: " << p->pm_mode << endl;
	} else {
	    cout << "  Mode: " << pmc_name_of_mode(p->pm_mode) << endl;
	}
	//cout << "  Event: " << pmc_name_of_event(p->pm_event) << endl;
	//cout << "  Reload Count: " << p->pm_reloadcount << endl;
    }
}

void
printevents()
{
    int status;
    int ncpus = pmc_ncpu();
    const struct pmc_cpuinfo *cpuinfo;

    status = pmc_cpuinfo(&cpuinfo);
    if (status < 0) {
	perror("pmc_cpuinfo");
	exit(1);
    }

    cout << "--- Dump Events ---" << endl;
    for (int i = 0; i < cpuinfo->pm_nclass; i++) {
	int evts;
	const char **evtlst;
	enum pmc_class c = cpuinfo->pm_classes[i].pm_class;

	status = pmc_event_names_of_class(c, &evtlst, &evts);
	if (status < 0) {
	    perror("pmc_event_names_of_class");
	    return;
	}

	cout << "Class: " << pmc_name_of_class(c) << endl;
	for (int j = 0; j < evts; j++) {
	    cout << "  " << evtlst[j] << endl;
	}
    }
}

int pipefd[2];
pmc_id_t pmc_instr;

void
setuppmc()
{
    int status;

    status = pmc_allocate("instructions", PMC_MODE_SS, 0, 0, &pmc_instr);
    if (status < 0) {
	perror("pmc_allocate");
	exit(1);
    }

    status = pipe(pipefd);
    if (status < 0) {
	perror("pipe");
    }

    status = pmc_configure_logfile(pipefd[1]);
    if (status < 0) {
	perror("pmc_configure_logfile");
    }

    status = pmc_start(pmc_instr);
    if (status < 0) {
	perror("pmc_start");
    }

    void *log = pmclog_open(pipefd[0]);
    for (int i = 0; i < 1000; i++) {
	struct pmclog_ev ev;
	pmclog_read(log, &ev);
	switch (ev.pl_type) {
	    case PMCLOG_TYPE_INITIALIZE:
		cout << "Init" << endl;
		break;
	    case PMCLOG_TYPE_PROCEXEC:
		cout << "Exec" << endl;
		break;
	    case PMCLOG_TYPE_PROCEXIT:
		cout << "Exit" << endl;
		break;
	    case PMCLOG_TYPE_PROCFORK:
		cout << "Fork" << endl;
		break;
	    case PMCLOG_TYPE_SYSEXIT:
		cout << "Sys Exit" << endl;
		break;
	    case PMCLOG_TYPE_MAP_IN:
		cout << "Map In" << endl;
		break;
	    case PMCLOG_TYPE_MAP_OUT:
		cout << "Map Out" << endl;
		break;
	    default:
		cout << "Type: " << ev.pl_type << endl;
		break;
	}
    }
    pmclog_close(log);

    status = pmc_stop(pmc_instr);
    if (status < 0) {
	perror("pmc_stop");
    }

    status = pmc_release(pmc_instr);
    if (status < 0) {
	perror("pmc_release");
    }

    status = pmc_configure_logfile(-1);
    if (status < 0) {
	perror("pmc_configure_logfile");
    }
    close(pipefd[0]);
    close(pipefd[1]);
}

int
main(int argc, const char *argv[])
{
    int status;

    status = pmc_init();
    if (status < 0) {
	perror("pmc_init");
	exit(1);
    }

    printcpu();
    printpmcs();
    printevents();

    // XXX: read configuration file

    setuppmc();
}

