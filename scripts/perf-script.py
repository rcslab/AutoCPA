from collections import Counter, defaultdict
import csv
from elftools.elf.elffile import ELFFile
import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *


DSO = None
ELF = None
COUNTS = defaultdict(Counter)

def map_ip(ip):
    for seg in ELF.iter_segments("PT_LOAD"):
        start = seg["p_offset"]
        end = start + seg["p_filesz"]
        if ip >= start and ip < end:
            return ip - start + seg["p_vaddr"]

def trace_begin():
    global DSO
    DSO = os.path.abspath(sys.argv[1])

    global ELF
    ELF = ELFFile(open(DSO, "rb"))

def trace_end():
    writer = csv.writer(sys.stdout)

    for ip, counts in COUNTS.items():
        row = [f"{ip:x}"]
        for name, count in counts.items():
            row.append(f"{name}={count}")
        writer.writerow(row)

def process_event(event):
    name = event["ev_name"]

    callchain = event.get("callchain", [])
    if len(callchain) < 1:
        return

    frame = callchain[0]
    if frame.get("dso", None) != DSO:
        return

    ip = frame["sym"]["start"] + frame["sym_off"]
    ip = map_ip(ip)
    if ip is not None:
        COUNTS[ip][name] += 1
