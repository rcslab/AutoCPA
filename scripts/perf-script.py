from collections import Counter, defaultdict
import csv
import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *


DSO = None
COUNTS = defaultdict(Counter)

def trace_begin():
    global DSO
    DSO = sys.argv[1]

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
    COUNTS[ip][name] += 1
