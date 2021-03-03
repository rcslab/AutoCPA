Continuous Profiler and Analysis Tools
======================================

Installation
------------

Platforms:
 - FreeBSD 12+

Dependencies:
 - Ghidra

Run the following to install dependencies:

```
# pkg install ghidra
```

```
# make
```

Getting Started
---------------

Our bcpid collection daemon can be run in foreground mode for testing as 
follows.  This should be run as root and files will be placed in /var/tmp.

```
bcpid/bcpid -f
```

Extracts cache miss samples from the bcpi data in /var/tmp and stores them in 
address_info.csv.
```
# scripts/query.py
```

At the moment Ghidra requires that you provide a binary with DWARF symbols 
included.  If needed you can merge the symbols and binary using the following 
command:

```
# scripts/merge-debug.sh program program.symbol program.full
```

This will run our cache miss analysis on the addresses generated in the 
previous step and generate a list of structures present in the samples.

WARNING: The first time you run this it may take a substantial amount of time.  
For the FreeBSD kernel with DWARF symbols we usually require 30 minutes for the 
Ghidra to finish the analysis.  Subsequent runs should be on the order of 
seconds.

```
# scripts/analyze.sh program.full
```

You can generated a report for a given structure:

```
# scripts/analyze.sh program.full structname
```
