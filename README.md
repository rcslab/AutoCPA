Continuous Profiler and Analysis Tools
======================================

Installation
------------

Platforms:
 - FreeBSD 12+

```
$ make
```


Ghidra
------

Our analysis pass depends on Ghidra.
Running the following script:

```
$ ./scripts/install-ghidra.sh
```

will install a copy of it under `./ghidra`.
On FreeBSD, this installation will require Linux emulation for some binaries, which you can set up with:

```
# pkg install linux_base-c7
# service linux start
```

To use an alternative Ghidra installation, set the `GHIDRA_ROOT` environment variable to its path.
By default, Ghidra project data will be saved to `./ghidra/projects`.
This path can be customized with the `GHIDRA_PROJECTS` environment variable.


Getting Started
---------------

Our bcpid collection daemon can should be run as root and records will be 
placed in `/var/tmp`.  The daemon can also be run in foreground mode for 
testing as with `-f` parameter and you change the output directory using the 
`-o` parameter.

The default counters are picked up `conf/ARCH_NAME.conf` where architecture 
name is displayed in the first line of `pmccontrol -l`.  The configuration file 
accepts pmc formatted comma separated parameters to the counters.  We also 
include several additional parameters `sample_rate`, `sample_ratio` and 
`label`.

Sampling can be done at a fixed rate or adaptive rate.  For fixed counters 
specify the `sample_rate`.  For adaptive counters specify the `sample_ratio` 
and set the target CPU overhead using `-a %CPU` parameter to bcpid.  The daemon 
will change the sample rate to meet the target CPU usage.

You should set the label using the standard pmc counter names with a few 
extensions we've made.  Currently we use `instructions`, `branches`, 
`dc-misses`, and `l2dc-misses`.

```
$ bcpid/bcpid
```

Extract cache miss samples from the bcpi data in `/var/tmp` and stores them in 
`address_info.csv`.

`BINARY` is the path to the executable object to analyze

```
$ bcpiquery/bcpiquery extract -o BINARY
```

At the moment Ghidra requires that you provide a binary with DWARF symbols 
included.  If needed you can merge the symbols and binary using the following 
command:

```
$ ./scripts/merge-debug.sh program program.debug program.full
```

This will run our cache miss analysis on the addresses generated in the 
previous step and generate a list of structures present in the samples.

The `analyze.sh` script runs the actual analysis.  It is invoked like this
(note that the argument order was recently changed):

```
./scripts/analyze.sh program.full address_info.csv
```

This runs the default `StructOrderAnalysis`, which suggests struct reorderings
to improve cache locality.  Other analyses can be selected with `-a`:

```
./scripts/analyze.sh -a DebugAnalysis program.full csv:address_info.csv
```


Kernel analysis
---------------

Different scripts must be used to import the FreeBSD kernel for analysis.
First, merge the debug info into the kernel and modules with

```
$ ./scripts/merge-kernel.sh /boot/kernel ./kernel.full
```

Or, if you have the obj directory from the kernel build, you can do

```
$ ./scripts/merge-built-kernel.sh /usr/obj/.../sys/GENERIC ./kernel.full
```

Then, import the kernel with

```
$ ./scripts/import-kernel.sh ./kernel.full
```

If the kernel to analyze was running on a different machine, you'll need to capture the output of `kldstat` on that machine and pass it to the import script:

```
$ ./scripts/import-kernel.sh ./kernel.full kldstat.out
```

At this point, the extract-kernel.sh script must be run:

```
$ ./scripts/extract-kernel.sh kernel ./address_info.csv
```

Note that this will use the kernel from the current machine.  If the kernel to analyze was running on a different machine, you'll need to create a sysroot for bcpi and point it there, using the directory specified in the import-kernel step above:

```
$ mkdir -p sysroot/boot
$ ln -s `pwd`/kernel.full sysroot/boot/kernel
$ BCPI_SYSROOT=$PWD/sysroot ./scripts/extract-kernel.sh /boot/kernel kldstat.out address_info.csv
```

Analysis works as normal:

```
$ ./scripts/analyze.sh ./kernel.full ./address_info.csv
```
