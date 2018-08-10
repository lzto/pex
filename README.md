Gatlin: Gating Function Checker for Linux Kernel
-------

This checker figures out critical resource(callee of direct/indirect callsite,
global variable use, interesting struct type and field use) by looking at existing
CAP/LSM/DAC check, then explore which path that uses such resource is not guarded by
those check.

#bugs discovered 

see ```log/bug_report.md```

#prerequisites

* LLVM-6/7
* compiler with C++11 support

#build

./build.sh

#usage

```
opt \
    -analyze \
    -load=build/gatlin/libgatlin.so \
    -gatlin \
    -gating=cap \
    -ccv=0 -ccf=1 -cct=0\
    -ccvv=0 -ccfv=0 -cctv=0\
    -cvf=0 \
    -skipfun=skip.fun \
    -skipvar=skip.var \
    -lsmhook=lsm.hook \
    -prt-good=0 -prt-bad=1 -prt-ign=0 \
    -stats \
    vmlinux.bc \
    -o /dev/null 2>&1 | tee log
```

#options
* gating - gating function: cap/lsm/dac, default: cap
* ccv - check critical variables, default: 0
* ccf - check critical functions, default: 1
* cct - check critical type fields, default 0
* ccfv - print path to critical function during collect phase, default 0
* ccvv - print path to critical variable during collect phase, default 0
* cctv - print path to critical type field during collect phase, default 0
* f2c - print critical function to capability mapping, default 1
* v2c - print critical variable to capability mapping, default 1
* t2c - print critical type field to capability mapping, default 1
* caw - print check functions and wrappers discovered, default 1
* kinit - print kernel init functions, default 1
* nkinit - print kernel non init functions, default 1
* kmi - kernel interface, default 0
* cvf - complex value flow, default 0
* skipfun - list of functions don't care
* skipvar - list of variables don't care
* capfunc - list of capability check functions
* lsmhook - list of LSM hook
* critsym - list of symbols to be treated as critical and ignore others
* kapi - list of kernel api
* prt-good - print good path, default 0
* prt-bad - print bad path, default 1
* prt-ign - print ignored path, default 0
* wcapchk-kinit - warn capability check during kernel boot process, default 0
* fwd-depth - forward search max depth, default 100
* bwd-depth - backward search max depth, default 100
* svfbudget - # of iterations for cvf graph update, default 5

#vmlinux.bc

You need to install wllvm(https://github.com/travitch/whole-program-llvm)
and then use the following command to generate a single bc file.

```
~/linux: make defconfig
~/linux: make CC=wllvm
~/linux: extract-bc vmlinux
```

#Misc: where are the checks, which module should be builtin

* DAC: they are mainly used in file systems(vfs),
       stage/luster and net/sunrpc also have some checks
* LSM: those LSM hooks are scattered around in net/fs/mm/core
* CAP: capability checks are also scattered in different parts of the kernel,
       besides net/fs/mm/core, lots of device drivers also use capability checks

#I want debug info

```
CONFIG_DEBUG_INFO=y
```

#resolve indirect call: KMI or CVF

There are two ways to resolve indirect call: KMI and CVF

* KMI: kernel module interface, is built upon human knowledge of linux kernel,
the observation is that most of the callee of indirect callsite is read from
a constant struct which statically stores a function pointer, 
by matching those struct type and indicies we can match indirect call
fairly accurate(over approximate)

* CVF: this is built upon SVF, and can accurately figure out callee for indirect call,
however this is very slow and memory hungry.
CVF can process a module with ~40k functions in one hour on an Intel Xeon 6132 2.6GHz CPU.

