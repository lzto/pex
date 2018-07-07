Linux Kernel Capability Checker
-------

This checker figures out critical resource(callee of direct/indirect callsite,
global variable use, interesting struct type and field use) by looking at existing
capable() check, then check which path that uses those resources is not guarded by
capable() check.

#prerequisites

* LLVM-6/7
* compiler with C++11 support

#build

./build.sh

#usage

```
opt \
    -analyze \
    -load=build/capchk/libcapchk.so \
    -capchk \
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
* gating - gating function: cap/lsm, default: cap
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
* cvf - complex value flow, default 0
* skipfun - list of functions don't care
* skipvar - list of variables don't care
* lsmhook - list of LSM hook
* prt-good - print good path, default 0
* prt-bad - print bad path, default 1
* prt-ign - print ignored path, default 0
* wcapchk-kinit - warn capability check during kernel boot process, default 0

