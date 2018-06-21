Linux Kernel Capability Checker
-------

#build

./build.sh

#usage

```
/opt/toolchain/llvm-git/bin/opt \
    -analyze \
    -load=build/capchk/libcapchk.so \
    -capchk \
    -ccv=0 -ccf=1 \
    -ccvv=0 -ccfv=0 \
    -cvf=0 \
    -skipfun=skip.fun \
    -skipvar=skip.var \
    -prt-good=0 -prt-bad=1 -prt-ign=0 \
    -stats \
    vmlinux.bc \
    -o /dev/null 2>&1 | tee log
```

#options
* ccv - check critical variables, default: 0
* ccf - check critical functions, default: 1
* ccfv - print path to critical function during collect phase, default 0
* ccvv - print path to critical variable during collect phase, default 0
* f2c - print critical function to capability mapping, default 1
* v2c - print critical variable to capability mapping, default 1
* caw - print check functions and wrappers discovered, default 1
* kinit - print kernel init functions, default 1
* nkinit - print kernel non init functions, default 1
* cvf - complex value flow, default 0
* skipfun - list of functions don't care
* skipvar - list of variables don't care
* prt-good - print good path, default 0
* prt-bad - print bad path, default 1
* prt-ign - print ignored path, default 0

