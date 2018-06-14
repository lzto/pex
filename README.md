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
    -stats \
    vmlinux.bc \
    -o /dev/null 2>&1 | tee log
```

#options
* ccv - check critical variables
* ccf - check critical functions
* ccfv - print path to critical function during collect phase
* ccvv - print path to critical variable during collect phase


