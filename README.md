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
    -ccv=flase -ccf=true \
    -stats \
    vmlinux.bc \
    -o /dev/null 2>&1 | tee log
```

#options
* ccv - check critical variables
* ccf - check critical functions


