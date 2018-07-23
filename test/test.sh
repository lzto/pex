clang test.c -c -emit-llvm -o  test.bc -O0 -g

opt \
	-analyze -load=/home/t.zhang2/gatlin/build/gatlin/libgatlin.so \
	-gatlin -stats \
    -gating=cap \
    -ccfv=1 -ccvv=0 -cctv=0\
    -ccf=1 -ccv=0 -cct=0\
	-cvf=1 \
    -prt-good=0 -prt-bad=1 -prt-ign=0 \
    -kinit=0 -nkinit=0 \
	test.bc -o /dev/null 2>&1

