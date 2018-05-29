TOOL_PREFIX=/opt/toolchain/llvm-git/bin/

CFLAGS= -O0 -g
LLC_CFLAGS=-O0
LDFLAGS= -O0
OPT_FLAGS=-stats

LINKER=$(TOOL_PREFIX)clang++

SOPATH=../build/capchk/libcapchk.so

all:
	$(TOOL_PREFIX)clang -O0 -c -emit-llvm chknchk.c -o test.bc ${CFLAGS}

	$(TOOL_PREFIX)opt \
					-load=${SOPATH} \
					test.bc \
					-capchk \
					${OPT_FLAGS}
	
bin: all
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-dag-combine-lt-dags
	@echo - displays the DAG after being built, before the first optimization pass
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-dag-combine1-dags
	@echo - displays the DAG before Legalization
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-legalize-dags
	@echo - displays the DAG before legalize types
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-legalize-types-dags
	@echo - displays the DAG before the second optimization pass
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-dag-combine2-dags
	@echo - displays the DAG before the Select phase
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-isel-dags
	@echo - displays the DAG before Scheduling
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-sched-dags
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-misched-dags
	@echo - displays the scheduler\'s dependency graph
	@echo $(TOOL_PREFIX)llc test-inst.ll -view-sunit-dags
	@echo "Build using clang directly"
	$(TOOL_PREFIX)clang test-inst.bc -O0 -g -o test-inst -mllvm -print-before-all -mllvm -print-after-all>foo.log 2>&1

clean:
	rm -f *.bc *.ll test-inst *.s foo.log
	rm -f *.dot *.png *.pdf
	rm -f *.o

see: gendot
	make cfg

gendot:
	$(TOOL_PREFIX)/opt test.bc -dot-callgraph -dot-cfg

DOTSRC=$(wildcard *.dot)

cfg:
	@$(foreach dotfile, $(DOTSRC), dot $(dotfile) -Tpdf -o $(dotfile).pdf;)
#	@$(foreach dotfile, $(DOTSRC), dot $(dotfile) -Tpng -o $(dotfile).png;)

xdot:
	xdot callgraph.dot

run:
	./test

