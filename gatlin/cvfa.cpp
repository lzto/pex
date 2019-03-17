/*
 * complex value flow analysis
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */

#include "cvfa.h"

#include "MSSA/SVFGStat.h"
#include "Util/GraphUtil.h"

#include "color.h"
#include "stopwatch.h"

#define TOTOAL_NUMBER_OF_STOP_WATCHES 2
#define WID_INIT 0
#define WID_ANAL 1

STOP_WATCH(TOTOAL_NUMBER_OF_STOP_WATCHES);

using namespace llvm;

CVFA::CVFA()
    :pta(new FlowSensitive)
{
    m = NULL;
    svfg = NULL;
}

CVFA::~CVFA()
{
}

void CVFA::initialize(Module& module)
{
    STOP_WATCH_START(WID_INIT);
    m = &module;
    errs()<<"Create SVFModule\n";
    SVFModule svfmod(module);
    errs()<<"Run Pointer Analysis\n";
    pta->analyze(svfmod);
    STOP_WATCH_STOP(WID_INIT);
    errs()<<ANSI_COLOR(BG_GREEN, FG_WHITE)
            <<"CVFA::initialize cost(0):"
            <<ANSI_COLOR_RESET;
    STOP_WATCH_REPORT(WID_INIT);

    svfg = pta->getSVFG();
}

void CVFA::get_callee_function_indirect(Function* callee, ConstInstructionSet& css)
{
    pta->getPTACallGraph()->getIndCallSitesInvokingCallee(callee, css);
    //getPTACallGraph()->getAllCallSitesInvokingCallee(callee, css);
}

