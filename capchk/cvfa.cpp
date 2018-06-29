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
    :m(NULL), svfg(NULL), pta(NULL)
{
    pta = new Andersen();
}

CVFA::~CVFA()
{
}

void CVFA::initialize(Module& module)
{
    errs()<<"Run Pointer Analysis\n";
    STOP_WATCH_START(WID_INIT);
    m = &module;
    pta->analyze(SVFModule(module));
    STOP_WATCH_STOP(WID_INIT);
    STOP_WATCH_REPORT(WID_INIT);
    errs()<<"Build SVFG\n";
    STOP_WATCH_START(WID_INIT);
    SVFGBuilder memSSA(true);
    svfg = memSSA.buildSVFG((BVDataPTAImpl*)pta);
    STOP_WATCH_STOP(WID_INIT);
    STOP_WATCH_REPORT(WID_INIT);
}

void CVFA::get_indirect_callee_for_func(Function* callee, InstructionSet& css)
{
    //getPTACallGraph()->getIndCallSitesInvokingCallee(callee, css);
    //getPTACallGraph()->getAllCallSitesInvokingCallee(callee, css);
}

