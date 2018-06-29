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
    :m(NULL)
{
}

CVFA::~CVFA()
{
}

void CVFA::initialize(Module& module)
{
    m = &module;
}

void CVFA::get_indirect_callee_for_func(Function* callee, InstructionSet& css)
{
    //getPTACallGraph()->getIndCallSitesInvokingCallee(callee, css);
    //getPTACallGraph()->getAllCallSitesInvokingCallee(callee, css);
}

