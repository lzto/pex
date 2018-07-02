/*
 * complex value flow analysis
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */
#ifndef _CVFA_H_
#define _CVFA_H_

#include "commontypes.h"

#include "MSSA/SVFGOPT.h"
#include "WPA/Andersen.h"
#include "MemoryModel/PointerAnalysis.h"

using namespace llvm;

class CVFA
{
private:
    Module* m;
    PointerAnalysis* pta;
    SVFG* svfg;

public:
    CVFA();
    ~CVFA();
    void initialize(Module& module);
    void get_callee_function_indirect(Function* callee, ConstInstructionSet& css);

};

#endif//_CVFA_H_

