/*
 * complex value flow analysis
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */
#ifndef _CVFA_H_
#define _CVFA_H_

#include "commontypes.h"

#include "MSSA/SVFGOPT.h"
#include "WPA/Andersen.h"

using namespace llvm;

class CVFA
{
private:
    Module* m;

public:
    CVFA();
    ~CVFA();
    void initialize(Module& module);
    void get_indirect_callee_for_func(Function* callee, InstructionSet& css);

};

#endif//_CVFA_H_

