/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#ifndef _GATLING_UTILITY_
#define _GATLING_UTILITY_

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"

#include "commontypes.h"

using namespace llvm;

int use_parent_func_arg(Value* v, Function* f);
Instruction* GetNextInstruction(Instruction* i);
Instruction* GetNextNonPHIInstruction(Instruction* i);
Function* get_callee_function_direct(Instruction* i);
StringRef get_callee_function_name(Instruction* i);
void get_callsite_inst(Value*, CallInstSet&);

#endif //_GATLING_UTILITY_

