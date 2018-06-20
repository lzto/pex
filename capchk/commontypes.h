/*
 * common types
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _COMMON_TYPES_
#define _COMMON_TYPES_

#include <list>
#include <map>
#include <stack>
#include <queue>
#include <set>

#include <llvm/IR/Function.h>

using namespace llvm;

enum _REACHABLE
{
    RFULL,
    RPARTIAL,
    RNONE,
    RKINIT,//hit kernel init functions
    RUNRESOLVEABLE,
    RNA,//not available
};

typedef std::list<std::string> StringList;
typedef std::list<Value*> ValueList;
typedef std::list<Instruction*> InstructionList;
typedef std::list<BasicBlock*> BasicBlockList;
typedef std::list<Function*> FunctionList;

typedef std::set<std::string> StringSet;
typedef std::set<Value*> ValueSet;
typedef std::set<Instruction*> InstructionSet;
typedef std::set<BasicBlock*> BasicBlockSet;
typedef std::set<Function*> FunctionSet;
typedef std::set<CallInst*> InDirectCallSites;

typedef std::map<Function*,_REACHABLE> FunctionToCheckResult;
typedef std::map<Type*, std::set<Function*>*> TypeToFunctions;
typedef std::map<Function*, InstructionSet*> Function2ChkInst;
typedef std::map<Function*, InstructionSet*> Function2CSInst;
typedef std::map<Value*, InstructionSet*> Value2ChkInst;
typedef std::map<Function*, int> FunctionData;
typedef std::map<Instruction*, FunctionSet*> Inst2Func;
typedef std::map<const Instruction*, FunctionSet*> ConstInst2Func;



#endif//_COMMON_TYPES_

