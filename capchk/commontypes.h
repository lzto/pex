/*
 * common types
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _COMMON_TYPES_
#define _COMMON_TYPES_

#include <list>
#include <map>
#include <unordered_map>
#include <stack>
#include <queue>
#include <set>
#include <unordered_set>

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
typedef std::list<CallInst*> CallInstList;
typedef std::list<BasicBlock*> BasicBlockList;
typedef std::list<Function*> FunctionList;
typedef std::list<Type*> TypeList;

typedef std::unordered_set<std::string> StringSet;
typedef std::unordered_set<Value*> ValueSet;
typedef std::unordered_set<Type*> TypeSet;
typedef std::unordered_set<Instruction*> InstructionSet;
typedef std::unordered_set<CallInst*> CallInstSet;
typedef std::unordered_set<const Instruction*> ConstInstructionSet;
typedef std::unordered_set<BasicBlock*> BasicBlockSet;
typedef std::unordered_set<Function*> FunctionSet;
typedef std::unordered_set<CallInst*> InDirectCallSites;
typedef ValueSet ModuleSet;

typedef std::unordered_map<Function*,_REACHABLE> FunctionToCheckResult;
typedef std::unordered_map<Function*, InstructionSet*> Function2ChkInst;
typedef std::unordered_map<Function*, InstructionSet*> Function2CSInst;
typedef std::unordered_map<Function*, int> FunctionData;
typedef std::unordered_map<Type*, std::unordered_set<Function*>*> TypeToFunctions;
typedef std::unordered_map<Type*, std::unordered_set<int>> Type2Fields;
typedef std::unordered_map<Type*, InstructionSet*> Type2ChkInst;
typedef std::unordered_map<Type*, ModuleSet*> ModuleInterface2Modules;
typedef std::unordered_map<Value*, InstructionSet*> Value2ChkInst;
typedef std::unordered_map<Instruction*, FunctionSet*> Inst2Func;
typedef std::unordered_map<const Instruction*, FunctionSet*> ConstInst2Func;



#endif//_COMMON_TYPES_

