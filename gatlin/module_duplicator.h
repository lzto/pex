/*
 * module_duplicator.h
 * Module Duplicator
 * duplicate module within given scope
 *
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _MOD_DUPER_
#define _MOD_DUPER_

#include "llvm-c/Core.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionAliasAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Pass.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include "commontypes.h"

using namespace llvm;

class ModuleDuplicator {
public:
  ModuleDuplicator(Module &, FunctionSet &, FunctionSet &);
  ~ModuleDuplicator();
  Module &getResult();
  Value *map_to_origin(const Value *);
  Value *map_to_duplicated(const Value *);

private:
  // map from orig to duplicated
  ValueToValueMapTy vmap;
  // map from duplicated to orig
  ValueToValueMapTy rvmap;
  Module *res_mod;
};

#endif //_MOD_DUPER_
