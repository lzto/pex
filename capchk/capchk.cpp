/*
 * CapChecker
 * linux kernel capability checker
 * 2018 Tong Zhang
 */


#include "llvm/Transforms/Instrumentation.h"

#include "llvm/ADT/Statistic.h"

#include "llvm/Pass.h"

#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionAliasAnalysis.h"

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/IR/Dominators.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"

#include "llvm-c/Core.h"

#include "llvm/ADT/SetVector.h"

#include <list>
#include <map>
#include <stack>
#include <queue>
#include <set>
#include <algorithm>

#include "color.h"

#include "stopwatch.h"
STOP_WATCH;

using namespace llvm;

#define DEBUG_TYPE "capchk"

/*
 * define statistics if not enabled in LLVM
 */

#if (!LLVM_ENABLE_STATS)

#undef STATISTIC
#define CUSTOM_STATISTICS 1
#define STATISTIC(X,Y) \
unsigned long X;\
const char* X##_desc = Y;

#define STATISTICS_DUMP(X) \
    errs()<<"    "<<X<<" : "<<X##_desc<<"\n";

#endif

STATISTIC(FuncCounter, "Functions greeted");
STATISTIC(ExternalFuncCounter, "External function");

class capchk : public ModulePass
{
    private:
        bool runOnModule(Module &);
        bool capchkPass(Module &);

        void process_each_function(Module& module);
        void verify(Module& module);
        #ifdef CUSTOM_STATISTICS
        void dump_statistics();
        #endif

        /*
         * context for current module
         */
        LLVMContext *ctx;
        Module* module;
        /*
         * for debug purpose
         */
        std::stack<Value*> dbgstk;
        void dump_dbgstk();

    public:
        static char ID;
        capchk() : ModulePass(ID)
        {
        }
        const char* getPassName()
        {
            return "capchk";
        }
        void getAnalysisUsage(AnalysisUsage &au) const override
        {
            au.setPreservesAll();
            au.addRequired<AAResultsWrapperPass>();
            au.addPreserved<GlobalsAAWrapperPass>();
            au.addRequired<TargetLibraryInfoWrapperPass>();
            au.addRequired<ScalarEvolutionWrapperPass>();
        }
};
#ifdef CUSTOM_STATISTICS
void capchk::dump_statistics()
{

    errs()<<"------------STATISTICS---------------\n";
    STATISTICS_DUMP(FuncCounter);
    STATISTICS_DUMP(ExternalFuncCounter);
    errs()<<"\n\n\n";
}
#endif

char capchk::ID;

/*
 * command line options
 */
/*cl::opt<bool> capchk_no_check("capchk_no_check",
                cl::desc("no checks at all, only bound propogation - disabled by default"),
                cl::init(false));
*/

/*
 * helper function
 */
Instruction* GetNextInstruction(Instruction* I)
{
    if (isa<TerminatorInst>(I))
    {
        return I;
    }
    BasicBlock::iterator BBI(I);
    return dyn_cast<Instruction>(++BBI);
}

Instruction* GetNextNonPHIInstruction(Instruction* I)
{
    if (isa<TerminatorInst>(I))
    {
        return I;
    }
    BasicBlock::iterator BBI(I);
    while(isa<PHINode>(BBI))
    {
        ++BBI;
    }
    return dyn_cast<Instruction>(BBI);
}

/*
 * debug function
 */
void capchk::dump_dbgstk()
{
    errs()<<ANSI_COLOR_GREEN<<"Process Stack:"<<ANSI_COLOR_RESET<<"\n";
    while(dbgstk.size())
    {
        errs()<<(dbgstk.size()-1)<<" : ";
        dbgstk.top()->dump();
        dbgstk.pop();
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

/*
 * prcess all functions in module
 */
void capchk::process_each_function(Module& module)
{
    std::list<Function*> processed_flist;
    //for each function
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func_ptr = dyn_cast<Function>(f_begin);

        bool found = (std::find(std::begin(processed_flist),
                                 std::end(processed_flist), func_ptr) 
                            != std::end(processed_flist));
        if (found)
        {
            continue;
        }
        if (func_ptr->isDeclaration())
        {
            ExternalFuncCounter++;
            continue;
        }
        FuncCounter++;
        #if DEBUG
        errs()<<ANSI_COLOR_MAGENTA
            <<"Process Function : "
            <<func_ptr->getName()
            <<ANSI_COLOR_RESET
            <<"\n";
        #endif

        /*
         * this is worklist algorithm
         */
        std::set<BasicBlock*> bb_visited;
        std::queue<BasicBlock*> bb_work_list;
        bb_work_list.push(&func_ptr->getEntryBlock());
        while(bb_work_list.size())
        {
            /*
             * pick the first item in the worklist
             */
            BasicBlock* bb = bb_work_list.front();
            bb_work_list.pop();
            if(bb_visited.count(bb))
            {
                continue;
            }
            bb_visited.insert(bb);
            /*
             * for each basic block, we scan through instructions
             *  - gather bound information when new pointer is allocated
             *  - insert bound check when pointer is dereferenced
             */
            
            for (BasicBlock::iterator ii = bb->begin(),
                    ie = bb->end();
                    ii!=ie; ++ii)
            {
                Instruction *I = dyn_cast<Instruction>(ii);
            }
            /*
             * insert all successor of current basic block to work list
             */
            for (succ_iterator si = succ_begin(bb),
                    se = succ_end(bb);
                    si!=se; ++si)
            {
                BasicBlock* succ_bb = cast<BasicBlock>(*si);
                bb_work_list.push(succ_bb);
            }
        }
        /*
         * there may be cases that block has no predecessor
         * we need to handle this specially
         */
        Function* func = func_ptr;
        for(Function::iterator i = func->begin(), e = func->end(); i != e; ++i)
        {
            BasicBlock* blk = dyn_cast<BasicBlock>(i);
            if (bb_visited.count(blk)==0)
            {
                #if (DEBUG>1)
                errs()<<" return bb has no predecessor, scan it anyway\n";
                #endif
                bb_visited.insert(blk);
                for (BasicBlock::iterator ii = blk->begin(),
                        ie = blk->end();
                        ii!=ie; ++ii)
                {
                    Instruction *I = dyn_cast<Instruction>(ii);
                }
            }
        }
    }
}

void capchk::verify(Module& module)
{
    errs()<<"  check bogus instruction parent ";
    for (Module::iterator fi = module.begin(), fe = module.end();
            fi != fe; ++fi)
    {
        Function* func = dyn_cast<Function>(fi);
        for(Function::iterator i = func->begin(), e = func->end(); i != e; ++i)
        {
            BasicBlock* blk = dyn_cast<BasicBlock>(i);
            for (BasicBlock::iterator ins = blk->begin(), inse = blk->end(); ins != inse; ++ins)
            {
                Instruction* iii = dyn_cast<Instruction>(ins);
                if (iii->getParent()!=blk)
                {
                    errs()<<"["<<ANSI_COLOR_RED<<"BAD"<<ANSI_COLOR_RESET<<"]\n";
                    iii->print(errs());
                    errs()<<"\n";
                    llvm_unreachable("Instruction has bogus parent pointer!");
                }
            }
        }
    }
    errs()<<"["<<ANSI_COLOR_GREEN<<"OK"<<ANSI_COLOR_RESET<<"]\n";
    //dominance relation
    #if 1
    errs()<<"  check dominance relation ";
    DominatorTree DT;
    for (Module::iterator fi = module.begin(), fe = module.end();
            fi != fe; ++fi)
    {
        Function* func = dyn_cast<Function>(fi);
        DT.recalculate(*func);
        for(Function::iterator i = func->begin(), e = func->end(); i != e; ++i)
        {
            BasicBlock* blk = dyn_cast<BasicBlock>(i);
            for (BasicBlock::iterator ins = blk->begin(), inse = blk->end(); ins != inse; ++ins)
            {
                Instruction* iii = dyn_cast<Instruction>(ins);
                for (unsigned i =0, e = iii->getNumOperands(); i!=e; ++i)
                {
                    if (!isa<Instruction>(iii->getOperand(i)))
                    {
                        continue;
                    }
                    Instruction *Op = cast<Instruction>(iii->getOperand(i));
                    if (InvokeInst *II = dyn_cast<InvokeInst>(Op))
                    {
                        if (II->getNormalDest() == II->getUnwindDest())
                        {
                            continue;
                        }
                    }
                    const Use &U = iii->getOperandUse(i);
                    if (!DT.dominates(Op, U))
                    {
                        errs()<<"["<<ANSI_COLOR_RED<<"BAD"<<ANSI_COLOR_RESET<<"]\n";
                        errs()<<ANSI_COLOR_RED<<"Use:"<<ANSI_COLOR_RESET;
                        iii->dump();
                        BasicBlock* usebb = iii->getParent();
                        errs()<<"   in BB:"<<usebb->getName()<<"\n";
                        errs()<<ANSI_COLOR_GREEN<<"Def:"<<ANSI_COLOR_RESET;
                        Op->dump();
                        BasicBlock* defbb = Op->getParent();
                        errs()<<"   in BB:"<<defbb->getName()<<"\n";
                        for (succ_iterator si = succ_begin(defbb),
                            se = succ_end(defbb);
                            si!=se; ++si)
                        {
                            BasicBlock* succ_bb = cast<BasicBlock>(*si);
                            errs()<<"     |->"<<succ_bb->getName()<<"\n";
                        }
                        errs()<<"--------------------------------------------\n";
                        defbb->dump();
                        usebb->dump();
                        llvm_unreachable("Instruction does not dominate all uses!");
                    }
                }
            }
        }
    }
    errs()<<"["<<ANSI_COLOR_GREEN<<"OK"<<ANSI_COLOR_RESET<<"]\n";
    #endif
    #if 1
    errs()<<"  check return type ";
    for (Module::iterator fi = module.begin(), fe = module.end();
            fi != fe; ++fi)
    {
        Function* func = dyn_cast<Function>(fi);
        for(Function::iterator i = func->begin(), e = func->end(); i != e; ++i)
        {
            BasicBlock* blk = dyn_cast<BasicBlock>(i);
            for (BasicBlock::iterator ins = blk->begin(), inse = blk->end(); ins != inse; ++ins)
            {
                Instruction* iii = dyn_cast<Instruction>(ins);
                ReturnInst* ret_inst = dyn_cast<ReturnInst>(iii);
                if (!ret_inst)
                {
                    continue;
                }
                StringRef errtext="";
                if(func->getReturnType()->isVoidTy())
                {
                    if (ret_inst->getReturnValue()==NULL)
                    {
                        continue;
                    }else
                    {
                        errtext="Return non-void for void function!";
                        goto examine_ret_type_fail;
                    }
                }
                if (ret_inst->getReturnValue()==NULL)
                {
                    errtext="Return void for non-void function!";
                    goto examine_ret_type_fail;
                }
                if (ret_inst->getReturnValue()->getType()!=
                        func->getReturnType())
                {
                    errtext = "Return value does not match function return type!";
                    goto examine_ret_type_fail;
                }
                continue;

examine_ret_type_fail:
                errs()<<"["<<ANSI_COLOR_RED<<"BAD"<<ANSI_COLOR_RESET<<"]\n";
                iii->print(errs());
                errs()<<"\n";
                errs()<<"required return type: ";
                func->getReturnType()->dump();
                errs()<<"\n";
#if DEBUG
                    errs()<<"Full function dump:";
                    func->dump();
#endif
                llvm_unreachable(errtext.data());
            }
        }
    }
    errs()<<"["<<ANSI_COLOR_GREEN<<"OK"<<ANSI_COLOR_RESET<<"]\n";
    #endif
}


bool capchk::runOnModule(Module &module)
{
    return capchkPass(module);
}

bool capchk::capchkPass(Module &module)
{
    errs()<<ANSI_COLOR_CYAN
        <<"--- CAP CHECKER ---"
        <<ANSI_COLOR_RESET<<"\n";
    process_each_function(module);
    errs()<<ANSI_COLOR_CYAN
        <<"--- DONE! ---"
        <<ANSI_COLOR_RESET<<"\n";
#if CUSTOM_STATISTICS
    dump_statistics();
#endif
    return false;
}

static RegisterPass<capchk>
XXX("capchk", "capchk Pass (with getAnalysisUsage implemented)");

