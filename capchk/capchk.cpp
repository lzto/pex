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


//SVF stuff

#include <list>
#include <map>
#include <stack>
#include <queue>
#include <set>
#include <algorithm>

#include "color.h"

#include "stopwatch.h"
STOP_WATCH;

#if defined(DEBUG)
#undef DEBUG
#define DEBUG 0
#else
#define DEBUG 0
#endif

using namespace llvm;

#define DEBUG_PREPARE 0
#define DEBUG_ANALYZE 1

#define MAX_PATH 1000

#define DEBUG_TYPE "capchk"

/*
 * define statistics if not enabled in LLVM
 */

#if defined(LLVM_ENABLE_STATS)
#undef LLVM_ENABLE_STATS
#endif

#if defined(NDEBUG)\
    || !defined(LLVM_ENABLE_STATS)\
||(!LLVM_ENABLE_STATS)

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
STATISTIC(DiscoveredPath, "Discovered Path");
STATISTIC(MatchedPath, "Matched Path");

typedef std::list<Value*> ValueList;
typedef std::list<BasicBlock*> BasicBlockList;
typedef std::list<Function*> FunctionList;



class capchk : public ModulePass
{
    private:
        bool runOnModule(Module &);
        bool capchkPass(Module &);

        void process_each_function(Module& module);
        void chk_div0(Module& module);
        void chk_unsafe_access(Module& module);

        void check_critical_function_usage(Module& module);
        void check_critical_variable_usage(Module& module);

        //void verify(Module& module);
#ifdef CUSTOM_STATISTICS
        void dump_statistics();
#endif

        //used by chk_unsafe_access
        bool is_safe_access(Instruction *ins, Value* addr, uint64_t type_size);

        /*
         * context for current module
         */
        LLVMContext *ctx;
        Module* m;
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
            au.addRequired<AAResultsWrapperPass>();
            au.addRequired<TargetLibraryInfoWrapperPass>();
            au.addRequired<ScalarEvolutionWrapperPass>();
            au.setPreservesAll();
        }
};
#ifdef CUSTOM_STATISTICS
void capchk::dump_statistics()
{
    errs()<<"------------STATISTICS---------------\n";
    STATISTICS_DUMP(FuncCounter);
    STATISTICS_DUMP(ExternalFuncCounter);
    STATISTICS_DUMP(DiscoveredPath);
    STATISTICS_DUMP(MatchedPath);
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

bool capchk::is_safe_access(Instruction* ins,Value* addr, uint64_t type_size)
{
    uint64_t size;
    uint64_t offset;
    bool result;

    bool know = false;
    std::string reason = "";

    if(isa<GlobalVariable>(addr))
    {
        GlobalVariable* gv = dyn_cast<GlobalVariable>(addr);
        if(gv->getLinkage()==GlobalValue::ExternalLinkage)
        {
            goto fallthrough;
        }
        if (!gv->hasInitializer())
        {
            //we have no idea???
            goto fallthrough;
        }
        Constant* initializer = gv->getInitializer();
        Type* itype = initializer->getType();
        unsigned allocated_size = m->getDataLayout()
            .getTypeAllocSize(itype);
        size = allocated_size;
        offset = 0;
    }else
    {
fallthrough:
        const TargetLibraryInfo * TLI = 
            &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
        const DataLayout &dl = m->getDataLayout();
        ObjectSizeOffsetVisitor* obj_size_vis;
        ObjectSizeOpts ObjSizeOptions;
        ObjSizeOptions.RoundToAlign = true;
        obj_size_vis = new ObjectSizeOffsetVisitor(dl, TLI, *ctx, ObjSizeOptions);

        SizeOffsetType size_offset = obj_size_vis->compute(addr);
        if (!obj_size_vis->bothKnown(size_offset))
        {
            if (obj_size_vis->knownSize(size_offset))
            {
                reason += "size: " + size_offset.first.getZExtValue();
            }else
            {
                reason += "size: NA ";
            }
            reason += " ";
            if (obj_size_vis->knownOffset(size_offset))
            {
                reason += "Offset: " + size_offset.second.getSExtValue();
            }else
            {
                reason += "offset: NA";
            }
            result = false;
            goto dead_or_alive;
        }
        know = true;
        size = size_offset.first.getZExtValue();
        offset = size_offset.second.getSExtValue();
    }
    result = (offset >= 0) && (size >= uint64_t(offset)) &&
        ((size - uint64_t(offset)) >= (type_size / 8));

dead_or_alive:
    if (know)
    {   
        if (!result)
        {
            errs()<<" "<<ins->getParent()->getParent()->getName()<<":"<<ANSI_COLOR_RED;
            ins->getDebugLoc().print(errs());
            errs()<<ANSI_COLOR_RESET"\n";

            errs()<<ANSI_COLOR_RED
                <<"NOT SAFE, "
                <<ANSI_COLOR_RESET
                <<"Reason:"
                <<reason<<"  "
                <<"Offset:"<<offset
                <<", size:"<<size<<"\n";
        }
    }else//unknown
    {
        errs()<<" unknown "<<ins->getParent()->getParent()->getName()
            <<":"<<ANSI_COLOR_RED;
        ins->getDebugLoc().print(errs());
        errs()<<ANSI_COLOR_RESET"\n";

        errs()<<"Reason:"<<reason<<"\n";
    }
    return result;
}

void capchk::chk_unsafe_access(Module& module)
{
    size_t total_dereference = 0;
    std::map<Value*, Value*> safe_access_list;

    for (Module::iterator mi = module.begin(), me = module.end();
            mi != me; ++mi)
    {
        Function *func = dyn_cast<Function>(mi);
        if (func->isDeclaration())
        {
            continue;
        }
        for(Function::iterator fi = func->begin(), fe = func->end();
                fi != fe; ++fi)
        {
            BasicBlock* blk = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator bi = blk->begin(), be = blk->end();
                    bi != be; ++bi)
            {
                Value* ptr_operand;
                uint64_t rwsize;
                if(isa<LoadInst>(bi))
                {
                    LoadInst* load = dyn_cast<LoadInst>(bi);
                    ptr_operand = load->getPointerOperand();
                    rwsize = module.getDataLayout()
                        .getTypeStoreSizeInBits(load->getType());
                }else if(isa<StoreInst>(bi))
                {
                    StoreInst* store = dyn_cast<StoreInst>(bi);
                    ptr_operand = store->getPointerOperand();
                    rwsize = module.getDataLayout()
                        .getTypeStoreSizeInBits(store
                                ->getValueOperand()
                                ->getType());
                }else
                {
                    continue;
                }
                total_dereference++;
                if (is_safe_access(dyn_cast<Instruction>(bi),ptr_operand, rwsize))
                {
                    safe_access_list[dyn_cast<Instruction>(bi)] = ptr_operand;
                }
            }
        }
    }
    errs()<<" "
        <<safe_access_list.size()
        <<"/"
        <<total_dereference
        <<" safe access collected\n";
}

static bool mayDivideByZero(Instruction *I) {
    if (!(I->getOpcode() == Instruction::UDiv ||
                I->getOpcode() == Instruction::SDiv ||
                I->getOpcode() == Instruction::URem ||
                I->getOpcode() == Instruction::SRem))
    {
        return false;
    }
    Value *Divisor = I->getOperand(1);
    auto *CInt = dyn_cast<ConstantInt>(Divisor);
    return !CInt || CInt->isZero();
}

void capchk::chk_div0(Module& module)
{
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func_ptr = dyn_cast<Function>(f_begin);
        if (func_ptr->isDeclaration())
            continue;
        //errs()<<func_ptr->getName()<<"\n";
        std::set<BasicBlock*> bb_visited;
        std::queue<BasicBlock*> bb_work_list;
        bb_work_list.push(&func_ptr->getEntryBlock());
        while(bb_work_list.size())
        {
            BasicBlock* bb = bb_work_list.front();
            bb_work_list.pop();
            if(bb_visited.count(bb))
            {
                continue;
            }
            bb_visited.insert(bb);

            for (BasicBlock::iterator ii = bb->begin(),
                    ie = bb->end();
                    ii!=ie; ++ii)
            {
                Instruction* pvi = dyn_cast<Instruction>(ii);
                if (!mayDivideByZero(pvi))
                {
                    continue;
                }
                errs()<<" "<<func_ptr->getName()<<":"<<ANSI_COLOR_RED;
                pvi->getDebugLoc().print(errs());
                errs()<<ANSI_COLOR_RESET"\n";
                pvi->print(errs());
                errs()<<"\n";
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
    }
}

/*
 * all critical functions, should be permission checked before using are
 * listed down here
 */
//sink
#if 0
static const char* critical_functions [] =
{
    //"critical_function",
    //"commit_creds",
    //"revert_creds",
    //"put_cred",
    //"rcu_read_unlock",
    ""
};
#else
//generate critical functions dynamically
std::list<std::string> critical_functions;
std::set<std::string> cf_set;
#endif

bool is_critical_function(const std::string& str)
{
    if (std::find(std::begin(critical_functions),
                std::end(critical_functions),
                str) != std::end(critical_functions))
    {
        return true;
    }
    return false;                                  
}

/*
 * permission check functions,
 * those function are used to perform permission check before
 * using critical resources
 */
static const char* check_functions [] = 
{
    "capable",
    "ns_capable",
    //"prepare_creds",
    //"override_creds",
    //"get_cred",
    //"rcu_read_lock",
};

bool is_check_function(const std::string& str)
{
    if (std::find(std::begin(check_functions),
                std::end(check_functions),
                str) != std::end(check_functions))
    {
        return true;
    }
    return false;                                  
}

/*
 * functions not interesting will be skipped
 */
static const char* skip_functions [] = 
{
    //may operate on wrong source?
    "mutex_lock",
    "mutex_unlock",
    "schedule",
    "_cond_resched",
    "printk",
    "__kmalloc",
    "signal_fault",
    "set_current_blocked",
    "fpu__restore_sig",
    "restore_altstack",
    "__bitmap_clear",
    "__bitmap_set",
    "load_direct_gdt",
    "load_fixmap_gdt",
    "write_ldt",
    "clear_user",
    "_copy_to_user",
    "_do_fork",
    "_raw_write_lock_irq",
    "_raw_spin_lock",
    "__schedule",
    "blk_flush_plug_list",
    "mlock_fixup",
    "rcu_all_qs",
    "tty_vhangup_self",
    "wakeup_flusher_threads",
    "laptop_sync_completion",
};

bool is_skip_function(const std::string& str)
{
    if (std::find(std::begin(skip_functions),
                std::end(skip_functions),
                str) != std::end(skip_functions))
    {
        return true;
    }
    return false;                                  
}

static const char* interesting_keyword [] = 
{
    "SyS",
    "sys",
    "open",
    "release",
    "lseek",
    "read",
    "write",
    "sync",
    "ioctl",
};

bool contains_interesting_kwd(const std::string& str)
{
    for (auto i = std::begin(interesting_keyword);
            i!=std::end(interesting_keyword); ++i)
    {
        std::size_t found = str.find(*i);
        if (found != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

/*
 * interesting type which contains functions pointers to deal with user request
 */
static const char* interesting_type_word [] = 
{
    "file_operations",
};


std::list<Value*> critical_variables;


/*
 * prcess all interesting 
 *
 *------------------------
 * algo1.
 * way to find out all interesting branch conditions:
 *
 * Given interesting function list Pi, for each function pi , we find out all
 * call site, for each call site, we do backward slicing to find out all path Psi
 * then we intersect each items in Psi to see if there are branch conditions that
 * intersect, if the conditional variable intersect, we consider the variable as
 * an interesting variable, and put them into Omega.//
 *
 *------------------------
 * algo2.
 * turn each conditional branch check into return instruction and see if 
 * the callsite is still reachable, if the callsite is still reachable then
 * there's a missing check if it is unreachable then we think all things are
 * checked.//
 * The following algorithm implemented algo2, which assumes that we already know
 * interesting variable.
 *
 * in order to findout which conditional (variable)check need to turn into Return
 * instruction, we do IPA, find aliased variable for those conditional checks, 
 * and turn them into Return instruction one by one
 *
 */



void capchk::check_critical_function_usage(Module& module)
{
    std::list<Function*> processed_flist;
    //for each critical function find out all callsite(use)
    //process one critical function at a time
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func_ptr = dyn_cast<Function>(f_begin);
        if (!is_critical_function(func_ptr->getName()))
        {
            continue;
        }
#if DEBUG
        errs()<<ANSI_COLOR_GREEN
            << func_ptr->getName()
            <<ANSI_COLOR_RED<<" called from:"
            <<ANSI_COLOR_RESET<<"\n";
#endif
        //interesting. let's find out all callsite
        //for each call site, figure out all variables used for conditional branch
        //dataflow is context sensitive, path insensitive
        std::list<ValueList> dataflow;
        int xuser = 0;
        //iterate through all call site
        for (auto *U: func_ptr->users())
        {
            Value *u = dyn_cast<Value>(U);
            xuser++;
            if (xuser>MAX_PATH)
            {
                errs()<<"MAX_PATH("<<MAX_PATH<<")"
                    <<" reached consider increasing MAX_PATH\n";
                break;
            }
            //u->print(errs());
            if (isa<CallInst>(u))
            {
                Instruction *csi = dyn_cast<Instruction>(u);
#if DEBUG
                errs()<<"    "<<ANSI_COLOR_RED
                    <<csi->getFunction()->getName()
                    <<ANSI_COLOR_RESET<<"\n";
#endif
                //figure out all predecessors
                //the use of basic block should be branch instruction
                //worklist algo.
                BasicBlock* bb = csi->getParent();
                std::list<BasicBlock*> worklist;
                std::set<BasicBlock*> visited;
                //context, path insensitive
                std::list<Value*> conds;
                //the first element in this list is the call site instruction
                conds.push_back(csi);

                worklist.push_back(bb);
                visited.insert(bb);//starting point
                /*
                 * within the function belongs to current callsite
                 * this will collect all conditional branch variables used
                 * in this function
                 */
                std::set<BasicBlock*> svisited;
                while (worklist.size()!=0)
                {
                    BasicBlock* cbu = worklist.front();
                    worklist.pop_front();
                    svisited.insert(cbu);
                    for (auto* bu: cbu->users())
                    {
                        //we expect that the use of this bb is from branch instruction
                        if (!isa<BranchInst>(bu))
                            continue;
                        BranchInst *br = dyn_cast<BranchInst>(bu);
#if DEBUG
                        errs()<<"        ";
                        br->print(errs());
                        errs()<<"\n";
#endif

                        if (br->isConditional())
                        {
                            Value* condition = br->getCondition();
                            //collect this BranchInst
                            conds.push_back(condition);
                        }else
                        {
                            //non-conditional branch
                        }
                        if (svisited.count(br->getParent())!=0)
                        {
                            continue;
                        }
                        worklist.push_back(br->getParent());
                        svisited.insert(br->getParent());
                    }
                }
#if DEBUG
                errs()<<ANSI_COLOR_YELLOW
                    <<" to reach this call site, those conditions are used:"
                    <<ANSI_COLOR_RESET<<"\n";
                for (auto* cond: conds)
                {
                    errs()<<"          "<<ANSI_COLOR_CYAN;
                    cond->print(errs());
                    errs()<<ANSI_COLOR_RESET<<"\n";

                }
#endif
                //save collected conds along the bbs
                if (conds.size()>1)
                    dataflow.push_back(conds);
            }
        }
        // intersect all conditional variables along the path
        // this requires inter-procedural alias analysis
        int cnt = 0;
        for (auto path_variables: dataflow)
        {
            errs()<<ANSI_COLOR_YELLOW
                <<"-Path:"
                <<cnt
                <<ANSI_COLOR_RESET
                <<"-\n";
            bool matched = false;
            for (auto* pv : path_variables)
            {
                //pv->print(errs());
                //errs()<<"\n";

                if (pv->hasName())
                    pv->print(errs());

                //if (isa<Instruction>(pv))
                //{
                //    Instruction* pvi = dyn_cast<Instruction>(pv);
                //    errs()<<"     ";
                //    pvi->getDebugLoc().print(errs());
                //    errs()<<"\n";
                //}
                if (isa<CmpInst>(pv))
                {
                    //errs()<<"CMP:\n";
                    CmpInst* ci = dyn_cast<CmpInst>(pv);
                    Value* cio0 = ci->getOperand(0);
                    //cio0->print(errs());
                    //errs()<<"\n";
                    if (isa<CallInst>(cio0))
                    {
                        CallInst *csi = dyn_cast<CallInst>(cio0);
                        Function* csf = csi->getCalledFunction();
                        if (csf)
                        {
                            if (csf->hasName())
                            {
                                errs()<<"Call: "<<csf->getName()<<"\n";
                                if (is_check_function(csf->getName()))
                                {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                    }
                }//ignore all other instructions
            }
            assert(isa<Instruction>(path_variables.front()));
            //if there's a match
            Instruction* pvi = dyn_cast<Instruction>(path_variables.front());
            pvi->print(errs());
            errs()<<"     ";
            pvi->getDebugLoc().print(errs());
            errs()<<"\n";

            DiscoveredPath++;

            if (matched)
            {
                MatchedPath++;
                errs()<<ANSI_COLOR_GREEN
                    <<"Matched!"
                    <<ANSI_COLOR_RESET<<"\n";
            }else 
            {
                errs()<<ANSI_COLOR_RED
                    <<"NO MATCH!"
                    <<ANSI_COLOR_RESET<<"\n";
            }

            cnt++;
        }
    }
}

enum _REACHABLE
{
    FULL,
    PARTIAL,
    NONE,
};

#define MAX_BACKWD_SLICE_DEPTH 4

_REACHABLE backward_slice_build_callgraph(FunctionList &callgraph, Instruction* I)
{
    callgraph.push_back(I->getFunction());
    //run backward slicing within this function to see if there's a check

    bool checked = false;
    bool has_check = false;
    bool has_no_check = false;

    BasicBlockList bbl;
    bbl.push_back(I->getParent());
    
    while (bbl.size())
    {
        BasicBlock* bb = bbl.front();
        bbl.pop_front();

        for (auto* U: bb->users())
        {
            if (isa<BasicBlock>(U))
                bbl.push_back(dyn_cast<BasicBlock>(U));
        }
        for(BasicBlock::iterator ii = bb->begin(),
                ie = bb->end();
                ii!=ie; ++ii)
        {
            if (!isa<CallInst>(ii))
                continue;
            CallInst* ci = dyn_cast<CallInst>(ii);
            if (Function* f = ci->getCalledFunction())
            {

                if (is_check_function(f->getName()))
                {
                    goto checked_out;
                }
            }else if (ci->getCalledValue())
            {
                //function pointer?????
            }
        }
    }

    //if no check and not entry function?
    //we need to go further if not reaching limit yet
    if (callgraph.size()>MAX_BACKWD_SLICE_DEPTH)
        goto nocheck_out;

    for (auto *U: I->users())
    {
        if (isa<CallInst>(U))
        {
            switch (backward_slice_build_callgraph(callgraph, dyn_cast<Instruction>(U)))
            {
                case FULL:
                    has_check = true;
                    break;
                case PARTIAL:
                    has_check = true;
                    has_no_check = true;
                    break;
                case NONE:
                    has_no_check = true;
                    break;
                default:
                    break;
            }
        }
    }

    callgraph.pop_back();
    if (has_check && has_no_check)
    {
        return PARTIAL;
    }else if (has_check && (!has_no_check))
    {
        return FULL;
    }
    return NONE;

nocheck_out:
    callgraph.pop_back();
    errs()<<ANSI_COLOR_RED
        <<"NO CHECK ON PATH:"
        <<ANSI_COLOR_RESET;
    for (auto *c: callgraph)
    {
        errs()<<"\t->"<<c->getName()<<"\n";
    }
    errs()<<ANSI_COLOR_RESET;
    return NONE;

checked_out:
    callgraph.pop_back();
    return FULL;
}

_REACHABLE backward_slice_reachable_to_chk_function(Instruction* I)
{
    FunctionList callgraph;
    return backward_slice_build_callgraph(callgraph, I);
}


/*
 * run inter-procedural backward analysis to figure out whether this can
 * be reached from entry point without running check
 */
void capchk::check_critical_variable_usage(Module& module)
{
    errs()<<"Analysing critical variable usage\n";
    for (auto *V: critical_variables)
    {
        FunctionList flist;//known functions
#if DEBUG_ANALYZE
        errs()<<ANSI_COLOR_RED;
        V->print(errs());
        errs()<<ANSI_COLOR_RESET<<"\n";
#endif
        for (auto *U: V->users())
        {
            if (!isa<Instruction>(U))//not an instruction????
                continue;
            Function* f = dyn_cast<Instruction>(U)->getFunction();
            flist.push_back(f);

            //is this instruction reachable from non-checked path?
            switch(backward_slice_reachable_to_chk_function(dyn_cast<Instruction>(U)))
            {
                case(FULL):
                    errs()<<ANSI_COLOR_GREEN
                        <<"OK"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(PARTIAL):
                    errs()<<ANSI_COLOR_RED
                        <<"PARTIAL"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(NONE):
                    errs()<<ANSI_COLOR_RED
                        <<"NONE"<<ANSI_COLOR_RESET<<"\n";
                    break;
                default:
                    break;
            }
        }
#if DEBUG_ANALYZE
        flist.unique();
        for (auto f: flist)
        {
            //U->print(errs());
            //errs()<<"\n";
            errs()<<"\t"
                <<f->getName()
                <<"\n";
        }
#endif
    }
}

void capchk::process_each_function(Module& module)
{
    /*
     * pre-process
     * generate resource/functions from syscall entry function
     */
    errs()<<"Pre-processing...\n";
    STOP_WATCH_START;
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func_ptr = dyn_cast<Function>(f_begin);
        bool is_function_permission_checked = false;
        std::list<std::string> current_func_res_list;
        /*
         * collect interesting variables found in this function
         */
        ValueList current_critical_variables;

        if (func_ptr->isDeclaration())
            continue;

        if (!contains_interesting_kwd(func_ptr->getName()))
            continue;

#if DEBUG_PREPARE
        errs()<<func_ptr->getName()<<"\n";
#endif
        /*
         * we have a syscall entry, explore inside to create critical function
         * list, this is worklist algorithm
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

            for (BasicBlock::iterator ii = bb->begin(),
                    ie = bb->end();
                    ii!=ie; ++ii)
            {
                if (isa<CallInst>(ii))
                {
                    //only interested in call site
                    CallInst *I = dyn_cast<CallInst>(ii);
                    Function* csfunc = I->getCalledFunction();
                    if (csfunc && csfunc->hasName())
                    {
                        if (csfunc->getName().startswith("llvm.")
                                ||is_skip_function(csfunc->getName()))
                        {
                            //ignore all llvm internal functions
                            //and all check functions
                            continue;
                        }

                        if (is_check_function(csfunc->getName()))
                        {

#if DEBUG_PREPARE
                            errs()<<ANSI_COLOR_RED
                                <<"    Check function used."
                                <<ANSI_COLOR_RESET<<"\n";
#endif
                            is_function_permission_checked = true;
                        }

                        current_func_res_list.push_back(csfunc->getName());

#if DEBUG_PREPARE
                        errs()<<"        "
                            <<ANSI_COLOR_YELLOW
                            <<csfunc->getName()
                            <<ANSI_COLOR_RESET<<"\n";
#endif
                    }
                }
                /*
                 * load/store from/to global variable will be considered
                 * critical variable
                 */
                else if (isa<LoadInst>(ii))
                {
                    LoadInst *li = dyn_cast<LoadInst>(ii);
                    //li->getOperand(0);
                    if (is_function_permission_checked)
                    {
                        Value* lval = li->getOperand(0);
                        if (isa<GlobalValue>(lval))
                        {
#if DEBUG_PREPARE
                            errs()<<"\t\t"<<ANSI_COLOR_GREEN;
                            //li->print(errs());
                            errs()<<"load from: ";
                            li->getOperand(0)->print(errs());
                            errs()<<ANSI_COLOR_RESET<<"\n";
#endif
                            current_critical_variables.push_back(lval);
                        }
                    }
                }else if (isa<StoreInst>(ii))
                {
                    StoreInst *si = dyn_cast<StoreInst>(ii);
                    //si->getOperand(1);
                    if (is_function_permission_checked)
                    {
                        Value* sval = si->getOperand(1);
                        if (isa<GlobalValue>(sval))
                        {
#if DEBUG_PREPARE
                            errs()<<"\t\t"<<ANSI_COLOR_GREEN;
                            //si->print(errs());
                            si->getOperand(1)->print(errs());
                            errs()<<ANSI_COLOR_RESET<<"\n";
#endif
                            current_critical_variables.push_back(sval);
                        }
                    }
                }
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
        if (is_function_permission_checked)
        {
            critical_functions.splice(critical_functions.begin(),
                    current_func_res_list);
            critical_variables.splice(critical_variables.begin(),
                    current_critical_variables);
        }
    }

    critical_functions.unique();
    critical_variables.unique();

    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;

    errs()<<"Collected "<<critical_functions.size()<<" critical functions\n";
    errs()<<"Collected "<<critical_variables.size()<<" critical variables\n";

    STOP_WATCH_START;
    check_critical_variable_usage(module);
    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;

    //check_critical_function_usage(module);

#if 0
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
        processed_flist->push_back(func_ptr);
        //no need to inspect Declaration
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
                switch(I->getOpcode())
                {
                    case(Instruction::Call):

                        ;
                    case(Instruction::Invoke):

                        ;
break:
                        //ignore non-call site
                        ;
                }
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
#endif
}

#if 0
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
#endif

bool capchk::runOnModule(Module &module)
{
    m = &module;
    return capchkPass(module);
}

bool capchk::capchkPass(Module &module)
{

#if 0
    errs()<<ANSI_COLOR_CYAN
        <<"--- UNSAFE ACCESS CHECKER ---"
        <<ANSI_COLOR_RESET<<"\n";
    chk_unsafe_access(module);
#endif

#if 0
    errs()<<ANSI_COLOR_CYAN
        <<"--- MAY DIV BY ZERO CHECKER ---"
        <<ANSI_COLOR_RESET<<"\n";
    chk_div0(module);
#endif

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

