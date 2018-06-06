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
STATISTIC(GoodPath, "Good Path");
STATISTIC(BadPath, "Bad Path");
STATISTIC(UnResolv, "Path Unable to Resolve");
STATISTIC(CRITVAR, "Critical Variables");
STATISTIC(CRITFUNC, "Critical Functions");

typedef std::list<Value*> ValueList;
typedef std::list<BasicBlock*> BasicBlockList;
typedef std::list<Function*> FunctionList;

typedef std::map<Type*, std::set<Function*>*> TypeToFunctions;
/*
 * t2fs is used to fuzzy matching calling using function pointer
 */
TypeToFunctions t2fs;

enum _REACHABLE
{
    RFULL,
    RPARTIAL,
    RNONE,
    RUNRESOLVEABLE,
};

#define MAX_PATH 1000
#define MAX_BACKWD_SLICE_DEPTH 100
#define MAX_FWD_SLICE_DEPTH 100

/*
 * for stdlib
 */
bool cmp_llvm_val(const Value* a, const Value* b)
{
    unsigned long _a = (unsigned long)a;
    unsigned long _b = (unsigned long)b;
    return a>b;
}

class capchk : public ModulePass
{
    private:
        bool runOnModule(Module &);
        bool capchkPass(Module &);

        void process(Module& module);
        void collect_kernel_init_functions(Module& module);
        void chk_div0(Module& module);
        void chk_unsafe_access(Module& module);

        void check_critical_function_usage(Module& module);
        void check_critical_variable_usage(Module& module);

        bool is_kernel_init_functions(Function* f, std::set<Function*>& visited);
        void forward_all_interesting_usage(Instruction* I, int depth);
        
        _REACHABLE backward_slice_build_callgraph(FunctionList &callgraph, Instruction* I);
        _REACHABLE backward_slice_reachable_to_chk_function(Instruction* I);

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
    STATISTICS_DUMP(GoodPath);
    STATISTICS_DUMP(BadPath);
    STATISTICS_DUMP(UnResolv);
    STATISTICS_DUMP(CRITFUNC);
    STATISTICS_DUMP(CRITVAR);
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
    //"inode_owner_or_capable",
    //"ptrace_may_access",
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
 * skip those variables
 */

static const char* skip_var [] = 
{
    "jiffies",
    "nr_cpu_ids",
    "nr_irqs",
    "nr_threads",
};

bool is_skip_var(const std::string& str)
{
    if (std::find(std::begin(skip_var),
                std::end(skip_var),
                str) != std::end(skip_var))
    {
        return true;
    }
    return false;                                  
}


/*
 * common interface which is not considered dangerous function
 * some of those functions need to analyze together with parameters
 * (require SVF, data flow analysis)
 */
static const char* skip_functions [] = 
{
    //may operate on wrong source?
    //"capable",
    //"ns_capable",
    "__mutex_init",
    "mutex_lock",
    "mutex_unlock",
    "schedule",
    "_cond_resched",
    "printk",
    "__kmalloc",
    "_copy_to_user",
    "_do_fork",
    "__memcpy",
    "strncmp",
    "strlen",
    "strim",
    "strchr",
    "strcmp",
    "memcmp",
    "skip_spaces",
    "kfree",
    "kmalloc"
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

static const char* kernel_start_functions [] = 
{
    "start_kernel",
};

std::list<std::string> kernel_init_functions;
std::list<std::string> non_kernel_init_functions;

/*
 * all discovered wrapper function to check functions will be stored here
 */
std::set<Function*> chk_function_wrapper;

/*bool is_kernel_init_functions(const std::string& str)
{
    if (std::find(std::begin(kernel_init_functions),
                std::end(kernel_init_functions),
                str) != std::end(kernel_init_functions))
    {
        return true;
    }
    return false;
}*/

/*
 * is this functions part of the kernel init sequence?
 * if function f has single user which goes to start_kernel(),
 * then this is a init function
 */
bool capchk::is_kernel_init_functions(Function* f, std::set<Function*>& visited)
{
    std::string str = f->getName();
    if (std::find(std::begin(kernel_init_functions),
                std::end(kernel_init_functions),
                str) != std::end(kernel_init_functions))
    {
        return true;
    }
    if (std::find(std::begin(non_kernel_init_functions),
                std::end(non_kernel_init_functions),
                str) != std::end(non_kernel_init_functions))
    {
        return false;
    }
    //init functions with initcall prefix belongs to kernel init sequence
    std::string std_gv_spec = "__initcall_" + str;
    for (GlobalVariable &gvi: m->globals())
    {
        GlobalValue* gi = &gvi;
        if (Value* gv = dyn_cast<Value>(gi))
        {
            if (gv->getName().startswith(std_gv_spec))
            {
                kernel_init_functions.push_back(str);
                return true;
            }
        }
    }


    //not found in cache?
    //all path that can reach to f should start from start_kernel()
    FunctionList flist;
    for (auto *U : f->users())
    {
        if (CallInst* cs = dyn_cast<CallInst>(U))
        {
            if (Function* csf = cs->getCalledFunction())
            {
                if (!csf->isDeclaration())
                    flist.push_back(csf);
            }
        }
    }
    //no user?
    if (flist.size()==0)
    {
        non_kernel_init_functions.push_back(f->getName());
        return false;
    }

    visited.insert(f);
    while (flist.size())
    {
        Function* f = flist.front();
        flist.pop_front();
        if (visited.count(f))
            continue;
        visited.insert(f);
        if (!is_kernel_init_functions(f, visited))
        {
            non_kernel_init_functions.push_back(f->getName());
            return false;
        }
    }
    kernel_init_functions.push_back(f->getName());
    return true;
}

void capchk::collect_kernel_init_functions(Module& module)
{
    Function *kstart = NULL;
    kernel_init_functions.push_back("start_kernel");
    kernel_init_functions.push_back("x86_64_start_kernel");
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func_ptr = dyn_cast<Function>(f_begin);
        if (func_ptr->isDeclaration())
            continue;
        if (func_ptr->hasName())
        {
            if (func_ptr->getName().startswith("start_kernel"))
            {
                errs()<<"Found start_kernel\n";
                kstart = func_ptr;
                break;
            }
        }
    }
    assert(kstart!=NULL);

    //find all init functions starting from start_kernel
    std::set<Function*> func_visited;
    std::list<Function*> func_work_list;
    func_work_list.push_back(kstart);

    while (func_work_list.size())
    {
        Function* cfunc = func_work_list.front();
        func_work_list.pop_front();

        if (cfunc->isDeclaration())
            continue;

        func_visited.insert(cfunc);
        kernel_init_functions.push_back(cfunc->getName());

        //for current function
        std::set<BasicBlock*> bb_visited;
        std::queue<BasicBlock*> bb_work_list;
        bb_work_list.push(&cfunc->getEntryBlock());
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
                CallInst* ci = dyn_cast<CallInst>(ii);
                if (!ci)
                {
                    continue;
                }
                if (Function* nf = ci->getCalledFunction())
                {
                    if (nf->isDeclaration())
                        continue;
                    if (func_visited.count(nf))
                        continue;
                    func_work_list.push_back(nf);
                }else if (Value* nv = ci->getCalledValue())
                {
                    //function pointer
                }
            }
            for (succ_iterator si = succ_begin(bb),
                    se = succ_end(bb);
                    si!=se; ++si)
            {
                BasicBlock* succ_bb = cast<BasicBlock>(*si);
                bb_work_list.push(succ_bb);
            }
        }
    }
    kernel_init_functions.sort();
    kernel_init_functions.erase(
            std::unique(kernel_init_functions.begin(), kernel_init_functions.end()),
            kernel_init_functions.end());

    errs()<<"Kernel Init Functions:\n";
    for (auto I: kernel_init_functions)
    {
        errs()<<I<<"\n";
    }
}

std::list<Value*> critical_variables;


_REACHABLE capchk::backward_slice_build_callgraph(FunctionList &callgraph, Instruction* I)
{
    Function* f = I->getFunction();

    DominatorTree dt(*f);

    callgraph.push_back(f);
    //run backward slicing within this function to see if there's a check

    bool checked = false;
    bool has_check = false;
    bool has_no_check = false;
    bool has_user = false;

    BasicBlockList bbl;
    std::set<BasicBlock*> bbvisited;
    bbl.push_back(I->getParent());
    
    errs()<<"\n+"<<callgraph.size();
    for (int i=0;i<callgraph.size();i++)
        errs()<<" ";
    errs()<<f->getName()<<"\n";

    std::set<Function*> k_visited;
    
    if (is_kernel_init_functions(f, k_visited))
    {
        errs()<<"Hit Kernel Init Function\n";
        goto checked_out; 
    }

    //all predecessor basic blocks
    //should call check function 
    //Also check whether the check can dominate use
    while (bbl.size())
    {
        BasicBlock* bb = bbl.front();
        bbvisited.insert(bb);
        bbl.pop_front();

        for (pred_iterator pi = pred_begin(bb),
                pe = pred_end(bb);
                pi!=pe; ++pi)
        {
            BasicBlock *nbb = cast<BasicBlock>(*pi);
            if (nbb==NULL)
                continue;
            if (bbvisited.count(nbb))
                continue;
            bbl.push_back(nbb);
        }

        for(BasicBlock::iterator ii = bb->begin(),
                ie = bb->end();
                ii!=ie; ++ii)
        {
            CallInst* ci = dyn_cast<CallInst>(ii);
            if (!ci)
                continue;
            Function * ifunc = NULL;
            if (Function* f = ci->getCalledFunction())
            {
                ifunc = f;
                //if this is either a check function or a wrapper to check function
                if (is_check_function(ifunc->getName()) ||
                        (chk_function_wrapper.count(ifunc)!=0))
                {
                    errs()<<"Hit Check Function:"<<ifunc->getName()<<"\n";
                    ci->getDebugLoc().print(errs());
                    errs()<<"\n";
                    if (!dt.dominates(ci, I))
                    {
                        errs()<<ANSI_COLOR_YELLOW
                            <<"However, this is a partial check."
                            <<ANSI_COLOR_RESET
                            <<"\n";
                        continue;
                    }
                    goto checked_out;
                }
            }else if (ci->getCalledValue())
            {
                Value* cv = ci->getCalledValue();
                //function pointer
                //errs()<<"call with function pointer\n";
                //cv->getType()->print(errs());
                //cv->print(errs());
                //errs()<<"\n";
                //ci->getDebugLoc().print(errs());

                //try to match a function with the same signature
                //FIXME: run SVF to figure out which function
                // this pointer points to
                std::set<Function*> *fl = t2fs[cv->getType()];
                if (fl==NULL)
                {
                    //should consider this unresolvable???
                    UnResolv++;
                    continue;
                }
                /*
                for (std::set<Function*>::iterator
                        fit = fl->begin(), fe = fl->end();
                        fit!=fe; ++fit)
                {
                    ifunc = *fit;
                    //if this is either a check function or a wrapper to check function
                    if (is_check_function(ifunc->getName()) ||
                            (chk_function_wrapper.count(ifunc)!=0))
                    {
                        errs()<<"Hit Check Function(call with fptr):"<<ifunc->getName()<<"\n";
                        ci->getDebugLoc().print(errs());
                        errs()<<"\n";
                        if (!dt.dominates(ci, I))
                        {
                            errs()<<ANSI_COLOR_YELLOW
                                <<"However, this is a partial check."
                                <<ANSI_COLOR_RESET
                                <<"\n";
                            continue;
                        }
                        continue;
                    }
                }*/
            }
        }
    }

    //if no check and not entry function?
    //we need to go further if not reaching limit ye
    if (callgraph.size()>MAX_BACKWD_SLICE_DEPTH)
        goto nocheck_out;

    for (auto *U: f->users())
    {
        has_user = true;
        if (isa<CallInst>(U))
        {
            switch (backward_slice_build_callgraph(callgraph, dyn_cast<Instruction>(U)))
            {
                case RFULL:
                    has_check = true;
                    break;
                case RPARTIAL:
                    has_check = true;
                    has_no_check = true;
                    break;
                case RNONE:
                    has_no_check = true;
                    break;
                case RUNRESOLVEABLE:
                default:
                    llvm_unreachable("what????");
                    break;
            }
        }else
        {
            //used by non-call instruction????
            //should match to all call site using fptr
            errs()<<"Used by non-call\n";
        }
    }

    if (!has_user)
    {
        errs()<<"This Function has no user? consider as entry point???\n";
        goto nocheck_out;
    }

    callgraph.pop_back();
    if (has_check)
    {
        if (has_no_check)
        {
            return RPARTIAL;
        }
        return RFULL;
    }
    return RNONE;

nocheck_out:
    errs()<<ANSI_COLOR_RED
        <<"\nNO CHECK ON PATH:\n"
        <<ANSI_COLOR_YELLOW;
    for (auto *c: callgraph)
    {
        errs()<<"\t->"<<c->getName()<<"\n";
    }
    errs()<<ANSI_COLOR_RESET;
    callgraph.pop_back();
    return RNONE;

checked_out:
    //errs()<<ANSI_COLOR_GREEN
    //    <<"Path Checked, return FULL\n"
    //    <<ANSI_COLOR_RESET;
    callgraph.pop_back();
    return RFULL;
}

_REACHABLE capchk::backward_slice_reachable_to_chk_function(Instruction* I)
{
    FunctionList callgraph;
    return backward_slice_build_callgraph(callgraph, I);
}

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
        if (is_skip_function(func_ptr->getName()))
        {
            continue;
        }
        errs()<<ANSI_COLOR_YELLOW
            <<"Inspect Use of Function:"
            <<func_ptr->getName()
            <<ANSI_COLOR_RESET
            <<"\n";
        //iterate through all call site
        for (auto *U: func_ptr->users())
        {
            CallInst *cs = dyn_cast<CallInst>(U);
            if (!cs)
            {
                continue;
            }
            errs()<<ANSI_COLOR_MAGENTA
                <<"Use:";
            cs->getDebugLoc().print(errs());
            //U->print(errs());
            errs()<<ANSI_COLOR_RESET<<"\n";
            switch(backward_slice_reachable_to_chk_function(cs))
            {
                case(RFULL):
                    GoodPath++;
                    errs()<<ANSI_COLOR_GREEN
                        <<"[FULL]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RPARTIAL):
                    BadPath++;
                    errs()<<ANSI_COLOR_YELLOW
                        <<"[PARTIAL]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RNONE):
                    BadPath++;
                    errs()<<ANSI_COLOR_RED
                        <<"[NONE]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RUNRESOLVEABLE):
                    UnResolv++;
                    break;
                default:
                    break;
            }
        }
    }
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
        errs()<<ANSI_COLOR_CYAN;
        V->print(errs());
        errs()<<ANSI_COLOR_RESET<<"\n";
#endif
        for (auto *U: V->users())
        {
            Instruction *ui = dyn_cast<Instruction>(U);
            if (!ui)//not an instruction????
                continue;
            Function* f = dyn_cast<Instruction>(U)->getFunction();

            //make sure this is not a kernel init function
            std::set<Function*> k_visited;
            if (is_kernel_init_functions(f, k_visited))
                continue;
            if (isa<LoadInst>(ui))
            {
                errs()<<"LOAD: ";
            }else if (isa<StoreInst>(ui))
            {
                errs()<<"STORE: ";
            }else
            {
                errs()<<"Use:opcode="<<ui->getOpcode()<<" ";
            }
            ui->getDebugLoc().print(errs());
            errs()<<"\n";

            flist.push_back(f);
            errs()<<"Function: "
                <<f->getName()
                <<"";
            //is this instruction reachable from non-checked path?
            switch(backward_slice_reachable_to_chk_function(dyn_cast<Instruction>(U)))
            {
                case(RFULL):
                    GoodPath++;
                    errs()<<ANSI_COLOR_GREEN
                        <<"[FULL]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RPARTIAL):
                    BadPath++;
                    errs()<<ANSI_COLOR_YELLOW
                        <<"[PARTIAL]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RNONE):
                    BadPath++;
                    errs()<<ANSI_COLOR_RED
                        <<"[NONE]"<<ANSI_COLOR_RESET<<"\n";
                    break;
                case(RUNRESOLVEABLE):
                    UnResolv++;
                    break;
                default:
                    break;
            }
        }
#if 0//DEBUG_ANALYZE
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

/*
 * interprocedural program slicing
 * figure out all global variable usage and function calls
 */
void capchk::forward_all_interesting_usage(Instruction* I, int depth)
{
    Function *func_ptr = I->getFunction();
    bool is_function_permission_checked = false;
    std::list<std::string> current_func_res_list;
    /*
     * collect interesting variables found in this function
     */
    ValueList current_critical_variables;

    if (depth>MAX_FWD_SLICE_DEPTH)
    {
//        errs()<<ANSI_COLOR_RED
//            <<"FWD SLICING MAX "
//            <<MAX_FWD_SLICE_DEPTH
//            <<" REACHED\n";
        return;
    }

#if DEBUG_PREPARE
    errs()<<func_ptr->getName()<<"\n";
#endif
    std::set<BasicBlock*> bb_visited;
    std::queue<BasicBlock*> bb_work_list;
    bb_work_list.push(I->getParent());
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
                if (is_function_permission_checked)
                    continue;
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

                    if (is_check_function(csfunc->getName()) ||
                            (chk_function_wrapper.count(csfunc)!=0))
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
                        if (!is_skip_var(lval->getName()))
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
                        errs()<<"store to: ";
                        si->getOperand(1)->print(errs());
                        errs()<<ANSI_COLOR_RESET<<"\n";
#endif
                        if (!is_skip_var(sval->getName()))
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
        //forwar slicing
        critical_functions.splice(critical_functions.begin(),
                current_func_res_list);
        critical_variables.splice(critical_variables.begin(),
                current_critical_variables);
        //this is a wrapper
        //errs()<<"Adding wrapper: "<<func_ptr->getName()<<"\n";
        //chk_function_wrapper.insert(func_ptr);

        //if functions is permission checked, consider this as a wrapper
        //and we need to check all use of this function
        for (auto *U: func_ptr->users())
        {
            if (CallInst* cs = dyn_cast<CallInst>(U))
            {
                forward_all_interesting_usage(cs, depth+1);
            }
        }
    }
}

void capchk::process(Module& module)
{
    /*
     * pre-process
     * generate resource/functions from syscall entry function
     */
    int count = 0;
    errs()<<"Pre-processing...\n";

    errs()<<"Collecting Initialization Closure.\n";
    STOP_WATCH_START;
    //collect_kernel_init_functions(module);
    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;
    errs()<<"Running SVF on init functions.\n";
    STOP_WATCH_START;
    //run_svf();
    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;

    errs()<<"Collect all permission-checked variables\n";
    STOP_WATCH_START;
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func_ptr = dyn_cast<Function>(fi);
        if (func_ptr->isDeclaration())
            continue;

        //auto& aa = getAnalysis<AAResultsWrapperPass>(*func_ptr).getAAResults();

        Type* type = func_ptr->getType();
        std::set<Function*> *fl = t2fs[type];
        if (fl==NULL)
        {
            fl = new std::set<Function*>;
            t2fs[type] = fl;
        }
        fl->insert(func_ptr);

        //if (!contains_interesting_kwd(func_ptr->getName()))
        //    continue;

        /*
         * FIXME: in order to figure out all use of critical variables,
         * we should use SVF/or other AA method to figure out Interprocedural
         * alias set
         */
        forward_all_interesting_usage(func_ptr->getEntryBlock().getFirstNonPHI(),0);
    }

    critical_functions.sort();
    critical_functions.erase(
            std::unique(critical_functions.begin(), critical_functions.end()),
            critical_functions.end());

    critical_variables.sort(cmp_llvm_val);
    critical_variables.erase(
            std::unique(critical_variables.begin(), critical_variables.end()),
            critical_variables.end());

    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;

    CRITFUNC = critical_functions.size();
    CRITVAR = critical_variables.size();

    errs()<<"Collected "<<critical_functions.size()<<" critical functions\n";
    errs()<<"Collected "<<critical_variables.size()<<" critical variables\n";

    errs()<<"Run Analysis.\n";
    /*STOP_WATCH_START;
    check_critical_variable_usage(module);
    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;*/

    STOP_WATCH_START;
    check_critical_function_usage(module);
    STOP_WATCH_STOP;
    STOP_WATCH_REPORT;
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

    process(module);

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

