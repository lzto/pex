/*
 * CapChecker
 * linux kernel capability checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "capchk.h"

#include "cvfa.h"
//my aux headers
#include "internal.h"
#include "color.h"
#include "aux.h"
#include "stopwatch.h"

#define TOTOAL_NUMBER_OF_STOP_WATCHES 2
#define WID_0 0
#define WID_KINIT 1
#define WID_CC 1
#define WID_PI 1

STOP_WATCH(TOTOAL_NUMBER_OF_STOP_WATCHES);

#define DEBUG_PREPARE 0
#define DEBUG_ANALYZE 1

#define MAX_PATH 1000
#define MAX_BACKWD_SLICE_DEPTH 100
#define MAX_FWD_SLICE_DEPTH 100

using namespace llvm;

char capchk::ID;

STATISTIC(FuncCounter, "Functions greeted");
STATISTIC(ExternalFuncCounter, "External functions");
STATISTIC(DiscoveredPath, "Discovered Path");
STATISTIC(MatchedPath, "Matched Path");
STATISTIC(GoodPath, "Good Path");
STATISTIC(BadPath, "Bad Path");
STATISTIC(UnResolv, "Path Unable to Resolve");
STATISTIC(CSFPResolved, "Resolved CallSite Using Function Pointer");
STATISTIC(CRITVAR, "Critical Variables");
STATISTIC(CRITFUNC, "Critical Functions");
STATISTIC(FwdAnalysisMaxHit, "# of times max depth for forward analysis hit");
STATISTIC(BwdAnalysisMaxHit, "# of times max depth for backward analysis hit");
STATISTIC(CPUnResolv, "Critical Function Pointer Unable to Resolve");
STATISTIC(CPResolv, "Critical Function Pointer Resolved");
STATISTIC(CFuncUsedByNonCallInst, "Critical Functions used by non CallInst");
STATISTIC(CFuncUsedByStaticAssign, "Critical Functions used by static assignment");
STATISTIC(MatchCallCriticalFuncPtr, "# of times indirect call site matched with critical functions");
STATISTIC(UnMatchCallCriticalFuncPtr, "# of times indirect call site failed to match with critical functions");
STATISTIC(CapChkInFPTR, "found capability check inside call using function ptr\n");

////////////////////////////////////////////////////////////////////////////////
//map function to its check instruction
Function2ChkInst f2ci;
Value2ChkInst v2ci;

//t2fs is used to fuzzy matching calling using function pointer
TypeToFunctions t2fs;

//map function to check instructions inside that function
//only include direct check
Function2ChkInst f2chks;
//discovered check inside functions, including other callee
//which will call the check, which is the super set of f2chks
Function2ChkInst f2chks_disc;

//all function pointer assignment,(part of function use)
InstructionSet fptrassign;
//stores all indirect call sites
InDirectCallSites idcs;
//function to callsite instruction
//type0: direct call with type cast
Function2CSInst f2csi_type0;
//type1: indirect call
Function2CSInst f2csi_type1;

//store indirect call site to its candidates
ConstInst2Func idcs2callee;

//all functions in the kernel
FunctionSet all_functions;

//all syscall is listed here
FunctionSet syscall_list;

//all discovered interesting type(have struct member points to function with check)
TypeSet discovered_interesting_type;

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
    STATISTICS_DUMP(CSFPResolved);
    STATISTICS_DUMP(CRITFUNC);
    STATISTICS_DUMP(CRITVAR);
    STATISTICS_DUMP(FwdAnalysisMaxHit);
    STATISTICS_DUMP(BwdAnalysisMaxHit);
    STATISTICS_DUMP(CPUnResolv);
    STATISTICS_DUMP(CPResolv);
    STATISTICS_DUMP(CFuncUsedByNonCallInst);
    STATISTICS_DUMP(CFuncUsedByStaticAssign);
    STATISTICS_DUMP(MatchCallCriticalFuncPtr);
    STATISTICS_DUMP(UnMatchCallCriticalFuncPtr);
    STATISTICS_DUMP(CapChkInFPTR);
    errs()<<"\n\n\n";
}
#endif

/*
 * command line options
 */
cl::opt<bool> knob_capchk_critical_var("ccv",
        cl::desc("check critical variable usage - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_critical_fun("ccf",
        cl::desc("check critical function usage - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_ccfv("ccfv",
        cl::desc("print path to critical function(collect phase) - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_ccvv("ccvv",
        cl::desc("print path to critical variable(collect phase) - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_f2c("f2c",
        cl::desc("print critical function to capability mapping - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_v2c("v2c",
        cl::desc("print critical variable to capability mapping - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_caw("caw",
        cl::desc("print check functions and wrappers discovered - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_kinit("kinit",
        cl::desc("print kernel init functions - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_nkinit("nkinit",
        cl::desc("print kernel non init functions - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_cvf("cvf",
        cl::desc("complex value flow analysis - disabled by default"),
        cl::init(false));

cl::opt<string> knob_skip_func_list("skipfun",
        cl::desc("non-critical function list"),
        cl::init("skip.fun"));

cl::opt<string> knob_skip_var_list("skipvar",
        cl::desc("non-critical variable name list"),
        cl::init("skip.var"));

cl::opt<bool> knob_dump_good_path("prt-good",
        cl::desc("print good path - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_dump_bad_path("prt-bad",
        cl::desc("print bad path - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_dump_ignore_path("prt-ign",
        cl::desc("print ignored path - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_warn_capchk_during_kinit("wcapchk-kinit",
        cl::desc("warn capability check during kernel boot process - disabled by default"),
        cl::init(false));


/*
 * helper function
 */
Instruction* GetNextInstruction(Instruction* I)
{
    if (isa<TerminatorInst>(I))
        return I;
    BasicBlock::iterator BBI(I);
    return dyn_cast<Instruction>(++BBI);
}

Instruction* GetNextNonPHIInstruction(Instruction* I)
{
    if (isa<TerminatorInst>(I))
        return I;
    BasicBlock::iterator BBI(I);
    while(isa<PHINode>(BBI))
        ++BBI;
    return dyn_cast<Instruction>(BBI);
}

Function* get_callee_function_direct(Instruction* i)
{
    CallInst* ci = dyn_cast<CallInst>(i);
    if (Function* f = ci->getCalledFunction())
        return f;
    Value* cv = ci->getCalledValue();
    Function* f = dyn_cast<Function>(cv->stripPointerCasts());
    return f;
}

StringRef get_callee_function_name(Instruction* i)
{
    if (Function* f = get_callee_function_direct(i))
        return f->getName();
    return "";
}

bool function_has_gv_initcall_use(Function* f)
{
    static FunctionSet fs_initcall;
    static FunctionSet fs_noninitcall;
    if (fs_initcall.count(f)!=0)
        return true;
    if (fs_noninitcall.count(f)!=0)
        return false;
    for (auto u: f->users())
        if (GlobalValue *gv = dyn_cast<GlobalValue>(u))
        {
            if (!gv->hasName())
                continue;
            if (gv->getName().startswith("__initcall_"))
            {
                fs_initcall.insert(f);
                return true;
            }
        }
    fs_noninitcall.insert(f);
    return false;
}

/*
 * all critical functions and variables
 * should be permission checked before use
 * generate critical functions on-the-fly
 */
FunctionSet critical_functions;
ValueSet critical_variables;

bool is_critical_function(Function* f)
{
    return critical_functions.count(f)!=0;
}

/*
 * permission check functions,
 * those function are used to perform permission check before
 * using critical resources
 */

bool is_check_function(const std::string& str)
{
    if (std::find(std::begin(_builtin_check_functions),
                std::end(_builtin_check_functions),
                str) != std::end(_builtin_check_functions))
    {
        return true;
    }
    return false;                                  
}

/*
 * record capability parameter position passed to capability check function
 * all discovered wrapper function to check functions will also have one entry
 *
 * This data is available after calling collect_wrappers()
 */
FunctionData chk_func_cap_position;

bool is_function_chk_or_wrapper(Function* f)
{
    return chk_func_cap_position.find(f)!=chk_func_cap_position.end();
}

//skip variables
bool use_internal_skip_var_list = false;
StringSet skip_var;

bool is_skip_var(const std::string& str)
{
    if (use_internal_skip_var_list)
        return std::find(std::begin(_builtin_skip_var), std::end(_builtin_skip_var), str)
            != std::end(_builtin_skip_var);
    return skip_var.count(str)!=0;
}

void load_skip_var_list(std::string& fn)
{
    std::ifstream input(fn);
    if (!input.is_open())
    {
        use_internal_skip_var_list = true;
        return;
    }
    std::string line;
    while(std::getline(input,line))
    {
        skip_var.insert(line);
    }
    input.close();
    errs()<<"Load skip var list, total:"<<skip_var.size()<<"\n";
}
//skip functions
bool use_internal_skip_func_list = false;
StringSet skip_functions;

bool is_skip_function(const std::string& str)
{
    if (use_internal_skip_func_list)
        return std::find(std::begin(_builtin_skip_functions), std::end(_builtin_skip_functions), str)
            != std::end(_builtin_skip_functions);
    return skip_functions.count(str)!=0;
}

void load_skip_func_list(std::string& fn)
{
    std::ifstream input(fn);
    if (!input.is_open())
    {
        use_internal_skip_func_list = true;
        return;
    }
    std::string line;
    while(std::getline(input,line))
    {
        skip_functions.insert(line);
    }
    input.close();
    errs()<<"Load skip function list, total:"<<skip_functions.size()<<"\n";
}

/*
 * interesting type which contains functions pointers to deal with user request
 */
bool is_interesting_type(Type* ty)
{
    if (!ty->isStructTy())
        return false;
    if (!dyn_cast<StructType>(ty)->hasName())
        return false;
    StringRef tyn = ty->getStructName();
    for (int i=0;i<BUILTIN_INTERESTING_TYPE_WORD_LIST_SIZE;i++)
    {
        if (tyn.startswith(_builtin_interesting_type_word[i]))
            return true;
    }
    if (discovered_interesting_type.count(ty)!=0)
        return true;
    return false;
}

bool is_syscall_prefix(StringRef str)
{
    for (int i=0;i<4;i++)
    {
        if (str.startswith(_builtin_syscall_prefix[i]))
        {
            return true;
        }
    }
    return false;
}

bool is_syscall(Function *f)
{
    return syscall_list.count(f)!=0;
}

FunctionSet kernel_init_functions;
FunctionSet non_kernel_init_functions;
////////////////////////////////////////////////////////////////////////////////
/*
 * debug function, track process progress internally
 */
void capchk::dump_dbgstk()
{
    errs()<<ANSI_COLOR_GREEN<<"Process Stack:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;

    for (auto* I: dbgstk)
    {
        errs()<<""<<cnt<<" "<<I->getFunction()->getName()<<" ";
        I->getDebugLoc().print(errs());
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

void capchk::dump_callstack(InstructionList& callstk)
{
    errs()<<ANSI_COLOR_GREEN<<"Call Stack:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;

    for (auto* I: callstk)
    {
        errs()<<""<<cnt<<" "<<I->getFunction()->getName()<<" ";
        I->getDebugLoc().print(errs());
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

void capchk::dump_as_good(InstructionList& callstk)
{
    if (!knob_dump_good_path)
        return;

    errs()<<ANSI_COLOR_MAGENTA
        <<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<ANSI_COLOR_GREEN
        <<"=Meet Check On PATH"<<"="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
}

void capchk::dump_as_bad(InstructionList& callstk)
{
    if (!knob_dump_bad_path)
        return;
    errs()<<ANSI_COLOR_MAGENTA
        <<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<"\n"<<ANSI_COLOR_RED
        <<"=NO CHECK ON PATH="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
}

void capchk::dump_as_ignored(InstructionList& callstk)
{
    if (!knob_dump_ignore_path)
        return;
    errs()<<ANSI_COLOR_MAGENTA
        <<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<"\n"<<ANSI_COLOR_YELLOW
        <<"=IGNORE PATH="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
}


void capchk::dump_v2ci()
{
    if (!knob_capchk_v2c)
        return;
    errs()<<ANSI_COLOR(BG_BLUE,FG_WHITE)
        <<"--- Variables Protected By Capability---"
        <<ANSI_COLOR_RESET<<"\n";
    for (auto& cis: v2ci)
    {
        Value* v = cis.first;
        errs()<<ANSI_COLOR_GREEN<<v->getName()<<ANSI_COLOR_RESET<<"\n";
        int last_cap_no = -1;
        bool mismatched_chk_func = false;
        Function* last_cap_chk_func = NULL;
        for (auto *ci: *cis.second)
        {
            CallInst* cs = dyn_cast<CallInst>(ci);
            Function* cf = get_callee_function_direct(cs);
            int cap_no = -1;
            if (is_function_chk_or_wrapper(cf))
            {
                cap_no = chk_func_cap_position[cf];
                Value* capv = cs->getArgOperand(cap_no);
                if (!isa<ConstantInt>(capv))
                {
                    cs->getDebugLoc().print(errs());
                    errs()<<"\n";
                    cs->print(errs());
                    errs()<<"\n";
                    //llvm_unreachable("expect ConstantInt in capable");
                    errs()<<"Dynamic Load CAP\n";
                    cs->getDebugLoc().print(errs());
                    errs()<<"\n";
                    continue;
                }
                cap_no = dyn_cast<ConstantInt>(capv)->getSExtValue();
                if (last_cap_no==-1)
                {
                    last_cap_no=cap_no;
                    last_cap_chk_func = cf;
                }
                if (last_cap_no!=cap_no)
                    last_cap_no = -2;
                if (last_cap_chk_func!=cf)
                    mismatched_chk_func = true;
            }
            assert((cap_no>=CAP_CHOWN) && (cap_no<=CAP_LAST_CAP));
            errs()<<"    "<<cap2string[cap_no]<<" @ "<<cf->getName()<<" ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n";
        }
        if ((last_cap_no==-2) || (mismatched_chk_func))
            errs()<<ANSI_COLOR_RED<<"inconsistent check"
                    <<ANSI_COLOR_RESET<<"\n";
    }
}

void capchk::dump_f2ci()
{
    if (!knob_capchk_f2c)
        return;
    errs()<<ANSI_COLOR(BG_BLUE,FG_WHITE)
        <<"--- Function Protected By Capability---"
        <<ANSI_COLOR_RESET<<"\n";
    for (auto& cis: f2ci)
    {
        Function* func = cis.first;
        errs()<<ANSI_COLOR_GREEN<<func->getName()<<ANSI_COLOR_RESET<<"\n";
        int last_cap_no = -1;
        bool mismatched_chk_func = false;
        Function* last_cap_chk_func = NULL;
        for (auto *ci: *cis.second)
        {
            CallInst* cs = dyn_cast<CallInst>(ci);
            Function* cf = get_callee_function_direct(cs);
            int cap_no = -1;
            if (is_function_chk_or_wrapper(cf))
            {
                cap_no = chk_func_cap_position[cf];
                Value* capv = cs->getArgOperand(cap_no);
                if (!isa<ConstantInt>(capv))
                {
                    cs->getDebugLoc().print(errs());
                    errs()<<"\n";
                    cs->print(errs());
                    errs()<<"\n";
                    //llvm_unreachable("expect ConstantInt in capable");
                    errs()<<"Dynamic Load CAP\n";
                    cs->getDebugLoc().print(errs());
                    errs()<<"\n";
                    continue;
                }
                cap_no = dyn_cast<ConstantInt>(capv)->getSExtValue();
                if (last_cap_no==-1)
                {
                    last_cap_no=cap_no;
                    last_cap_chk_func = cf;
                }
                if (last_cap_no!=cap_no)
                    last_cap_no = -2;
                if (last_cap_chk_func!=cf)
                    mismatched_chk_func = true;
            }
            assert((cap_no>=CAP_CHOWN) && (cap_no<=CAP_LAST_CAP));
            errs()<<"    "<<cap2string[cap_no]<<" @ "<<cf->getName()<<" ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n";
        }
        if ((last_cap_no==-2) || (mismatched_chk_func))
            errs()<<ANSI_COLOR_RED<<"inconsistent check"
                    <<ANSI_COLOR_RESET<<"\n";
    }
}

void capchk::dump_kinit()
{
    if (!knob_capchk_kinit)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
            <<"=Kernel Init Functions="
            <<ANSI_COLOR_RESET<<"\n";
    for (auto I: kernel_init_functions)
    {
        errs()<<I->getName()<<"\n";
    }
    errs()<<"=o=\n";
}

void capchk::dump_non_kinit()
{
    if (!knob_capchk_nkinit)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
            <<"=NON-Kernel Init Functions="
            <<ANSI_COLOR_RESET<<"\n";
    for (auto I: non_kernel_init_functions)
    {
        errs()<<I->getName()<<"\n";
    }
    errs()<<"=o=\n";
}

void capchk::dump_chk_and_wrap()
{
    if (!knob_capchk_caw)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
        <<"=chk functions and wrappers="
        <<ANSI_COLOR_RESET<<"\n";
    for (auto &f2p: chk_func_cap_position)
    {
        errs()<<". "<<f2p.first->getName()
            <<"  @ "<<f2p.second
            <<"\n";
    }
    errs()<<"=o=\n";
}

/*
 * is this function type contains non-trivial(non-primary) type?
 */
bool capchk::is_complex_type(Type* t)
{
    if (!t->isFunctionTy())
        return false;
    if (t->isFunctionVarArg())
        return true;
    FunctionType *ft = dyn_cast<FunctionType>(t);
    //params
    int number_of_complex_type = 0;
    for (int i = 0; i<ft->getNumParams(); i++)
    {
        Type* argt = ft->getParamType(i);
strip_pointer:
        if (argt->isPointerTy())
        {
            argt = argt->getPointerElementType();
            goto strip_pointer;
        }

        if (argt->isSingleValueType())
            continue;
        number_of_complex_type++;
    }
    //return type
    Type* rt = ft->getReturnType();

again://to strip pointer
    if (rt->isPointerTy())
    {
        Type* pet = rt->getPointerElementType();
        if (pet->isPointerTy())
        {
            rt = pet;
            goto again;
        }
        if (!pet->isSingleValueType())
        {
            number_of_complex_type++;
        }
    }

    return (number_of_complex_type!=0);
}

/*
 * def/use global?
 * take care of phi node using `visited'
 */
Value* capchk::get_global_def(Value* val, ValueSet& visited)
{
    if (visited.count(val)!=0)
        return NULL;
    visited.insert(val);
    if (isa<GlobalValue>(val))
        return val;
    if (Instruction* vali = dyn_cast<Instruction>(val))
    {
        for (auto &U : vali->operands())
        {
            Value* v = get_global_def(U, visited);
            if (v)
                return v;
        }
    }else if (Value* valv = dyn_cast<Value>(val))
    {
        //llvm_unreachable("how can this be ?");
    }
    return NULL;
}

Value* capchk::get_global_def(Value* val)
{
    ValueSet visited;
    return get_global_def(val, visited);
}

bool capchk::is_rw_global(Value* val)
{
    ValueSet visited;
    return get_global_def(val, visited)!=NULL;
}


/*
 * user can trace back to function argument?
 * only support simple wrapper
 * return the cap parameter position in parameter list
 * return -1 for not found
 */
int capchk::use_parent_func_arg(Value* v, Function* f)
{
    int cnt = 0;
    for (auto a = f->arg_begin(), b = f->arg_end(); a!=b; ++a)
    {
        if (dyn_cast<Value>(a)==v)
            return cnt;
        cnt++;
    }
    return -1;
}
/*
 * is this functions part of the kernel init sequence?
 * if function f has single user which goes to start_kernel(),
 * then this is a init function
 */
bool capchk::is_kernel_init_functions(Function* f, FunctionSet& visited)
{
    if (kernel_init_functions.count(f)!=0)
        return true;
    if (non_kernel_init_functions.count(f)!=0)
        return false;

    //init functions with initcall prefix belongs to kernel init sequence
    if (function_has_gv_initcall_use(f))
    {
        kernel_init_functions.insert(f);
        return true;
    }

    //not found in cache?
    //all path that can reach to f should start from start_kernel()
    //look backward(find who used f)
    FunctionList flist;
    for (auto *U : f->users())
        if (CallInst* cs = dyn_cast<CallInst>(U))
            flist.push_back(cs->getFunction());

    //no user?
    if (flist.size()==0)
    {
        non_kernel_init_functions.insert(f);
        return false;
    }

    visited.insert(f);
    while (flist.size())
    {
        Function* xf = flist.front();
        flist.pop_front();
        if (visited.count(xf))
            continue;
        visited.insert(xf);
        if (!is_kernel_init_functions(xf, visited))
        {
            non_kernel_init_functions.insert(f);
            return false;
        }
    }
    kernel_init_functions.insert(f);
    return true;
}

bool capchk::is_kernel_init_functions(Function* f)
{
    FunctionSet visited;
    return is_kernel_init_functions(f, visited);
}

void capchk::collect_kernel_init_functions(Module& module)
{
    //kstart is the first function in boot sequence
    Function *kstart = NULL;
    //kernel init functions
    FunctionSet kinit_funcs;
    //Step 1: find kernel entry point
    errs()<<"Finding Kernel Entry Point and all __initcall_\n";
    STOP_WATCH_START(WID_KINIT);
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
            continue;
        StringRef fname = func->getName();
        if (fname.startswith("x86_64_start_kernel"))
        {
            errs()<<ANSI_COLOR_GREEN
                <<"Found "<<func->getName()
                <<ANSI_COLOR_RESET<<"\n";
            kstart = func;
            kinit_funcs.insert(kstart);
            kernel_init_functions.insert(func);
        }else if (fname.startswith("start_kernel"))
        {
            //we should consider start_kernel as kernel init functions no
            //matter what
            kernel_init_functions.insert(func);
            kinit_funcs.insert(func);
            //everything calling start_kernel should be considered init
            //for (auto *U: func->users())
            //    if (Instruction *I = dyn_cast<Instruction>(U))
            //        kinit_funcs.insert(I->getFunction());
        }else
        {
            if (function_has_gv_initcall_use(func))
                kernel_init_functions.insert(func);
        }
    }
    //should always find kstart
    assert(kstart!=NULL);
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);

    errs()<<"Initial Kernel Init Function Count:"<<kernel_init_functions.size()<<"\n";

    //Step 2: over approximate kernel init functions
    errs()<<"Over Approximate Kernel Init Functions\n";
    STOP_WATCH_START(WID_KINIT);
    FunctionSet func_visited;
    FunctionSet func_work_set;
    for (auto f: kernel_init_functions)
        func_work_set.insert(f);

    while (func_work_set.size())
    {
        Function* cfunc = *func_work_set.begin();
        func_work_set.erase(cfunc);

        if (cfunc->isDeclaration() || cfunc->isIntrinsic() || is_syscall(cfunc))
            continue;
        
        kinit_funcs.insert(cfunc);
        func_visited.insert(cfunc);
        kernel_init_functions.insert(cfunc);

        //explore call graph starting from this function
        for(Function::iterator fi = cfunc->begin(), fe = cfunc->end(); fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                CallInst* ci = dyn_cast<CallInst>(ii);
                if ((!ci) || (ci->isInlineAsm()))
                    continue;
                if (Function* nf = get_callee_function_direct(ci))
                {
                    if (nf->isDeclaration() || nf->isIntrinsic() ||
                        func_visited.count(nf) || is_syscall(nf))
                        continue;
                    func_work_set.insert(nf);
                }else
                {
#if 0
                    //indirect call?
                    FunctionSet fs = resolve_indirect_callee(ci);
                    errs()<<"Indirect Call in kernel init seq: @ ";
                    ci->getDebugLoc().print(errs());
                    errs()<<"\n";
                    for (auto callee: fs)
                    {
                        errs()<<"    "<<callee->getName()<<"\n";
                        if (!func_visited.count(callee))
                            func_work_set.insert(callee);
                    }
#endif
                }
            }
        }
    }
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);

    errs()<<"Refine Result\n";
    STOP_WATCH_START(WID_KINIT);
    /*
     * ! BUG: query use of inlined function result in in-accurate result?
     * inlined foo();
     * bar(){zoo()} zoo(){foo};
     *
     * query user{foo()} -> zoo()
     * query BasicBlocks in bar -> got call instruction in bar()?
     */
    //remove all non_kernel_init_functions from kernel_init_functions
    //purge all over approximation
    int last_count = 0;

again:
    for (auto f: kinit_funcs)
    {
        if ((f->getName()=="start_kernel") ||
            (f->getName()=="x86_64_start_kernel") ||
            function_has_gv_initcall_use(f))
            continue;
        for (auto *U: f->users())
        {
            if (!isa<Instruction>(U))
                continue;
            if (kinit_funcs.count(dyn_cast<Instruction>(U)->getFunction())==0)
            {
                //means that we have a user does not belong to kernel init functions
                //we need to remove it
                non_kernel_init_functions.insert(f);
                break;
            }
        }
    }
    for (auto f: non_kernel_init_functions)
    {
        kernel_init_functions.erase(f);
        kinit_funcs.erase(f);
    }

    if (last_count!=non_kernel_init_functions.size())
    {
        last_count = non_kernel_init_functions.size();
        static int refine_pass = 0;
        errs()<<"refine pass "<<refine_pass<<" "<<kernel_init_functions.size()<<" left\n";
        refine_pass++;
        goto again;
    }

    errs()<<" Refine result : count="<<kernel_init_functions.size()<<"\n";
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);


#if 1
//this is imprecise, clear it
    //errs()<<"clear NON-kernel-init functions\n";
    //non_kernel_init_functions.clear();
#endif
    dump_kinit();
}

////////////////////////////////////////////////////////////////////////////////

FunctionSet capchk::resolve_indirect_callee(CallInst* ci)
{
    FunctionSet fs;
    if (ci->isInlineAsm())
        return fs;
    if (Function* callee = ci->getCalledFunction())
    {
        //not indirect call
        fs.insert(callee);
        return fs;
    }
    Value* cv = ci->getCalledValue();
    if (Function* callee = dyn_cast<Function>(cv->stripPointerCasts()))
    {
        fs.insert(callee);
        return fs;
    }
    //FUZZY MATCHING
    //method 1: signature based matching
    //only allow precise match when collecting protected functions
    if (!knob_capchk_cvf)
    {
        Type *ft = cv->getType()->getPointerElementType();
        if (!is_complex_type(ft))
        {
            return fs;
        }
        std::set<Function*> *fl = t2fs[ft];
        if (fl==NULL)
            return fs;
        for (auto* f: *fl)
        {
            fs.insert(f);
        }
    }else
    {
    //method 2: use svf to figure out
        if (FunctionSet* _fs = idcs2callee[ci])
            for (auto* f: *_fs)
                fs.insert(f);
    }
    return fs;
}

void capchk::collect_chkps(Module& module)
{
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration() || func->isIntrinsic()
                ||is_function_chk_or_wrapper(func))
            continue;
        
        InstructionSet *chks = f2chks[func];
        if (!chks)
        {
            chks = new InstructionSet();
            f2chks[func] = chks;
        }

        for(Function::iterator fi = func->begin(), fe = func->end(); fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                if (CallInst* ci = dyn_cast<CallInst>(ii))
                    if (Function* _f = get_callee_function_direct(ci))
                    {
                        if (is_function_chk_or_wrapper(_f))
                            chks->insert(ci);
                    }
            }
        }
    }
}

/*
 * track user of functions which have checks, and see whether it is tied
 * to any interesting type(struct)
 */
Value* find_struct_use(Value* f, ValueSet& visited)
{
    if (visited.count(f))
        return NULL;
    visited.insert(f);
    for (auto* u: f->users())
    {
        if (u->getType()->isStructTy())
            return u;
        if (Value*_u = find_struct_use(u, visited))
            return _u;
    }
}


void capchk::identify_interesting_struct(Module& module)
{
    for(auto& pair: f2chks)
    {
        ValueSet visited;
        Function* f = pair.first;
        InstructionSet* chkins = pair.second;
        if (chkins->size()==0)
            continue;
        if (Value* u = find_struct_use(f, visited))
        {
            Type* type = u->getType();
            //should always skip this
            if (type->getStructName().startswith("struct.kernel_symbol"))
                continue;
            bool already_exists = is_interesting_type(type);
            errs()<<"Function: "<<f->getName()
                <<" used by ";
            if (!already_exists)
                errs()<<ANSI_COLOR_GREEN<<" new discover:";
            if (type->getStructName().size()==0)
                errs()<<ANSI_COLOR_RED<<"Annonymouse Type";
            else
                errs()<<type->getStructName();
            errs()<<ANSI_COLOR_RESET<<"\n";
            discovered_interesting_type.insert(type);
        }
    }
}

void capchk::collect_wrappers(Module& module)
{
    //add capable and ns_capable to chk_func_cap_position so that we can use them
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        StringRef fname = func->getName();
        if (fname=="capable")
        {
            chk_func_cap_position[func] = 0;
        }else if (fname=="ns_capable")
        {
            chk_func_cap_position[func] = 1;
        }
        if (chk_func_cap_position.size()==2)
            break;//we are done here
    }

    //last time discovered functions
    FunctionData pass_data;
    //functions that will be used for discovery next time
    FunctionData pass_data_next;

    for (auto fpair: chk_func_cap_position)
        pass_data[fpair.first] = fpair.second;
again:
    for (auto fpair: pass_data)
    {
        Function * func = fpair.first;
        int cap_pos = fpair.second;
        assert(cap_pos>=0);
        //we got a capability check function or a wrapper function,
        //find all use without Constant Value and add them to wrapper
        for (auto U: func->users())
        {
            CallInst* cs = dyn_cast<CallInst>(U);
            if (cs==NULL)
                continue;//how come?
            assert(cs->getCalledFunction()==func);
            Value* capv = cs->getArgOperand(cap_pos);
            if (isa<ConstantInt>(capv))
                continue;
            Function* parent_func = cs->getFunction();
            //we have a wrapper,
            int pos = use_parent_func_arg(capv, parent_func);
            if (pos>=0)
            {
                //type 1 wrapper, cap is from parent function argument
                pass_data_next[parent_func] = pos;
            }else
            {
                //type 2 wrapper, cap is from inside this function
                //what to do with this?
                llvm_unreachable("What??");
            }
        }
    }
    //put pass_data_next in pass_data and chk_func_cap_position
    pass_data.clear();
    for (auto fpair: pass_data_next)
    {
        Function *f = fpair.first;
        int pos = fpair.second;
        if (chk_func_cap_position.count(f)==0)
        {
            pass_data[f] = pos;
            chk_func_cap_position[f] = pos;
        }
    }
    //do this until we discovered everything
    if (pass_data.size())
        goto again;
    
    dump_chk_and_wrap();
}

void capchk::collect_pp(Module& module)
{
    errs()<<"Collect all functions and indirect callsites\n";
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration())
        {
            ExternalFuncCounter++;
            continue;
        }
        if (func->isIntrinsic())
            continue;

        FuncCounter++;

        all_functions.insert(func);
        Type* type = func->getFunctionType();
        FunctionSet *fl = t2fs[type];
        if (fl==NULL)
        {
            fl = new FunctionSet;
            t2fs[type] = fl;
        }
        fl->insert(func);
        
        if (is_syscall_prefix(func->getName()))
            syscall_list.insert(func);

        for(Function::iterator fi = func->begin(), fe = func->end();
                fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                CallInst* ci = dyn_cast<CallInst>(ii);
                if (!ci || ci->getCalledFunction() || ci->isInlineAsm())
                    continue;
                
                Value* cv = ci->getCalledValue();
                Function *bcf = dyn_cast<Function>(cv->stripPointerCasts());
                if (bcf)
                {
                    //this is actually a direct call with function type cast
                    InstructionSet* csis = f2csi_type0[bcf];
                    if (csis==NULL)
                    {
                        csis = new InstructionSet;
                        f2csi_type0[bcf] = csis;
                    }
                    csis->insert(ci);
                    continue;
                }
                idcs.insert(ci);
            }
        }
    }
}

void capchk::collect_crits(Module& module)
{
    STOP_WATCH_START(WID_CC);
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration() || func->isIntrinsic()
                || is_function_chk_or_wrapper(func))
            continue;

        dbgstk.push_back(func->getEntryBlock().getFirstNonPHI());
        InstructionList callgraph;
        InstructionList chks;
        forward_all_interesting_usage(func->getEntryBlock().getFirstNonPHI(),
               0, false, callgraph, chks);
        dbgstk.pop_back();
    }

    STOP_WATCH_STOP(WID_CC);
    STOP_WATCH_REPORT(WID_CC);

    CRITFUNC = critical_functions.size();
    CRITVAR = critical_variables.size();
}

/*
 * discover checks inside functions f, including checks inside other callee
 */
InstructionSet& capchk::discover_chks(Function* f, FunctionSet& visited)
{
    InstructionSet* ret;
    if (visited.count(f))
        return *f2chks_disc[f];
    visited.insert(f);

    ret = new InstructionSet;
    f2chks_disc[f] = ret;

    //any direct check
    if (InstructionSet* chks = f2chks[f])
        for (auto *i: *chks)
            ret->insert(i);

    //indirect check
    for(Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi)
    {
        BasicBlock* bb = dyn_cast<BasicBlock>(fi);
        for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
        {
            CallInst* ci = dyn_cast<CallInst>(ii);
            if (!ci)
                continue;
            if (ci->isInlineAsm())
                continue;

            Function *nextf = get_callee_function_direct(ci);
            if (!nextf)//ignore all indirect call
                continue;
            InstructionSet r = discover_chks(nextf, visited);
            if (r.size())
                ret->insert(ci);
        }
    }

    return *ret;
}

InstructionSet& capchk::discover_chks(Function* f)
{
    if (f2chks_disc.count(f)!=0)
        return *f2chks_disc[f];

    FunctionSet visited;
    InstructionSet& ret = discover_chks(f, visited);
    return ret;
}

void capchk::backward_slice_build_callgraph(InstructionList &callgraph,
            Instruction* I, FunctionToCheckResult& fvisited, int& good, int& bad, int& ignored)
{
    //we've reached the limit
    if (callgraph.size()>MAX_BACKWD_SLICE_DEPTH)
    {
        BwdAnalysisMaxHit++;
        return;
    }
    Function* f = I->getFunction();
    if (fvisited.find(f)!=fvisited.end())
    {
        switch(fvisited[f])
        {
            case(RFULL):
                good++;
                break;
            case(RNONE):
                bad++;
                break;
            case(RNA):
                break;
            default:
                ignored++;
                break;
        }
        return;
    }
    callgraph.push_back(I);
    //place holder
    fvisited[f] = RNA;
    DominatorTree dt(*f);
    InstructionSet chks;

    if (is_kernel_init_functions(f))
    {
        //kernel init function?
        ignored++;
        dump_as_ignored(callgraph);
        goto ignored_out; 
    }
////////////////////////////////////////////////////////////////////////////////
    /*
     * should consider check inside other Callee used by this function
     * if there's a check inside those function, also consider this function
     * checked
     * for example:
     * ------------------------------------------------------
     * foo()                         | bar()
     * {                             | {
     *   if(bar())                   |    if (capable())
     *   {                           |        return true;
     *       zoo();                  |    return false;
     *   }                           | }
     * }                             |
     *-------------------------------------------------------
     */
    chks = discover_chks(f);
    if (chks.size())
    {
        for (auto* chk: chks)
        {
            if (dt.dominates(chk, I))
            {
                if (knob_dump_good_path)
                {
                    errs()<<ANSI_COLOR(BG_GREEN, FG_BLACK)
                        <<"Hit Check Function:"
                        <<get_callee_function_name(chk)
                        <<" @ ";
                    chk->getDebugLoc().print(errs());
                    errs()<<ANSI_COLOR_RESET<<"\n";
                }
                good++;
                goto good_out;
            }
        }
    }

    if (is_syscall(f))
    {
        //this is syscall and no check, report it as bad
        bad++;
        goto bad_out;
    }
////////////////////////////////////////////////////////////////////////////////
    /*
     * we havn't got a check yet, we need to go to f's user to see
     * if it is checked there
     */
    //Direct CallSite
    for (auto *U: f->users())
    {
        if (CallInst* _ci = dyn_cast<CallInst>(U))
        {
            if (_ci->getCalledFunction()!=f)
            {
                //this should match otherwise it is used as a call back function
                //which is not our interest
                //errs()<<"Function "<<f->getName()<< " used as a callback @ ";
                //_ci->getDebugLoc().print(errs());
                //errs()<<"\n";
                ignored++;
                dump_as_ignored(callgraph);
                continue;
            }
            backward_slice_build_callgraph(callgraph,
                    dyn_cast<Instruction>(U), fvisited, good, bad, ignored);
        }else
        {
            if (!isa<Instruction>(U))
            {
                CFuncUsedByStaticAssign++;
                //must be non-instruction
                if (is_interesting_type(U->getType()))
                {
                    //used as kernel entry point and no check
                    bad++;
                    dump_as_bad(callgraph);
                }else
                {
                    ignored++;
                    dump_as_ignored(callgraph);
                }
            }else
            {
                //other use of current function?
                //llvm_unreachable("what?");
                CFuncUsedByNonCallInst++;
            }
        }
    }
    //Indirect CallSite(also user of current function)
    bs_using_indcs(f, callgraph, fvisited, good, bad, ignored);

//intermediate.. just return.
ignored_out:
    callgraph.pop_back();
    return;

good_out:
    fvisited[f] = RFULL;
    dump_as_good(callgraph);
    callgraph.pop_back();
    return;

bad_out:
    fvisited[f] = RNONE;
    dump_as_bad(callgraph);
    callgraph.pop_back();
    return;
}

void capchk::_backward_slice_reachable_to_chk_function(Instruction* I,
        int& good, int& bad, int& ignored)
{
    InstructionList callgraph;
    //FIXME: should consider function+instruction pair as visited?
    FunctionToCheckResult fvisited;
    return backward_slice_build_callgraph(callgraph, I, fvisited, good, bad, ignored);
}

void capchk::backward_slice_reachable_to_chk_function(Instruction* cs,
        int& good, int& bad, int& ignored)
{
    //collect all path and meet condition
    _backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
}

/*
 * exact match with bitcast
 */
bool capchk::match_cs_using_fptr_method_0(Function* func,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored)
{
    bool ret = false;
    InstructionSet *csis = f2csi_type0[func];

    if (csis==NULL)
    {
        UnMatchCallCriticalFuncPtr++;
        goto end;
    }
    ret = true;
    MatchCallCriticalFuncPtr = csis->size();
    for (auto* csi: *csis)
        backward_slice_build_callgraph(callgraph, csi, visited, good, bad, ignored);

end:
    return ret;
}

/*
 * signature based method to find out indirect callee
 */
bool capchk::match_cs_using_fptr_method_1(Function* func,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored)
{
    //we want exact match to non-trivial function
    int cnt = 0;
    Type* func_type = func->getFunctionType();
    FunctionSet *fl = t2fs[func_type];
    if (!is_complex_type(func_type))
        goto end;
    if ((fl==NULL) || (fl->size()!=1))
        goto end;
    if ((*fl->begin())!=func)
        goto end;
    for (auto* idc: idcs)
    {
        Value* cv = idc->getCalledValue();
        //or strip function pointer can do the trick?
        Function* _func = dyn_cast<Function>(cv->stripPointerCasts());
        if (_func==func)
            continue;

        Type* ft = cv->getType()->getPointerElementType();
        Type* ft2 = cv->stripPointerCasts()->getType()->getPointerElementType();
        if ((func_type == ft) || (func_type == ft2))
        {
            cnt++;
            //errs()<<"Found matched functions for indirectcall:"
            //    <<(*fl->begin())->getName()<<"\n";
            backward_slice_build_callgraph(callgraph, idc, visited, good, bad, ignored);
        }
    }
end:
    MatchCallCriticalFuncPtr+=cnt;
    if (cnt==0)
        UnMatchCallCriticalFuncPtr++;
    return cnt!=0;
}


bool capchk::bs_using_indcs(Function* func,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored)
{
    bool ret;
    ret = match_cs_using_fptr_method_0(func, callgraph, visited, good, bad, ignored);
    //exact match don't need to look further
    if (ret)
        return ret;
    ret = match_cs_using_fptr_method_1(func, callgraph, visited, good, bad, ignored);
    return ret;
}

/*
 * Complex Value Flow Analysis
 * figure out candidate for indirect callee using value flow analysis
 *
 * TODO: refactor method0~2, using following routine to pre-calculate
 * candidate function so that we can make check simpler
 *
 */
void capchk::resolve_all_indirect_callee(Module& module)
{
    //collect all function pointer assignment(fptrassign=source)
    for (Module::iterator mi = module.begin(), me = module.end(); mi != me; ++mi)
    {
        Function *func = dyn_cast<Function>(mi);
        if (func->isDeclaration() || func->isIntrinsic())
            continue;
        for (auto* U: func->users())
        {
            Value* u = dyn_cast<Value>(U);
            if (isa<CallInst>(U))
                continue;
            //not interested in pure bitcast?
            if (Instruction* i = dyn_cast<Instruction>(u))
                fptrassign.insert(i);
        }
    }

    //create svf instance
    CVFA cvfa;
    //initialize, this will take some time
    cvfa.initialize(module);

    //do analysis(idcs=sink)
    //method 1, simple type cast
    for (auto* idc: idcs)
    {
        Value* cv = idc->getCalledValue();

        FunctionSet* funcs = idcs2callee[idc];
        if (funcs==NULL)
        {
            funcs = new FunctionSet;
            idcs2callee[idc] = funcs;
        }
        if (Function* func = dyn_cast<Function>(cv->stripPointerCasts()))
        {
            funcs->insert(func);
            continue;
        }
    }
    //method 2, value flow, track down def-use-chain till we found
    //function pointer assignment
    if (knob_capchk_cvf)
    {
        errs()<<"SVF indirect call track:\n";
        for (auto f: all_functions)
        {
            std::set<const Instruction*> css;
            cvfa.get_indirect_callee_for_func(f, css);
            if (css.size()==0)
                continue;
            errs()<<"FUNC:"<<f->getName()<<", found "<<css.size()<<"\n";
            for (auto* _ci: css)
            {
                const CallInst* ci = dyn_cast<CallInst>(_ci);
                FunctionSet* funcs = idcs2callee[ci];
                if (funcs==NULL)
                {
                    funcs = new FunctionSet;
                    idcs2callee[ci] = funcs;
                }
                funcs->insert(f);
#if 1
                errs()<<"CallSite: ";
                ci->getDebugLoc().print(errs());
                errs()<<"\n";
                ci->print(errs());
                errs()<<"\n";
#endif
            }
        }
    }
}

/*
 * check possible critical function path 
 */
void capchk::check_critical_function_usage(Module& module)
{
    FunctionList processed_flist;
    //for each critical function find out all callsite(use)
    //process one critical function at a time
    for (Module::iterator f_begin = module.begin(), f_end = module.end();
            f_begin != f_end; ++f_begin)
    {
        Function *func = dyn_cast<Function>(f_begin);
        if (!is_critical_function(func))
            continue;
        if (is_skip_function(func->getName()))
            continue;
        errs()<<ANSI_COLOR_YELLOW
            <<"Inspect Use of Function:"
            <<func->getName()
            <<ANSI_COLOR_RESET
            <<"\n";
        //iterate through all call site
        //direct call
        int good=0, bad=0, ignored=0;
        for (auto *U: func->users())
        {
            CallInst *cs = dyn_cast<CallInst>(U);
            if (!cs)
                continue;
            backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
        }
        //summary
        if (bad!=0)
        {
            errs()<<ANSI_COLOR_GREEN<<"Good: "<<good<<" "
                  <<ANSI_COLOR_RED<<"Bad: "<<bad<<" "
                  <<ANSI_COLOR_YELLOW<<"Ignored: "<<ignored
                  <<ANSI_COLOR_RESET<<"\n";
        }
        BadPath+=bad;
        GoodPath+=good;
    }
}



/*
 * run inter-procedural backward analysis to figure out whether the use of
 * critical variable can be reached from entry point without running check
 */
void capchk::check_critical_variable_usage(Module& module)
{
    for (auto *V: critical_variables)
    {
        FunctionList flist;//known functions
#if DEBUG_ANALYZE
        errs()<<ANSI_COLOR_YELLOW
            <<"Inspect Use of Variable:"
            <<V->getName()
            <<ANSI_COLOR_RESET<<"\n";
#endif

        //figure out all use-def, put them info workset
        InstructionSet workset;
        for (auto* U: V->users())
        {
            Instruction *ui = dyn_cast<Instruction>(U);
            if (!ui)//not an instruction????
            {
                //llvm_unreachable("not an instruction?");
                continue;
            }
            Function* f = ui->getFunction();
            //make sure this is not inside a kernel init function
            if (is_kernel_init_functions(f))
                continue;
            //value flow 
            workset.insert(ui);
        }
        for (auto* U: workset)
        {
            Function*f = U->getFunction();
            errs()<<" @ "<<f->getName()<<" ";
            U->getDebugLoc().print(errs());
            errs()<<"\n";
            flist.push_back(f);

            //is this instruction reachable from non-checked path?
            int good=0, bad=0, ignored=0;
            _backward_slice_reachable_to_chk_function(dyn_cast<Instruction>(U), good, bad, ignored);
            if (bad!=0)
            {
                errs()<<ANSI_COLOR_GREEN<<"Good: "<<good<<" "
                      <<ANSI_COLOR_RED<<"Bad: "<<bad<<" "
                      <<ANSI_COLOR_YELLOW<<"Ignored: "<<ignored
                      <<ANSI_COLOR_RESET<<"\n";
            }
            BadPath+=bad;
            GoodPath+=good;
        }
    }
}

void capchk::crit_func_collect(CallInst* cs, FunctionSet& current_crit_funcs,
        InstructionList& chks)
{
    //ignore inline asm
    if (cs->isInlineAsm())
        return;
    if (Function *csf = get_callee_function_direct(cs))
    {
        if (csf->isIntrinsic()
                ||is_skip_function(csf->getName())
                ||is_function_chk_or_wrapper(csf))
            return;
        current_crit_funcs.insert(csf);

        if (knob_capchk_ccfv)
        {
            errs()<<"Add call<direct> "<<csf->getName()<<" use @ ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n cause:";
            dump_dbgstk();
        }

        InstructionSet* ill = f2ci[csf];
        if (ill==NULL)
        {
            ill = new InstructionSet;
            f2ci[csf] = ill;
        }
        for (auto chki: chks)
            ill->insert(chki);

    }else if (Value* csv = cs->getCalledValue())
    {
        errs()<<"Want to resolve indirect call @ ";
        cs->getDebugLoc().print(errs());
        errs()<<"\n";

        FunctionSet fs = resolve_indirect_callee(cs);
        if (!fs.size())
        {
            CPUnResolv++;
            return;
        }
        CPResolv++;
        Function* csf = *fs.begin();
#if 1
        if (csf->isIntrinsic()
                ||is_skip_function(csf->getName())
                ||is_function_chk_or_wrapper(csf))
            return;

        current_crit_funcs.insert(csf);
        if (knob_capchk_ccfv)
        {
            errs()<<"Add call<indirect> "<<csf->getName()<<" use @ ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n cause:";
            dump_dbgstk();
        }
        InstructionSet* ill = f2ci[csf];
        if (ill==NULL)
        {
            ill = new InstructionSet;
            f2ci[csf] = ill;
        }
        //insert all chks?
        for (auto chki: chks)
            ill->insert(chki);
#endif
    }
}

void capchk::crit_vars_collect(Instruction* ii, ValueList& current_critical_variables,
        InstructionList& chks)
{
    Value* gv = get_global_def(ii);
    if (gv && (!isa<Function>(gv)) && (!is_skip_var(gv->getName())))
    {
        if (knob_capchk_ccvv)
        {
            errs()<<"Add "<<gv->getName()<<" use @ ";
            ii->getDebugLoc().print(errs());
            errs()<<"\n cause:";
            dump_dbgstk();
        }
        current_critical_variables.push_back(gv);
        InstructionSet* ill = v2ci[gv];
        if (ill==NULL)
        {
            ill = new InstructionSet;
            v2ci[gv] = ill;
        }
        for (auto chki: chks)
            ill->insert(chki);
    }
}

/*
 * IPA: figure out all global variable usage and function calls
 * FIXME: SVF, global var, should build whold call graph first,
 * TODO : (after collecting all critical functions),
 *        partation the kernel and run svf then do alias analysis
 *        to figure mod/ref set
 * 
 * @I: from where are we starting, all following instructions should be dominated
 *     by I, if checked=true
 * @depth: are we going to deep?
 * @checked: is this function already checked? means that `I' will dominate all,
 *     means that the caller of current function have already been dominated by
 *     a check
 * @callgraph: how to we get here
 * @chks: which checks are protecting us?
 */
void capchk::forward_all_interesting_usage(Instruction* I, int depth,
        bool checked, InstructionList& callgraph,
        InstructionList& chks)
{
    Function *func = I->getFunction();
    DominatorTree dt(*func);

    bool is_function_permission_checked = checked;
    /*
     * collect interesting variables/functions found in this function
     */
    FunctionSet current_crit_funcs;
    ValueList current_critical_variables;

    //don't allow recursive
    if (std::find(callgraph.begin(), callgraph.end(), I)!=callgraph.end())
        return;

    callgraph.push_back(I);

    if (depth>MAX_FWD_SLICE_DEPTH)
    {
        callgraph.pop_back();
        FwdAnalysisMaxHit++;
        return;
    }

    BasicBlockSet bb_visited;
    BasicBlockList bb_work_list;

    /*
     * a list of instruction where check functions are used,
     * that will be later used to do dominance checking
     */
    InstructionList chk_instruction_list;

/*****************************
 * first figure out all checks
 */
    //already checked?
    if (is_function_permission_checked)
        goto rescan_and_add_all;

    bb_work_list.push_back(I->getParent());
    while(bb_work_list.size())
    {
        BasicBlock* bb = bb_work_list.front();
        bb_work_list.pop_front();
        if(bb_visited.count(bb))
            continue;
        bb_visited.insert(bb);

        for (BasicBlock::iterator ii = bb->begin(),
                ie = bb->end();
                ii!=ie; ++ii)
        {
            if (isa<CallInst>(ii))
            {
                //only interested in call site
                CallInst *ci = dyn_cast<CallInst>(ii);
                if (Function* csfunc = get_callee_function_direct(ci))
                {
                    if (is_function_chk_or_wrapper(csfunc))
                    {
                        is_function_permission_checked = true;
                        chk_instruction_list.push_back(ci);
                        chks.push_back(ci);
                    }
                }else if (!ci->isInlineAsm())
                {
                    //don't really care inline asm
                    //FIXME:this is in-direct call, could there be a check inside
                    //indirect call we are missing?
                }
            }
        }
        //insert all successor of current basic block to work list
        for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si!=se; ++si)
            bb_work_list.push_back(cast<BasicBlock>(*si));
    }

    if (!is_function_permission_checked)
        goto out;

/*******************************************************************
 * second, re-scan all instructions and figure out 
 * which one can be dominated by those check instructions(protected)
 */
rescan_and_add_all:

    for(Function::iterator fi = func->begin(), fe = func->end(); fi != fe; ++fi)
    {
        BasicBlock* bb = dyn_cast<BasicBlock>(fi);
        for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
        {
            Instruction* si = dyn_cast<Instruction>(ii);
            /*
             * if any check dominate si then go ahead and
             * add them to protected list
             */
            //already checked before entering current scope
            //all following usage should be dominated by incoming Instruction
            if (checked)
            {
                //should dominate use
                if (dt.dominates(I,si))
                    goto add;
            }
            //or should have newly discovered check.. and 
            //there should be at least one check dominate the use
            for (auto* _ci : chk_instruction_list)
                if (dt.dominates(_ci,si))
                    goto add;
            //dont care if not protected
            continue;

add:
            if (CallInst* cs = dyn_cast<CallInst>(ii))
            {
                crit_func_collect(cs, current_crit_funcs, chks);
                //continue;
                //need to look at argument
            }
            crit_vars_collect(si, current_critical_variables, chks);
        }
    }
    /**********
     * merge 
     */
    if (is_function_permission_checked)
    {
        //merge forwar slicing result
        for (auto i: current_crit_funcs)
            critical_functions.insert(i);
        for(auto v: current_critical_variables)
            critical_variables.insert(v);

        //if functions is permission checked, we need to 
        //and we need to check all use of this function
        for (auto *U: func->users())
        {
            if (CallInst* cs = dyn_cast<CallInst>(U))
            {
                Function* pfunc = cs->getFunction();
                if (pfunc->isIntrinsic())
                    continue;
                if (is_kernel_init_functions(pfunc))
                {
                    if (knob_warn_capchk_during_kinit)
                    {
                        dbgstk.push_back(cs);
                        errs()<<ANSI_COLOR_YELLOW
                            <<"capability check used during kernel initialization\n"
                            <<ANSI_COLOR_RESET;
                        dump_dbgstk();
                        dbgstk.pop_back();
                    }
                    continue;
                }

                dbgstk.push_back(cs);
                forward_all_interesting_usage(cs, depth+1, true, callgraph, chks);
                dbgstk.pop_back();
            }
        }
    }
out:
    callgraph.pop_back();
    return;
}

void capchk::my_debug(Module& module)
{
#if 0
    Function* f;
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration() || func->isIntrinsic())
            continue;
        if (func->hasName())
        {
            StringRef fname = func->getName();
            if (fname=="mix_pool_bytes")
            {
                f = func;
                break;
            }
        }
    }
    for (auto* u: f->users())
    {
        if (Instruction*i = dyn_cast<Instruction>(u))
        {
            Function* xf = i->getFunction();
            errs()<<xf->getName()<<"\n";
        }
    }
#else
    for(GlobalVariable &gvi: module.globals())
    {
        GlobalVariable* gi = &gvi;
        if (gi->isDeclaration())
            continue;
        if (!isa<Value>(gi))
            continue;
        Value* gv = dyn_cast<Value>(gi);
        StringRef gvname = gv->getName();
        if (gvname.startswith("llvm."))
            continue;
        bool gv_use_func = false;
        if (!gi->hasInitializer())
            continue;
        errs()<<"GV:"<<gvname<<"\n";
    }
#endif
    exit(0);
}

/*
 * process capability protected globals and functions
 */
void capchk::process_cpgf(Module& module)
{
    //my_debug(module);
    /*
     * pre-process
     * generate resource/functions from syscall entry function
     */
    errs()<<"Pre-processing...\n";
    load_skip_func_list(knob_skip_func_list);
    load_skip_var_list(knob_skip_var_list);
    STOP_WATCH_START(WID_0);
    collect_pp(module);
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);

    errs()<<"Identify wrappers\n";
    STOP_WATCH_START(WID_0);
    collect_wrappers(module);
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);

    errs()<<"Collect Checkpoints\n";
    STOP_WATCH_START(WID_0);
    collect_chkps(module);
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);

    errs()<<"Identify interesting struct\n";
    STOP_WATCH_START(WID_0);
    identify_interesting_struct(module);
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);

    if (knob_capchk_cvf)
    {
        errs()<<"Resolving callee for indirect call.\n";
        STOP_WATCH_START(WID_0);
        resolve_all_indirect_callee(module);
        STOP_WATCH_STOP(WID_0);
        STOP_WATCH_REPORT(WID_0);
    }

    errs()<<"Collecting Initialization Closure.\n";
    STOP_WATCH_START(WID_0);
    collect_kernel_init_functions(module);
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);

    errs()<<"Collect all permission-checked variables and functions\n";
    STOP_WATCH_START(WID_0);
    collect_crits(module);
    errs()<<"Collected "<<critical_functions.size()<<" critical functions\n";
    errs()<<"Collected "<<critical_variables.size()<<" critical variables\n";

    dump_v2ci();
    dump_f2ci();

    errs()<<"Run Analysis\n";

    if (knob_capchk_critical_var)
    {
        errs()<<"Critical variables\n";
        STOP_WATCH_START(WID_0);
        check_critical_variable_usage(module);
        STOP_WATCH_STOP(WID_0);
        STOP_WATCH_REPORT(WID_0);
    }
    if (knob_capchk_critical_fun)
    {
        errs()<<"Critical functions\n";
        STOP_WATCH_START(WID_0);
        check_critical_function_usage(module);
        STOP_WATCH_STOP(WID_0);
        STOP_WATCH_REPORT(WID_0);
    }
    dump_non_kinit();
}

bool capchk::runOnModule(Module &module)
{
    m = &module;
    return capchkPass(module);
}

bool capchk::capchkPass(Module &module)
{
    errs()<<ANSI_COLOR_CYAN
        <<"--- PROCESS FUNCTIONS ---"
        <<ANSI_COLOR_RESET<<"\n";
    process_cpgf(module);
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

