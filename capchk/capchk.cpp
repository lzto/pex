/*
 * CapChecker
 * linux kernel capability checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "capchk.h"

#include "cvfa.h"
//my aux headers
#include "color.h"
#include "internal.h"
#include "stopwatch.h"
#include "utility.h"

#define TOTOAL_NUMBER_OF_STOP_WATCHES 2
#define WID_0 0
#define WID_KINIT 1
#define WID_CC 1
#define WID_PI 1

STOP_WATCH(TOTOAL_NUMBER_OF_STOP_WATCHES);

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
STATISTIC(CPUnResolv, "Critical Function Pointer Unable to Resolve, Collect Pass");
STATISTIC(CPResolv, "Critical Function Pointer Resolved, Collect Pass");
STATISTIC(CFuncUsedByNonCallInst, "Critical Functions used by non CallInst");
STATISTIC(CFuncUsedByStaticAssign, "Critical Functions used by static assignment");
STATISTIC(MatchCallCriticalFuncPtr, "# of times indirect call site matched with critical functions");
STATISTIC(UnMatchCallCriticalFuncPtr, "# of times indirect call site failed to match with critical functions");
STATISTIC(CapChkInFPTR, "found capability check inside call using function ptr\n");

////////////////////////////////////////////////////////////////////////////////
//map function to its check instruction
Function2ChkInst f2ci;
Value2ChkInst v2ci;
Type2ChkInst t2ci;

//t2fs is used to fuzzy matching calling using function pointer
TypeToFunctions t2fs;

//map function to check instructions inside that function
//only include direct check
Function2ChkInst f2chks;
//discovered check inside functions, including other callee
//which will call the check, which is the super set of f2chks
Function2ChkInst f2chks_disc;

//all function pointer assignment,(part of function use)
//InstructionSet fptrassign;

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
cl::opt<std::string> knob_gating_type("gating",
        cl::desc("gating function: cap/lsm - default: cap"),
        cl::init("cap"));

cl::opt<bool> knob_capchk_critical_var("ccv",
        cl::desc("check critical variable usage - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_critical_fun("ccf",
        cl::desc("check critical function usage - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_critical_type_field("cct",
        cl::desc("check critical type field usage - disable by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_ccfv("ccfv",
        cl::desc("print path to critical function(collect phase) - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_ccvv("ccvv",
        cl::desc("print path to critical variable(collect phase) - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_cctv("cctv",
        cl::desc("print path to critical type field(collect phase) - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_capchk_f2c("f2c",
        cl::desc("print critical function to gating function mapping - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_v2c("v2c",
        cl::desc("print critical variable to gating function mapping - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_capchk_t2c("t2c",
        cl::desc("print critical type field to gating function mapping - enable by default"),
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

cl::opt<string> knob_lsm_function_list("lsmhook",
        cl::desc("lsm hook function name list"),
        cl::init("lsm.hook"));

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

cl::opt<unsigned int> knob_fwd_depth("fwd-depth",
        cl::desc("forward search max depth - default 100"),
        cl::init(100));

cl::opt<unsigned int> knob_bwd_depth("bwd-depth",
        cl::desc("backward search max depth - default 100"),
        cl::init(100));

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
 * all critical functions and variables should be permission checked before use
 * generate critical functions on-the-fly
 *
 * critical_functions: direct call's callee
 * critical_variables: global variables
 * critical_ftype: interesting type(struct) and fields that should be checked before use
 *      type, field sensitive
 */
FunctionSet critical_functions;
ValueSet critical_variables;
Type2Fields critical_typefields;

bool is_critical_function(Function* f)
{
    return critical_functions.count(f)!=0;
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

bool _is_used_by_static_assign_to_interesting_type(Value* v,
        std::unordered_set<Value*>& duchain)
{
    if (duchain.count(v))
        return false;
    duchain.insert(v);
    if (is_interesting_type(v->getType()))
    {
        duchain.erase(v);
        return true;
    }
    for (auto *u: v->users())
    {
        if (isa<Instruction>(u))
            continue;
        if (_is_used_by_static_assign_to_interesting_type(u, duchain))
        {
            duchain.erase(v);
            return true;
        }
    }
    duchain.erase(v);
    return false;
}

bool is_used_by_static_assign_to_interesting_type(Value* v)
{
    std::unordered_set<Value*> duchain;
    return _is_used_by_static_assign_to_interesting_type(v, duchain);
}

bool is_syscall_prefix(StringRef str)
{
    for (int i=0;i<4;i++)
        if (str.startswith(_builtin_syscall_prefix[i]))
            return true;
    return false;
}

bool is_syscall(Function *f)
{
    return syscall_list.count(f)!=0;
}

bool is_skip_struct(StringRef str)
{
    for (int i=0;i<BUILDIN_STRUCT_TO_SKIP;i++)
        if (str.startswith(_builtin_struct_to_skip[i]))
            return true;
    return false;
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
        <<"--- Variables Protected By Gating Function---"
        <<ANSI_COLOR_RESET<<"\n";
    for (auto& cis: v2ci)
    {
        Value* v = cis.first;
        errs()<<ANSI_COLOR_GREEN<<v->getName()<<ANSI_COLOR_RESET<<"\n";
        gating->dump_interesting(cis.second);
    }
}

void capchk::dump_f2ci()
{
    if (!knob_capchk_f2c)
        return;
    errs()<<ANSI_COLOR(BG_BLUE,FG_WHITE)
        <<"--- Function Protected By Gating Function---"
        <<ANSI_COLOR_RESET<<"\n";
    for (auto& cis: f2ci)
    {
        Function* func = cis.first;
        errs()<<ANSI_COLOR_GREEN<<func->getName()<<ANSI_COLOR_RESET<<"\n";
        gating->dump_interesting(cis.second);
    }
}

/*
 * dump interesting type field and guarding checks
 */
void capchk::dump_tf2ci()
{
    if (!knob_capchk_t2c)
        return;

    errs()<<ANSI_COLOR(BG_CYAN, FG_WHITE)
        <<"--- Interesting Type fields and checks ---"
        <<ANSI_COLOR_RESET<<"\n";
#if 0
    for (auto v: critical_typefields)
    {
        StructType* t = dyn_cast<StructType>(v.first);
        std::set<int>& fields = v.second;
        if (t->hasName())
            errs()<<t->getName();
        else
            errs()<<"AnnonymouseType";
        errs()<<":";
        for (auto i: fields)
            errs()<<i<<",";
        errs()<<"\n";
    }
#else
    for(auto& cis: t2ci)
    {
        StructType* t = dyn_cast<StructType>(cis.first);
        if (t->hasName())
            errs()<<ANSI_COLOR_GREEN<<t->getName();
        else
            errs()<<ANSI_COLOR_RED<<"AnnonymouseType";
        errs()<<":";
        std::unordered_set<int>& fields = critical_typefields[t];
        for (auto i: fields)
            errs()<<i<<",";
        errs()<<ANSI_COLOR_RESET<<"\n";
        gating->dump_interesting(cis.second);
    }
#endif
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

void capchk::dump_gating()
{
    if (!knob_capchk_caw)
        return;
    gating->dump();
}

void capchk::dump_scope(FunctionSet& scope)
{
    errs()<<" scope("<<scope.size()<<"): ";
    for(auto *f: scope)
    {
        errs()<<f->getName()<<",";
    }
    errs()<<"\n";
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
    for (int i = 0; i<(int)ft->getNumParams(); i++)
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
    }/*else if (Value* valv = dyn_cast<Value>(val))
    {
        //llvm_unreachable("how can this be ?");
    }*/
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
            if (kstart==NULL)
                kstart = func;
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
    if (kstart==NULL)
    {
        errs()<<ANSI_COLOR_RED
            <<"kstart function not found, may affect precission, continue anyway\n"
            <<ANSI_COLOR_RESET;
    }
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

    if (last_count!=(int)non_kernel_init_functions.size())
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
//resolve indirect callee
FunctionSet capchk::resolve_indirect_callee(CallInst* ci)
{
    FunctionSet fs;
    if (ci->isInlineAsm())
        return fs;
    if (Function* callee = get_callee_function_direct(ci))
    {
        //not indirect call
        fs.insert(callee);
        return fs;
    }
    //FUZZY MATCHING
    //method 1: signature based matching
    //only allow precise match when collecting protected functions
    if (!knob_capchk_cvf)
    {
        Value* cv = ci->getCalledValue();
        Type *ft = cv->getType()->getPointerElementType();
        if (!is_complex_type(ft))
            return fs;
        if (t2fs.find(ft)==t2fs.end())
            return fs;
        FunctionSet *fl = t2fs[ft];
        for (auto* f: *fl)
            fs.insert(f);
    }else
    {
    //method 2: use svf to figure out
        auto _fs = idcs2callee.find(ci);
        if (_fs != idcs2callee.end())
        {
            for (auto* f: *(_fs->second))
                fs.insert(f);
        }
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
                ||gating->is_gating_function(func))
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
                        if (gating->is_gating_function(_f))
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
    return NULL;
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
            StructType* type = dyn_cast<StructType>(u->getType());
            if (!type->hasName())
                continue;
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
                || gating->is_gating_function(func))
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
    if (callgraph.size()>knob_bwd_depth)
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
                if (is_used_by_static_assign_to_interesting_type(U))
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
    MatchCallCriticalFuncPtr += csis->size();
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

/*
 * get result from value flow analysis result
 */
bool capchk::match_cs_using_cvf(Function* func,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored)
{
    //TODO: optimize this
    int cnt = 0;
    for (auto* idc: idcs)
    {
        auto fs = idcs2callee.find(idc);
        if(fs==idcs2callee.end())
            continue;
        for (auto* f: *(fs->second))
        {
            if (f!=func)
                continue;
            cnt++;
            backward_slice_build_callgraph(callgraph, idc, visited, good, bad, ignored);
            break;
        }
    }
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

    if (!knob_capchk_cvf)
    {
        ret = match_cs_using_fptr_method_0(func, callgraph, visited, good, bad, ignored);
        //exact match don't need to look further
        if (ret)
            return ret;
        ret = match_cs_using_fptr_method_1(func, callgraph, visited, good, bad, ignored);
        return ret;
    }
    return match_cs_using_cvf(func, callgraph, visited, good, bad, ignored);
}

/*
 * Complex Value Flow Analysis
 * figure out candidate for indirect callee using value flow analysis
 */
void capchk::cvf_resolve_all_indirect_callee(Module& module)
{
#if 0
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
#endif

    //create svf instance
    CVFA cvfa;
    //initialize, this will take some time
    cvfa.initialize(module);

    //do analysis(idcs=sink)
    //method 1, simple type cast, they are actually direct call
    for (auto* idc: idcs)
    {
        if (Function* func = get_callee_function_direct(idc))
        {
            FunctionSet* funcs = idcs2callee[idc];
            if (funcs==NULL)
            {
                funcs = new FunctionSet;
                idcs2callee[idc] = funcs;
            }
            funcs->insert(func);
        }
    }
    //method 2, value flow
    //find out all possible value of indirect callee
    errs()<<ANSI_COLOR(BG_WHITE, FG_BLUE)
        <<"SVF indirect call track:"
        <<ANSI_COLOR_RESET<<"\n";
    for (auto f: all_functions)
    {
        ConstInstructionSet css;
        cvfa.get_callee_function_indirect(f, css);
        if (css.size()==0)
            continue;
        errs()<<ANSI_COLOR(BG_CYAN, FG_WHITE)
            <<"FUNC:"<<f->getName()
            <<", found "<<css.size()
            <<ANSI_COLOR_RESET<<"\n";
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
#endif
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
            CallInstSet cil;
            get_callsite_inst(U, cil);
            for (auto cs: cil)
                backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
        }
        //indirect call
        for (auto& callees: idcs2callee)
        {
            CallInst *cs = const_cast<CallInst*>
                            (static_cast<const CallInst*>(callees.first));
            for (auto* f: *callees.second)
                if (f==func)
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
 * collect our scope for value flow analysis
 * first go backward to see if we can reach to interesting point
 * (interesting struct, or syscall)
 * then go forward to collect all def-use chain from current I
 * - I: from where we start working
 * - scope: the result, empty scope means that it is not interesting
 */
void capchk::collect_backward_scope(Instruction* i, FunctionSet& scope,
        InstructionList& callgraph, FunctionSet& visited)
{
    if (callgraph.size()>knob_bwd_depth)
        return;
    Function *f = i->getFunction();
    if (visited.count(f))
        return;
    visited.insert(f);
    //dont care kinit functions
    if (is_kernel_init_functions(f))
        return;
    //reached interesting point
    if (is_syscall(f))
    {
        errs()<<"Add scope because reached syscall\n";
        dump_callstack(callgraph);
        for (auto *I: callgraph)
            scope.insert(I->getFunction());
        return;
    }
    //have other use of this function in callsite?
    for (auto* u: f->users())
    {
        if (CallInst* ci = dyn_cast<CallInst>(u))
        {
            //should call this function
            if (ci->getCalledFunction()!=f)
                continue;
            callgraph.push_back(ci);
            collect_backward_scope(ci, scope, callgraph, visited);
            callgraph.pop_back();
        }else
        {
            if (!isa<Instruction>(u))
                if (is_interesting_type(u->getType()))
                {
                    errs()<<"Add scope because reached interesting use\n";
                    dump_callstack(callgraph);
                    for (auto*I:callgraph)
                        scope.insert(I->getFunction());
                }
        }
    }
}

void capchk::augment_scope(FunctionSet& scope)
{
    FunctionSet workscope;
    FunctionSet newscope;
    for (auto *f: scope)
        workscope.insert(f);
again:
    for(auto* f: workscope)
    {
        for(Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                if (!isa<CallInst>(ii))
                    continue;
                CallInst* ci = dyn_cast<CallInst>(ii);
                Function* f = get_callee_function_direct(ci);
                if (!f)
                {
                    //this is a indirect call, need to resolve this 
                    continue;
                }
                if (!scope.count(f))
                    newscope.insert(f);
            }
        }
    }
    workscope.clear();
    for (auto *f: newscope)
    {
        workscope.insert(f);
        scope.insert(f);
    }
    if (workscope.size())
    {
        newscope.clear();
        goto again;
    }
}

void capchk::collect_scope(Instruction* i, FunctionSet& scope)
{
    InstructionList callgraph;
    FunctionSet visited;
    callgraph.push_back(i);
    collect_backward_scope(i, scope, callgraph, visited);
    callgraph.pop_back();
    //augment_scope(scope);
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
        errs()<<ANSI_COLOR_YELLOW
            <<"Inspect Use of Variable:"
            <<V->getName()
            <<ANSI_COLOR_RESET<<"\n";

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
#if 0
            //TODO: value flow
            //collect our scope, which function can be reached from here
            //go forward and backward
            FunctionSet scope;
            collect_scope(ui, scope);
            //use unable to reach interesting point is discarded
            if (scope.size()==0)
                continue;
            //InstructionList* IL = run_complex_value_flow(scope);
            //for(auto* i:IL)
            //{
            //  workset.insert(i);
            //}
            dump_scope(scope);
#endif
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

void capchk::figure_out_gep_using_type_field(InstructionSet& workset,
        const std::pair<Type*,std::unordered_set<int>>& v, Module& module)
{
    for (Module::iterator f = module.begin(), f_end = module.end();
        f != f_end; ++f)
    {
        if (is_skip_function(dyn_cast<Function>(f)->getName()))
            continue;
        for(Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                if (!isa<GetElementPtrInst>(ii))
                    continue;
                GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(ii);
                /*if (!gep_used_by_call_or_store(gep))
                    continue;*/
                Type* gep_operand_type
                    = dyn_cast<PointerType>(gep->getPointerOperandType())
                        ->getElementType();
                //check type
                if (gep_operand_type==v.first)
                {
                    //check field
                    assert(gep->hasIndices());
                    ConstantInt* cint = dyn_cast<ConstantInt>(gep->idx_begin());
                    if (!cint)
                        continue;
                    int idx = cint->getSExtValue();
                    if (v.second.count(idx))
                        workset.insert(gep);
                }
            }
        }
    }
}

void capchk::check_critical_type_field_usage(Module& module)
{
    for (auto V: critical_typefields)
    {
        StructType* t = dyn_cast<StructType>(V.first);
        //std::set<int>& fields = V.second;

        errs()<<ANSI_COLOR_YELLOW
            <<"Inspect Use of Type:"
            <<t->getStructName()
            <<ANSI_COLOR_RESET<<"\n";

        //figure out all use-def, put them info workset
        InstructionSet workset;
        //figure out where the type is used, and add all of them in workset
        //mainly gep
        figure_out_gep_using_type_field(workset, V, module);

        for (auto* U: workset)
        {
            Function*f = U->getFunction();
            errs()<<" @ "<<f->getName()<<" ";
            U->getDebugLoc().print(errs());
            errs()<<"\n";

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

/*
 * collect critical function calls,
 * callee of direct call is collected directly,
 * callee of indirect call is reasoned by its type or struct
 */
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
                ||gating->is_gating_function(csf))
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

    }//else if (Value* csv = cs->getCalledValue())
    else if (cs->getCalledValue()!=NULL)
    {
        if (knob_capchk_ccfv)
        {
            errs()<<"Resolve indirect call @ ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n";
        }
        //TODO:solve as gep function pointer of struct 
        FunctionSet fs = resolve_indirect_callee(cs);
        if (!fs.size())
        {
            if (knob_capchk_ccfv)
                errs()<<ANSI_COLOR_RED<<"[NO MATCH]"<<ANSI_COLOR_RESET<<"\n";
            CPUnResolv++;
            return;
        }
        if (knob_capchk_ccfv)
            errs()<<ANSI_COLOR_GREEN<<"[FOUND "<<fs.size()<<" MATCH]"<<ANSI_COLOR_RESET<<"\n";
        CPResolv++;
        for (auto* csf: fs)
        {
            if (csf->isIntrinsic() || is_skip_function(csf->getName())
                    ||gating->is_gating_function(csf))
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
        }
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
 * figure whether this instruction is reading/writing any struct field
 * inter-procedural
 */
void capchk::crit_type_field_collect(Instruction* i, Type2Fields& current_t2fmaps,
        InstructionList& chks)
{
    StructType *t = NULL;
    if (LoadInst* li = dyn_cast<LoadInst>(i))
    {
        /*
         * we are expecting that we load a pointer from a struct type
         * which will be like:
         *
         * addr = (may bit cast) gep(struct addr, field)
         * ptr = load(addr)
         */
        //only interested in pointer type
        if (!li->getType()->isPointerTy())
            return;
        Value* addr = li->getPointerOperand()->stripPointerCasts();
        //now we are expecting a gep
        if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(addr))
        {
            //great we got a gep
            //Value* gep_operand = gep->getPointerOperand();
            Type* gep_operand_type
                = dyn_cast<PointerType>(gep->getPointerOperandType())
                    ->getElementType();
            if (!isa<StructType>(gep_operand_type))
                return;
            //FIXME: only handle the first field as of now
            assert(gep->hasIndices());
            if (!(dyn_cast<ConstantInt>(gep->idx_begin())))
            {
                /*errs()<<"gep has no indices @ position 0 ";
                gep->getDebugLoc().print(errs());
                errs()<<"\n";
                gep->print(errs());
                errs()<<"\n";*/
                return;
            }
            //what is the first indice?
            StructType* stype = dyn_cast<StructType>(gep_operand_type);
            if (is_skip_struct(stype->getStructName()))
                return;
            int idx = dyn_cast<ConstantInt>(gep->idx_begin())->getSExtValue();
            current_t2fmaps[gep_operand_type].insert(idx);
            t = stype;
            goto goodret;
        }else
        {
            //what else? maybe phi?
        }
    }else if (StoreInst* si = dyn_cast<StoreInst>(i))
    {
        /*
         * we are expecting that we store a pointer into a struct type
         * which will be like:
         *
         * addr = (may bit cast) gep(struct addr, field)
         * store(interesting_ptr, addr);
         */
        if (!si->getValueOperand()->getType()->isPointerTy())
            return;
        Value* addr = si->getPointerOperand()->stripPointerCasts();
        if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(addr))
        {
            //great we got a gep
            //Value* gep_operand = gep->getPointerOperand();
            Type* gep_operand_type
                = dyn_cast<PointerType>(gep->getPointerOperandType())
                    ->getElementType();
            if (!isa<StructType>(gep_operand_type))
                return;
            //FIXME: only handle the first field as of now
            assert(gep->hasIndices());
            if (!(dyn_cast<ConstantInt>(gep->idx_begin())))
            {
                /*errs()<<"gep has no indices @ position 0 ";
                gep->getDebugLoc().print(errs());
                errs()<<"\n";
                gep->print(errs());
                errs()<<"\n";*/
                return;
            }
            //what is the first indice?
            StructType* stype = dyn_cast<StructType>(gep_operand_type);
            if (is_skip_struct(stype->getStructName()))
                return;

            int idx = dyn_cast<ConstantInt>(gep->idx_begin())->getSExtValue();
            current_t2fmaps[gep_operand_type].insert(idx);
            t = stype;
            goto goodret;
        }else
        {
            //what else? maybe phi?
        }
    }else
    {
        //what else can it be?
    }
    return;
goodret:
    InstructionSet* ill = t2ci[t];
    if (ill==NULL)
    {
        ill = new InstructionSet;
        t2ci[t] = ill;
    }
    for (auto i: chks)
        ill->insert(i);
    if (knob_capchk_cctv)
    {
        errs()<<"Add struct "<<t->getStructName()<<" use @ ";
        i->getDebugLoc().print(errs());
        errs()<<"\n cause:";
        dump_dbgstk();
    }

    return;
}

/*
 * IPA: figure out all global variable usage and function calls
 * 
 * @I: from where are we starting, all following instructions should be dominated
 *     by I, if checked=true
 * @depth: are we going too deep?
 * @checked: is this function already checked? means that `I' will dominate all,
 *     means that the caller of current function have already been dominated by
 *     a check
 * @callgraph: how do we get here
 * @chks: which checks are protecting us?
 */
void capchk::forward_all_interesting_usage(Instruction* I, unsigned int depth,
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
    Type2Fields current_critical_type_fields;

    //don't allow recursive
    if (std::find(callgraph.begin(), callgraph.end(), I)!=callgraph.end())
        return;

    callgraph.push_back(I);

    if (depth>knob_fwd_depth)
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
                    if (gating->is_gating_function(csfunc))
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
            crit_type_field_collect(si, current_critical_type_fields, chks);
        }
    }
    /**********
     * merge 
     */
    if (is_function_permission_checked)
    {
        //merge forward slicing result
        for (auto i: current_crit_funcs)
            critical_functions.insert(i);
        for (auto v: current_critical_variables)
            critical_variables.insert(v);
        for (auto v: current_critical_type_fields)
        {
            Type* t = v.first;
            std::unordered_set<int>& sset = v.second;
            std::unordered_set<int>& dset = critical_typefields[t];
            for (auto x: sset)
                dset.insert(x);
        }

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
        //bool gv_use_func = false;
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

    errs()<<"Process Gating Functions\n";
    STOP_WATCH_START(WID_0);
    if (knob_gating_type=="cap")
        gating = new GatingCap(module);
    else if (knob_gating_type=="lsm")
        gating = new GatingLSM(module, knob_lsm_function_list);
    else
        llvm_unreachable("invalid setting!");
    STOP_WATCH_STOP(WID_0);
    STOP_WATCH_REPORT(WID_0);
    dump_gating();

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
        cvf_resolve_all_indirect_callee(module);
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
    errs()<<"Collected "<<critical_typefields.size()<<" critical type/fields\n";

    dump_v2ci();
    dump_f2ci();
    dump_tf2ci();

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
    if (knob_capchk_critical_type_field)
    {
        errs()<<"Critical Type Field\n";
        STOP_WATCH_START(WID_0);
        check_critical_type_field_usage(module);
        STOP_WATCH_STOP(WID_0);
        STOP_WATCH_REPORT(WID_0);
    }
    dump_non_kinit();
    delete gating;
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

