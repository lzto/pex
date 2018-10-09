/*
 * CapChecker header file
 * linux kernel capability checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _CAPCHK_H_
#define _CAPCHK_H_

#include <fstream>

#include "llvm-c/Core.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionAliasAnalysis.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Function.h"
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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SetVector.h"

#include "commontypes.h"

#include "simple_set.h"
#include "gating_function_base.h"
#include "internal.h"
#include "utility.h"

#define DEBUG_TYPE "gatlin"

#if defined(DEBUG)
#undef DEBUG
#define DEBUG 0
#else
#define DEBUG 0
#endif

/*
* define statistics if not enabled in LLVM
*/
#if defined(LLVM_ENABLE_STATS)
#undef LLVM_ENABLE_STATS
#endif

#if defined(NDEBUG)\
   || !defined(LLVM_ENABLE_STATS)\
   || (!LLVM_ENABLE_STATS)

#undef STATISTIC
#define CUSTOM_STATISTICS 1
#define STATISTIC(X,Y) \
   unsigned long X;\
const char* X##_desc = Y;

#define STATISTICS_DUMP(X) \
   errs()<<"    "<<X<<" : "<<X##_desc<<"\n";

#endif

class gatlin : public ModulePass
{
    private:
        virtual bool runOnModule(Module &) override;
        bool gatlinPass(Module &);

        //capability checker
        void process_cpgf(Module& module);

        /*
         * prepare
         */
        void preprocess(Module& module);

        void collect_kernel_init_functions(Module& module);
        void collect_wrappers(Module& module);
        void collect_crits(Module& module);
        void collect_chkps(Module&);
        void identify_interesting_struct(Module&);
        void identify_kmi(Module&);
        void identify_dynamic_kmi(Module&);

        void populate_indcall_list_using_cvf(Module&);
        void populate_indcall_list_through_kmi(Module&);
        FunctionSet resolve_indirect_callee_using_kmi(CallInst*, int&);
        FunctionSet resolve_indirect_callee_using_dkmi(CallInst*);
        FunctionSet resolve_indirect_callee(CallInst*);
        FunctionSet resolve_indirect_callee_ldcst_kmi(CallInst* ci, int&err);

        bool load_from_global_fptr(Value* cv);

        void dump_kmi_info(CallInst*);

        void figure_out_gep_using_type_field(InstructionSet&,
                const std::pair<Type*,std::unordered_set<int>>&, Module&);

        void forward_all_interesting_usage(Instruction* I, unsigned int depth,
                bool checked, InstructionList &callgraph,
                InstructionList& chks);
        /*
         * analyze
         */
        void check_critical_function_usage(Module& module);
        void check_critical_variable_usage(Module& module);
        void check_critical_type_field_usage(Module& module);

        void backward_slice_build_callgraph(InstructionList &callgraph,
                Instruction* I, FunctionToCheckResult& fvisited,
                int& good, int& bad, int& ignored);
        void _backward_slice_reachable_to_chk_function(Instruction* I,
                int& good, int& bad, int& ignored);
        void backward_slice_reachable_to_chk_function(Instruction* I,
                int& good, int& bad, int& ignored);

        bool backward_slice_using_indcs(Function*,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored);

        bool match_cs_using_fptr_method_0(Function*,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored);
        bool match_cs_using_fptr_method_1(Function*,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored);
        bool match_cs_using_cvf(Function*,
                InstructionList& callgraph, FunctionToCheckResult& visited,
                int& good, int& bad, int& ignored);

        InstructionSet& discover_chks(Function* f);
        InstructionSet& discover_chks(Function* f, FunctionSet& visited);

#ifdef CUSTOM_STATISTICS
        void dump_statistics();
#endif

        //used by forward_all_interesting_usage to collect critical resources
        void crit_func_collect(CallInst*, FunctionSet&, InstructionList& chks);
        void crit_vars_collect(Instruction*, ValueList&, InstructionList& chks);
        void crit_type_field_collect(Instruction*, Type2Fields&, InstructionList& chks);

        /*
         * for debug purpose
         */

        void dump_as_good(InstructionList& callstk);
        void dump_as_bad(InstructionList& callstk);
        void dump_as_ignored(InstructionList& callstk);

        void dump_gating();
        void dump_f2ci();
        void dump_v2ci();
        void dump_tf2ci();
        void dump_kinit();
        void dump_non_kinit();
        void dump_kmi();
        void dump_dkmi();
    
        void my_debug(Module& module);

    public:
        static char ID;
        gatlin() : ModulePass(ID){};

        virtual StringRef getPassName() const override
        {
            return "gatlin";
        }

        virtual void print(raw_ostream &OS, const Module *M)
        {
            OS<<"Analysis Result\n";
        }

        void getAnalysisUsage(AnalysisUsage &au) const override
        {
            //au.addRequired<AAResultsWrapperPass>();
            //au.addRequired<TargetLibraryInfoWrapperPass>();
            //au.addRequired<ScalarEvolutionWrapperPass>();
            au.setPreservesAll();
        }

    private:
//private objects
        InstructionList dbgstk;
        /*
         * context for current module
         */
        LLVMContext *ctx;
        Module* m;

        GatingFunctionBase *gating;

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

        //functions which has unresolved indirect calls
        FunctionSet fuidcs;

        //all syscall is listed here
        FunctionSet syscall_list;

        //functions have address taken by struct(kmi)
        FunctionSet kmi_funcs;
        //trace event functions
        FunctionSet trace_event_funcs;
        //bpf stuff
        FunctionSet bpf_funcs;
        //irq stuff
        FunctionSet irq_funcs;

        //all discovered interesting type(have struct member points to function with check)
        TypeSet discovered_interesting_type;

        //all module interface to corresponding module mapping
        ModuleInterface2Modules mi2m;
        //dynamic KMI
        DMInterface dmi;


        FunctionSet kernel_init_functions;
        FunctionSet non_kernel_init_functions;

        //store all skipped critical functions here
        FunctionSet skipped_functions;
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

    private:
/*
 * aux helper functions
 */
        inline bool is_critical_function(Function* f)
        {
            return critical_functions.count(f)!=0;
        }

        void find_in_mi2m(Type* t, ModuleSet& ms);
        bool is_interesting_type(Type*);
        bool is_used_by_static_assign_to_interesting_type(Value* v);
        bool _is_used_by_static_assign_to_interesting_type(Value* v,
                std::unordered_set<Value*>& duchain);

        bool is_syscall_prefix(StringRef str)
        {
            for (int i=0;i<4;i++)
                if (str.startswith(_builtin_syscall_prefix[i]))
                    return true;
            return false;
        }

        inline bool is_syscall(Function *f)
        {
            return syscall_list.count(f)!=0;
        }

        bool is_kernel_init_functions(Function* f);
        bool is_kernel_init_functions(Function* f, FunctionSet& visited);

        bool is_complex_type(Type*);
        bool is_rw_global(Value*);
        Value* get_global_def(Value*);
        Value* get_global_def(Value*, ValueSet&);

        inline bool is_skip_var(const std::string& str)
        {
            return skip_vars->exists_ignore_dot_number(str);
        };
        inline bool is_skip_function(const std::string& str)
        {
            return skip_funcs->exists_ignore_dot_number(str)
                || kernel_api->exists_ignore_dot_number(str);
        };

        FunctionSet function_signature_match(CallInst* ci);

};

#endif//_CAPCHK_H_

