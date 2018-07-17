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

#define DEBUG_TYPE "capchk"

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

class capchk : public ModulePass
{
    private:
        virtual bool runOnModule(Module &) override;
        bool capchkPass(Module &);

        //capability checker
        void process_cpgf(Module& module);

        /*
         * prepare
         */
        void collect_kernel_init_functions(Module& module);
        void collect_wrappers(Module& module);
        void collect_crits(Module& module);
        void collect_pp(Module& module);
        void collect_chkps(Module&);
        void identify_interesting_struct(Module&);
        void identify_logical_module(Module&);
        void cvf_resolve_all_indirect_callee(Module& module);
        void figure_out_gep_using_type_field(InstructionSet&,
                const std::pair<Type*,std::unordered_set<int>>&, Module&);

        void forward_all_interesting_usage(Instruction* I, unsigned int depth,
                bool checked, InstructionList &callgraph,
                InstructionList& chks);

        void collect_scope(Instruction*, FunctionSet&);
        void collect_backward_scope(Instruction* i, FunctionSet& scope,
            InstructionList& callgraph, FunctionSet& visited);
        void augment_scope(FunctionSet& scope);

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

        bool bs_using_indcs(Function*,
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

        FunctionSet resolve_indirect_callee(CallInst*);

        InstructionSet& discover_chks(Function* f);
        InstructionSet& discover_chks(Function* f, FunctionSet& visited);
    


#ifdef CUSTOM_STATISTICS
        void dump_statistics();
#endif
        /*
         * several aux helper functions
         */
        bool is_complex_type(Type*);
        bool is_rw_global(Value*);
        Value* get_global_def(Value*);
        Value* get_global_def(Value*, ValueSet&);
        bool is_kernel_init_functions(Function* f);
        bool is_kernel_init_functions(Function* f, FunctionSet& visited);

        inline bool is_skip_var(const std::string& str)
        {
            return skip_vars->exists(str);
        };
        inline bool is_skip_function(const std::string& str)
        {
            return skip_funcs->exists(str) || kernel_api->exists(str);
        };

        //used by forward_all_interesting_usage to collect critical resources
        void crit_func_collect(CallInst*, FunctionSet&, InstructionList& chks);
        void crit_vars_collect(Instruction*, ValueList&, InstructionList& chks);
        void crit_type_field_collect(Instruction*, Type2Fields&, InstructionList& chks);

        /*
         * context for current module
         */
        LLVMContext *ctx;
        Module* m;
        /*
         * for debug purpose
         */
        InstructionList dbgstk;
        void dump_dbgstk();
        void dump_as_good(InstructionList& callstk);
        void dump_as_bad(InstructionList& callstk);
        void dump_as_ignored(InstructionList& callstk);
        void dump_callstack(InstructionList& callstk);

        void dump_gating();
        void dump_f2ci();
        void dump_v2ci();
        void dump_tf2ci();
        void dump_kinit();
        void dump_non_kinit();
        void dump_scope(FunctionSet&);
    

        void my_debug(Module& module);

//private object
        GatingFunctionBase *gating;
        SimpleSet* skip_vars;
        SimpleSet* skip_funcs;
        SimpleSet* crit_syms;
        SimpleSet* kernel_api;

    public:
        static char ID;
        capchk() : ModulePass(ID){};

        virtual StringRef getPassName() const override
        {
            return "capchk";
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
};

#endif//_CAPCHK_H_

