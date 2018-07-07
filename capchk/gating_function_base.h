/*
 * Gating Function
 * extend this class to identify other types of checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _GATING_FUNCTION_BASE_
#define _GATING_FUNCTION_BASE_

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Use.h"

#include "commontypes.h"
#include "internal.h"
#include "aux.h"

using namespace llvm;

class GatingFunctionBase
{
    protected:
        Module &m;

    public:
        GatingFunctionBase(Module& _m):m(_m){};
        virtual ~GatingFunctionBase(){};
        virtual bool is_gating_function(Function*)
        {
            return false;
        };
        virtual bool is_gating_function(std::string&)
        {
            return false;
        };
        virtual void dump(){};
        virtual void dump_interesting(InstructionSet*){};
};


class GatingCap : public GatingFunctionBase
{
    protected:
    /*
     * record capability parameter position passed to capability check function
     * all discovered wrapper function to check functions will also have one entry
     *
     * This data is available after calling collect_wrappers()
     */
        FunctionData chk_func_cap_position;

    private:
        bool is_builtin_capchk_function(const std::string&);
    public:
        GatingCap(Module&);
        ~GatingCap(){};
        virtual bool is_gating_function(Function*);
        virtual bool is_gating_function(std::string&);
        virtual void dump();
        virtual void dump_interesting(InstructionSet*);
};

class GatingLSM : public GatingFunctionBase
{
    protected:

    private:
        bool is_builtin_lsm_hook(const std::string&){ return false; };

    public:
        GatingLSM(Module& _m): GatingFunctionBase(_m){};
        ~GatingLSM(){};
        virtual bool is_gating_function(Function*){ return false; };
        virtual bool is_gating_function(std::string&){ return false; };
        virtual void dump(){};
        virtual void dump_interesting(InstructionSet*){};
};
#endif //_GATING_FUNCTION_BASE_


