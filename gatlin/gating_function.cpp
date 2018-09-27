/*
 * Gating Functions
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */

#include "gating_function_base.h"
#include "color.h"

#include "llvm/IR/CallSite.h"
#include "llvm/Support/raw_ostream.h"

#include "utility.h"

#include <fstream>

void GatingFunctionBase::dump_interesting(InstructionSet* cis)
{
    for (auto *ci: *cis)
    {
        CallInst* cs = dyn_cast<CallInst>(ci);
        Function* cf = get_callee_function_direct(cs);
        if (is_gating_function(cf))
        {
            errs()<<"    "<<cf->getName()<<" @ ";
            cs->getDebugLoc().print(errs());
            errs()<<"\n";
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//GatingCap

void GatingCap::load_cap_func_list(std::string& file)
{
    std::ifstream input(file);
    if (!input.is_open())
    {
        //TODO:load builtin list into cap_func_name2cap_arg_pos
        for (int i=0;i<BUILTIN_CAP_FUNC_LIST_SIZE;i++)
        {
            const struct str2int *p = &_builtin_cap_functions[i];
            cap_func_name2cap_arg_pos[p->k] = p->v;
        }
        return;
    }
    std::string line;
    while(std::getline(input,line))
    {
        std::size_t found = line.find(" ");
        assert(found!=std::string::npos);
        std::string name = line.substr(0, found);
        int pos = stoi(line.substr(found+1));
        cap_func_name2cap_arg_pos[name] = pos;
    }
    input.close();
    errs()<<"Load CAP FUNC list, total:"<<cap_func_name2cap_arg_pos.size()<<"\n";
}

bool GatingCap::is_builtin_gatlin_function(const std::string& str)
{
    for (int i=0;i<BUILTIN_CAP_FUNC_LIST_SIZE;i++)
    {
        const struct str2int *p = &_builtin_cap_functions[i];
        if (p->k==str)
            return true;
    }
    return false;                                  
}

GatingCap::GatingCap(Module& module, std::string& capfile)
    : GatingFunctionBase(module)
{
    load_cap_func_list(capfile);
    //add capable and ns_capable to chk_func_cap_position so that we can use them
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        StringRef fname = func->getName();

        if (cap_func_name2cap_arg_pos.find(fname)!=cap_func_name2cap_arg_pos.end())
        {
            chk_func_cap_position[func] = cap_func_name2cap_arg_pos[fname];
            if (chk_func_cap_position.size()==cap_func_name2cap_arg_pos.size())
                break;//we are done here
        }
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
            if (cap_pos>=cs->getNumArgOperands())
            {
                func->print(errs());
                llvm_unreachable(ANSI_COLOR_RED
                        "Check capability parameter"
                        ANSI_COLOR_RESET);
            }
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
                //llvm_unreachable("What??");
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
}

bool GatingCap::is_gating_function(Function* f)
{
    return chk_func_cap_position.find(f)!=chk_func_cap_position.end();
}

bool GatingCap::is_gating_function(std::string& str)
{
    for (auto& f2p: chk_func_cap_position)
    {
        if (f2p.first->getName()==str)
            return true;
    }
    return false;
}

void GatingCap::dump()
{
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

void GatingCap::dump_interesting(InstructionSet* cis)
{
    int last_cap_no = -1;
    bool mismatched_chk_func = false;
    Function* last_cap_chk_func = NULL;
    for (auto *ci: *cis)
    {
        CallInst* cs = dyn_cast<CallInst>(ci);
        Function* cf = get_callee_function_direct(cs);
        int cap_no = -1;
        if (is_gating_function(cf))
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

////////////////////////////////////////////////////////////////////////////////
//LSM

void GatingLSM::load_lsm_hook_list(std::string& file)
{
    std::ifstream input(file);
    if (!input.is_open())
        return;
    std::string line;
    while(std::getline(input,line))
        lsm_hook_names.insert(line);
    input.close();
    errs()<<"Load LSM hook list, total:"<<lsm_hook_names.size()<<"\n";
}

bool GatingLSM::is_lsm_hook(StringRef& str)
{
    if (lsm_hook_names.size())
    {
        return lsm_hook_names.find(str)!=lsm_hook_names.end();
    }
    //use builtin name
    if (str.startswith("security_"))
        return true;
    return false;
}

GatingLSM::GatingLSM(Module& module, std::string& lsmfile)
    : GatingFunctionBase(module)
{
    load_lsm_hook_list(lsmfile);
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        StringRef fname = func->getName();
        if (is_lsm_hook(fname))
        {
            lsm_hook_functions.insert(func);
        }
    }
}

bool GatingLSM::is_gating_function(Function* f)
{
    return lsm_hook_functions.find(f)!=lsm_hook_functions.end();
}

bool GatingLSM::is_gating_function(std::string& str)
{
    for (auto f: lsm_hook_functions)
    {
        if (f->getName()==str)
            return true;
    }
    return false;
}

void GatingLSM::dump()
{
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
        <<"=LSM hook functions="
        <<ANSI_COLOR_RESET<<"\n";
    for (auto f: lsm_hook_functions)
    {
        errs()<<". "<<f->getName()<<"\n";
    }
    errs()<<"=o=\n";
}

////////////////////////////////////////////////////////////////////////////////
//DAC
GatingDAC::GatingDAC(Module& module) : GatingFunctionBase(module)
{
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        StringRef fname = func->getName();
        if ((fname=="posix_acl_permission") || 
            (fname=="check_acl") ||
            (fname=="acl_permission_check") ||
            (fname=="generic_permission") ||
            (fname=="sb_permission") ||
            (fname=="inode_permission"))
        {
            dac_functions.insert(func);
        }
        if (dac_functions.size()==6)
            break;//we are done here
    }
    //discover wrapper
    //for all user of dac function, find whether the parameter comes from
    //out layer wrapper parameter?
    for (auto *dacf: dac_functions)
    {
        for (auto* u: dacf->users())
        {
            //should be call instruction and the callee is dacf
            CallInst *ci = dyn_cast<CallInst>(u);
            if (!ci)
                continue;
            if (ci->getCalledFunction()!=dacf)
                continue;
            Function* userf = ci->getFunction();
            //parameters comes from wrapper's parameter?
            for (int i = 0;i<ci->getNumOperands();i++)
            {
                Value* a = ci->getOperand(i);
                if (use_parent_func_arg(a, userf))
                {
                    dac_functions.insert(userf);
                }
            }
        }
    }
}

bool GatingDAC::is_gating_function(Function* f)
{
    return dac_functions.find(f)!=dac_functions.end();
}

bool GatingDAC::is_gating_function(std::string& str)
{
    for (auto& f: dac_functions)
    {
        if (f->getName()==str)
            return true;
    }
    return false;
}

void GatingDAC::dump()
{
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
        <<"=chk functions and wrappers="
        <<ANSI_COLOR_RESET<<"\n";
    for (auto &f: dac_functions)
    {
        errs()<<". "<<f->getName()
            <<"\n";
    }
    errs()<<"=o=\n";
}

