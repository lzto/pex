/*
 * Module Duplicator
 * duplicate module within given scope so that cvf can process the graph faster
 * 
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "module_duplicator.h"

#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;


ModuleDuplicator::ModuleDuplicator(Module& m, FunctionSet &keep, FunctionSet &remove)
{
#if (LLVM_VERSION_MAJOR>=7)
    res_mod = CloneModule(m, vmap).release();
#elif (LLVM_VERSION_MAJOR<=6)
    res_mod = CloneModule(&m, vmap).release();
#endif
    //generate reverse mapping from duplicated function to original function
    for (auto p: vmap)
    {
        Value * v = const_cast<Value*>
                            (static_cast<const Value*>(p.first));
        rvmap[p.second] = v;
    }

    int cnt = 0;
    //all functions to be erased from res_mod
    FunctionSet to_erase;
    FunctionSet dst_func_keep_set;

    //keep set
    for (auto f: keep)
    {
        auto nf = vmap[f];
        if (nf==NULL)
            continue;
        Function* func = dyn_cast<Function>(nf);
        dst_func_keep_set.insert(func);
    }
    for (Module::iterator fi = res_mod->begin(), f_end = res_mod->end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration())
            continue;
        if (dst_func_keep_set.find(func)!=dst_func_keep_set.end())
            continue;
        //otherwise erase
        to_erase.insert(func);
    }
////////////////////////////////////////////////////////////////////////////////
    //remove set
    for (auto f: remove)
    {
        auto nf = vmap[f];
        if (nf==NULL)
            continue;
        Function* func = dyn_cast<Function>(nf);
        to_erase.insert(func);
        cnt++;
    }

    //keep other global aliases
    for (GlobalAlias &ga : res_mod->aliases())
    {
        Constant* a = ga.getAliasee();
        Function* f = dyn_cast<Function>(a);
        if (to_erase.find(f)!=to_erase.end())
            to_erase.erase(f);
    }

    //do actual erase
    for (auto f: to_erase)
    {
        //create declaration
        std::string n = "_dummy_";
        n.append(f->getName());
        //errs()<<" erase "<<f->getName()<<"\n";
#if (LLVM_VERSION_MAJOR>=8)
        FunctionCallee nf_callee = res_mod->getOrInsertFunction(n, f->getFunctionType(), f->getAttributes());
        auto* nf = dyn_cast<Function>(nf_callee.getCallee());
#else
        auto* nf = res_mod->getOrInsertFunction(n, f->getFunctionType(), f->getAttributes());
#endif
        /*
         * erase function
         * also remove everthing inside f from vmap
         * and create new mapping from dummy function to original function
         * so that they can be mapped back to original function
         */
        Value* origf = rvmap[f];
        vmap.erase(f);
        rvmap.erase(origf);
        vmap[origf] = nf;
        rvmap[nf] = origf;

        f->replaceAllUsesWith(nf);
        f->eraseFromParent();
        //fix use
        cnt++;
    }
    
    errs()<<"Keep:"<<keep.size()<<" Functions \n";
    errs()<<"Remove:"<<remove.size()<<" Functions \n";
    errs()<<"erase:"<<cnt<<" Functions \n";
    raw_ostream *debugos = &errs();
    if (verifyModule(*res_mod, debugos))
        llvm_unreachable("Failed!\n");

    //errs()<<"=======DM=======\n";
    cnt = 0;
    for (Module::iterator fi = res_mod->begin(), f_end = res_mod->end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration())
            continue;
        if (func->isIntrinsic())
            continue;
        cnt++;
        //errs()<<" - "<<func->getName()<<"\n";
    }
    errs()<<"Duplicated module function cnt="<<cnt<<"\n";
    //errs()<<"=o=\n";
}

ModuleDuplicator::~ModuleDuplicator()
{
    delete res_mod;
}

Module& ModuleDuplicator::getResult()
{
    return *res_mod;
}

Value* ModuleDuplicator::map_to_duplicated(const Value* v)
{
    return vmap[v];
}

Value* ModuleDuplicator::map_to_origin(const Value* v)
{
    return rvmap[v];
}

