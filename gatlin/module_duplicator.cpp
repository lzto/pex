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
    res_mod = CloneModule(m, vmap).release();
    int cnt = 0;
    FunctionSet to_erase;
    FunctionSet dst_func_keep_set;
#if 1
    //FIXME:dont use KEEP now
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
#endif
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

    for (auto f: to_erase)
    {
        //create declaration
        std::string n = "_dummy_";
        n.append(f->getName());
        auto* nf = res_mod->getOrInsertFunction(n, f->getFunctionType(), f->getAttributes());
        //erase function
        //also remove everthing inside f from vmap
        vmap.erase(f);

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
    {
        llvm_unreachable("Failed!\n");
    }

    for (auto p: vmap)
    {
        Value * v = const_cast<Value*>
                            (static_cast<const Value*>(p.first));
        rvmap[p.second] = v;
    }
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

