/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "utility.h"
#include "color.h"
#include "internal.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static InstructionList dbgstk;
static ValueList dbglst;
/*
 * user can trace back to function argument?
 * only support simple wrapper
 * return the cap parameter position in parameter list
 * TODO: track full def-use chain
 * return -1 for not found
 */
int use_parent_func_arg(Value* v, Function* f)
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

static bool any_user_of_av_is_v(Value* av, Value* v, ValueSet& visited)
{
    if (av==v)
        return true;
    if (visited.count(av))
        return false;
    visited.insert(av);
    for (auto* u: av->users())
    {
        if (dyn_cast<Value>(u)==v)
        {
            return true;
        }
        if (any_user_of_av_is_v(u, v, visited))
        {
            return true;
        }
    }
    return false;
}

/*
 * full def-use chain
 */
int use_parent_func_arg_deep(Value* v, Function* f)
{
    int cnt = 0;
    for (auto a = f->arg_begin(), b = f->arg_end(); a!=b; ++a)
    {
        Value* av = dyn_cast<Value>(a);
        ValueSet visited;
        if (any_user_of_av_is_v(av,v,visited))
            return cnt;
        cnt++;
    }
    return -1;
}


Instruction* GetNextInstruction(Instruction* i)
{
    if (isa<TerminatorInst>(i))
        return i;
    BasicBlock::iterator BBI(i);
    return dyn_cast<Instruction>(++BBI);
}

Instruction* GetNextNonPHIInstruction(Instruction* i)
{
    if (isa<TerminatorInst>(i))
        return i;
    BasicBlock::iterator BBI(i);
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

InstructionSet get_user_instruction(Value* v)
{
    InstructionSet ret;
    ValueSet vset;
    ValueSet visited;
    visited.insert(v);
    for (auto* u: v->users())
    {
        vset.insert(u);
    }
    while (vset.size())
    {
        for (auto x: vset)
        {
            v = x;
            break;
        }
        visited.insert(v);
        vset.erase(v);
        //if a user is a instruction add it to ret and remove from vset
        if (Instruction *i = dyn_cast<Instruction>(v))
        {
            ret.insert(i);
            continue;
        }
        //otherwise add all user of current one
        for (auto* _u: v->users())
        {
            if (visited.count(_u)==0)
                vset.insert(_u);
        }
    }
    return ret;
}

/*
 * get CallInst
 * this can resolve call using bitcast
 *  : call %() bitcast %() @foo()
 */
static void _get_callsite_inst(Value*u, CallInstSet& cil, int depth)
{
    if (depth>2)
        return;
    Value* v = u;
    CallInst *cs;
    cs = dyn_cast<CallInst>(v);
    if (cs)
    {
        cil.insert(cs);
        return;
    }
    //otherwise...
    for (auto *u: v->users())
        _get_callsite_inst(u, cil, depth+1);
}

void get_callsite_inst(Value*u, CallInstSet& cil)
{
    _get_callsite_inst(u, cil, 0);
}

/*
 * is this type a function pointer type or 
 * this is a composite type which have function pointer type element
 */
static bool _has_function_pointer_type(Type* type, TypeSet& visited)
{
    if (visited.count(type)!=0)
        return false;
    visited.insert(type);
strip_pointer:
    if (type->isPointerTy())
    {
        type = type->getPointerElementType();
        goto strip_pointer;
    }
    if (type->isFunctionTy())
        return true;
    
    //ignore array type?
    //if (!type->isAggregateType())
    if (!type->isStructTy())
        return false;
    //for each element in this aggregate type, find out whether the element
    //type is Function pointer type, need to track down more if element is
    //aggregate type
    for (unsigned i=0; i<type->getStructNumElements(); ++i)
    {
        Type* t = type->getStructElementType(i);
        if (t->isPointerTy())
        {
            if (_has_function_pointer_type(t, visited))
                return true;
        }else if (t->isStructTy())
        {
            if (_has_function_pointer_type(t, visited))
                return true;
        }
    }
    //other composite type
    return false;
}

bool has_function_pointer_type(Type* type)
{
    TypeSet visited;
    return _has_function_pointer_type(type, visited);
}

/*
 * trace point function as callee?
 * similar to load+gep
 */
bool is_tracepoint_func(Value* v)
{
    LoadInst* li = dyn_cast<LoadInst>(v);
    if (!li)
        return false;
    Value* addr = li->getPointerOperand()->stripPointerCasts();
    //should be pointer type
    if (PointerType* pt = dyn_cast<PointerType>(addr->getType()))
    {
        Type* et = pt->getElementType();
        if (StructType *st = dyn_cast<StructType>(et))
        {
            //resolved!, they are trying to load the first function pointer
            //from a struct type we already know!
            //errs()<<"Found:"<<st->getStructName()<<"\n";
            if (st->getStructName()=="struct.tracepoint_func")
            {
                return true;
            }
            return true;
        }
    }
    //something else?
    return false;
}

/*
 * get the type where the function pointer is stored
 * could be combined with bitcast/gep
 *
 *   addr = (may bit cast) gep(struct addr, field)
 *   ptr = load(addr)
 */
GetElementPtrInst* get_load_from_gep(Value* v)
{
    LoadInst* li = dyn_cast<LoadInst>(v);
    if (!li)
        return NULL;
    Value* addr = li->getPointerOperand()->stripPointerCasts();
    //could also load from constant expr
    if (ConstantExpr *ce = dyn_cast<ConstantExpr>(addr))
    {
        addr = ce->getAsInstruction();
    }
    if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(addr))
        return gep;
    errs()<<"non gep:";
    //addr->print(errs());
    errs()<<"\n";
    return NULL;
}

Type* get_load_from_type(Value* v)
{
    GetElementPtrInst* gep = get_load_from_gep(v);
    if (gep==NULL)
        return NULL;
    Type* ty = dyn_cast<PointerType>(gep->getPointerOperandType())
            ->getElementType();
    return ty;
}

//only care about case where all indices are constantint
void get_gep_indicies(GetElementPtrInst* gep, std::list<int>& indices)
{
    if ((!gep) || (!gep->hasAllConstantIndices()))
        return;
    for (auto i = gep->idx_begin(); i!=gep->idx_end(); ++i)
    {
        ConstantInt* idc = dyn_cast<ConstantInt>(i);
        indices.push_back(idc->getSExtValue());
    }
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

void str_truncate_dot_number(std::string& str)
{
    if (!isdigit(str.back()))
        return;
    std::size_t found = str.find_last_of('.');
    str = str.substr(0,found);
}

bool is_skip_struct(StringRef str)
{
    for (int i=0;i<BUILDIN_STRUCT_TO_SKIP;i++)
        if (str.startswith(_builtin_struct_to_skip[i]))
            return true;
    return false;
}


static Value* _get_value_from_composit(Value* cv, std::list<int>& indices)
{
    //cv must be global value
    GlobalVariable* gi = dyn_cast<GlobalVariable>(cv);
    Constant* initializer = dyn_cast<Constant>(cv);
    Value* ret = NULL;
    Value* v;
    int i;

    dbglst.push_back(cv);

    if (!indices.size())
        goto end;

    i = indices.front();
    indices.pop_front();

    if (gi!=NULL)
        initializer = gi->getInitializer();
    else
        goto end;
again:
    /*
     * no initializer? the member of struct in question does not have a
     * concreat assignment, we can return now.
     */
    if (initializer==NULL)
        goto end;
    if (initializer->isZeroValue())
        goto end;
    v = initializer->getAggregateElement(i);
    assert(v!=cv);
    if (v==NULL)
    {
        initializer = initializer->getAggregateElement((unsigned)0);
        goto again;
    }

    v = v->stripPointerCasts();
    assert(v);
    if (isa<Function>(v))
    {
        ret = v;
        goto end;
    }
    if (indices.size())
    {
        ret = _get_value_from_composit(v, indices);
    }
end:
    dbglst.pop_back();
    return ret;
}

Value* get_value_from_composit(Value* cv, std::list<int>& indices)
{
    std::list<int> i = std::list<int>(indices);
    return _get_value_from_composit(cv, i);
}

/*
 * is this function's address taken?
 * ignore all use by EXPORT_SYMBOL and perf probe trace defs.
 */
bool is_address_taken(Function* f)
{
    bool ret = false;
    for (auto& u: f->uses())
    {
        auto* user = u.getUser();
        if (CallInst* ci = dyn_cast<CallInst>(user))
        {
            //used inside inline asm?
            if (ci->isInlineAsm())
                continue;
            //used as direct call, or parameter inside llvm.*
            if (Function* _f = get_callee_function_direct(ci))
            {
                if ((_f==f) || (_f->isIntrinsic()))
                    continue;
                //used as function parameter
                ret = true;
                goto end;
            }else
            {
                //used as function parameter
                ret = true;
                goto end;
            }
            llvm_unreachable("should not reach here");
        }
        //not call instruction
        ValueList vs;
        ValueSet visited;
        vs.push_back(dyn_cast<Value>(user));
        while(vs.size())
        {
            Value* v = vs.front();
            vs.pop_front();
            if (v->hasName())
            {
               auto name = v->getName();
               if (name.startswith("__ksymtab") || 
                       name.startswith("trace_event") ||
                       name.startswith("perf_trace") ||
                       name.startswith("trace_raw") || 
                       name.startswith("llvm.") ||
                       name.startswith("event_class"))
                   continue;
               ret = true;
               goto end;
            }
            for (auto&u: v->uses())
            {
                auto* user = dyn_cast<Value>(u.getUser());
                if (!visited.count(user))
                {
                    visited.insert(user);
                    vs.push_back(user);
                }
            }
        }
    }
end:
    return ret;
}

bool is_using_function_ptr(Function* f)
{
    bool ret = false;
    for(Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi)
    {
        BasicBlock* bb = dyn_cast<BasicBlock>(fi);
        for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
        {
            if (CallInst *ci = dyn_cast<CallInst>(ii))
            {
                if (Function* f = get_callee_function_direct(ci))
                {
                    //should skip those...
                    if (f->isIntrinsic())
                      continue;
                    //parameters have function pointer in it?
                    for (auto &i: ci->arg_operands())
                    {
                        //if (isa<Function>(i->stripPointerCasts()))
                        if (PointerType *pty = dyn_cast<PointerType>(i->getType()))
                        {
                            if (isa<FunctionType>(pty->getElementType()))
                            {
                                ret = true;
                                goto end;
                            }
                        }
                    }
                    //means that direct call is not using a function pointer
                    //in the parameter
                    continue;
                }else if (ci->isInlineAsm())
                {
                    //ignore inlineasm
                    //InlineAsm* iasm = dyn_cast<InlinAsm>(ci->getCalledValue());
                    continue;
                }else
                {
                    ret = true;
                    goto end;
                }
            }
            //any other use of function is considered using function pointer
            for (auto &i: ii->operands())
            {
                //if (isa<Function>(i->stripPointerCasts()))
                if (PointerType *pty = dyn_cast<PointerType>(i->getType()))
                {
                    if (isa<FunctionType>(pty->getElementType()))
                    {
                        ret = true;
                        goto end;
                    }
                }
            }
        }
    }
end:
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
void dump_callstack(InstructionList& callstk)
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


void dump_dbgstk(InstructionList& dbgstk)
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

void dump_gdblst(ValueList& list)
{
    errs()<<ANSI_COLOR_GREEN<<"Process List:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;
    for (auto* I: list)
    {
        errs()<<"  "<<cnt<<":";
        I->print(errs());
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

