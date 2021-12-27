/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "utility.h"
#include "color.h"
#include "internal.h"
#include "llvm/IR/CFG.h"
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
int use_parent_func_arg(Value *v, Function *f) {
  int cnt = 0;
  for (auto a = f->arg_begin(), b = f->arg_end(); a != b; ++a) {
    if (dyn_cast<Value>(a) == v)
      return cnt;
    cnt++;
  }
  return -1;
}

static bool any_user_of_av_is_v(Value *av, Value *v, ValueSet &visited) {
  if (av == v)
    return true;
  if (visited.count(av))
    return false;
  visited.insert(av);
  for (auto *u : av->users()) {
    if (dyn_cast<Value>(u) == v) {
      return true;
    }
    if (any_user_of_av_is_v(u, v, visited)) {
      return true;
    }
  }
  return false;
}

/*
 * full def-use chain
 */
int use_parent_func_arg_deep(Value *v, Function *f) {
  int cnt = 0;
  for (auto a = f->arg_begin(), b = f->arg_end(); a != b; ++a) {
    Value *av = dyn_cast<Value>(a);
    ValueSet visited;
    if (any_user_of_av_is_v(av, v, visited))
      return cnt;
    cnt++;
  }
  return -1;
}

Instruction *GetNextInstruction(Instruction *i) {
  // if (isa<TerminatorInst>(i))
  //    return i;
  BasicBlock::iterator BBI(i);
  return dyn_cast<Instruction>(++BBI);
}

Instruction *GetNextNonPHIInstruction(Instruction *i) {
  // if (isa<TerminatorInst>(i))
  //    return i;
  BasicBlock::iterator BBI(i);
  while (isa<PHINode>(BBI))
    ++BBI;
  return dyn_cast<Instruction>(BBI);
}

Function *get_callee_function_direct(Instruction *i) {
  CallInst *ci = dyn_cast<CallInst>(i);
  if (Function *f = ci->getCalledFunction())
    return f;
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  Function *f = dyn_cast<Function>(cv->stripPointerCasts());
  return f;
}

StringRef get_callee_function_name(Instruction *i) {
  if (Function *f = get_callee_function_direct(i))
    return f->getName();
  return "";
}

// compare two indices
bool indices_equal(Indices *a, Indices *b) {
  if (a->size() != b->size())
    return false;
  auto ai = a->begin();
  auto bi = b->begin();
  while (ai != a->end()) {
    if (*ai != *bi)
      return false;
    bi++;
    ai++;
  }
  return true;
}

/*
 * store dyn KMI result into DMInterface so that we can use it later
 */
void add_function_to_dmi(Function *f, StructType *t, Indices &idcs,
                         DMInterface &dmi) {
  IFPairs *ifps = dmi[t];
  if (ifps == NULL) {
    ifps = new IFPairs;
    dmi[t] = ifps;
  }
  FunctionSet *fset = NULL;
  for (auto *p : *ifps) {
    if (indices_equal(&idcs, p->first)) {
      fset = p->second;
      break;
    }
  }
  if (fset == NULL) {
    fset = new FunctionSet;
    Indices *idc = new Indices;
    for (auto i : idcs)
      idc->push_back(i);
    IFPair *ifp = new IFPair(idc, fset);
    ifps->push_back(ifp);
  }
  fset->insert(f);
}

/*
 * this type exists in dmi?
 */
bool dmi_type_exists(StructType *t, DMInterface &dmi) {
  // first method
  auto ifps = dmi.find(t);
  std::string stname;
  // only use this for literal
  if (t->isLiteral()) {
    if (ifps != dmi.end())
      return true;
    return false;
  }
  // match using name
  stname = std::string(t->getStructName());
  str_truncate_dot_number(stname);
  for (auto &ifpsp : dmi) {
    StructType *cst = ifpsp.first;
    if (cst->isLiteral())
      continue;
    std::string cstn = std::string(cst->getStructName());
    str_truncate_dot_number(cstn);
    if (cstn == stname) {
      return true;
    }
  }
  return false;
}

/*
 * given StructType and indices, return FunctionSet or NULL
 */
FunctionSet *dmi_exists(StructType *t, Indices &idcs, DMInterface &dmi) {
  // first method
  auto ifps = dmi.find(t);
  std::string stname;
  IFPairs *ifpairs;
  // only use this for literal
  if (t->isLiteral()) {
    if (ifps != dmi.end()) {
      ifpairs = ifps->second;
      for (auto *p : *ifpairs)
        if (indices_equal(&idcs, p->first))
          return p->second;
    }
    goto end;
  }

  // match using name
  stname = std::string(t->getStructName());
  str_truncate_dot_number(stname);
  for (auto &ifpsp : dmi) {
    StructType *cst = ifpsp.first;
    if (cst->isLiteral())
      continue;
    std::string cstn = std::string(cst->getStructName());
    str_truncate_dot_number(cstn);
    if (cstn == stname) {
      ifpairs = ifpsp.second;
      for (auto *p : *ifpairs)
        if (indices_equal(&idcs, p->first))
          return p->second;
    }
  }

end:
  return NULL;
}

/*
 * intra-procedural analysis
 *
 * only handle high level type info right now.
 * maybe we can extend this to global variable as well
 *
 * see if store instruction actually store the value to some field of a struct
 * return non NULL if found, and indices is stored in idcs
 *
 */
static StructType *resolve_where_is_it_stored_to(StoreInst *si, Indices &idcs) {
  StructType *ret = NULL;
  // po is the place where we want to store to
  Value *po = si->getPointerOperand();
  ValueList worklist;
  ValueSet visited;
  worklist.push_back(po);

  // use worklist to track what du-chain
  while (worklist.size()) {
    // fetch an item and skip if visited
    po = worklist.front();
    worklist.pop_front();
    if (visited.count(po))
      continue;
    visited.insert(po);

    /*
     * pointer operand is global variable?
     * dont care... we can extend this to support fine grind global-aa, since
     * we already know the target
     */
    if (dyn_cast<GlobalVariable>(po))
      continue;
    if (ConstantExpr *cxpr = dyn_cast<ConstantExpr>(po)) {
      Instruction *cxpri = cxpr->getAsInstruction();
      worklist.push_back(cxpri);
      continue;
    }
    if (Instruction *i = dyn_cast<Instruction>(po)) {
      switch (i->getOpcode()) {
      case (Instruction::PHI): {
        PHINode *phi = dyn_cast<PHINode>(i);
        for (unsigned int i = 0; i < phi->getNumIncomingValues(); i++)
          worklist.push_back(phi->getIncomingValue(i));
        break;
      }
      case (Instruction::Select): {
        SelectInst *sli = dyn_cast<SelectInst>(i);
        worklist.push_back(sli->getTrueValue());
        worklist.push_back(sli->getFalseValue());
        break;
      }
      case (BitCastInst::BitCast): {
        BitCastInst *bci = dyn_cast<BitCastInst>(i);
        // FIXME:sometimes struct name is purged into i8.. we don't know why,
        // but we are not able to resolve those since they are translated
        // to gep of byte directly without using any struct type/member/field
        // info example: alloc_buffer, drivers/usb/host/ohci-dbg.c
        worklist.push_back(bci->getOperand(0));
        break;
      }
      case (Instruction::IntToPtr): {
        IntToPtrInst *i2ptr = dyn_cast<IntToPtrInst>(i);
        worklist.push_back(i2ptr->getOperand(0));
        break;
      }
      case (Instruction::GetElementPtr): {
        // only GEP is meaningful
        GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(i);
        Type *t = gep->getSourceElementType();
        get_gep_indicies(gep, idcs);
        assert(idcs.size() != 0);
        ret = dyn_cast<StructType>(t);
        goto out;
        break;
      }
      case (Instruction::Call): {
        // ignore interprocedural...
        break;
      }
      case (Instruction::Load): {
        // we are not able to handle load
        break;
      }
      case (Instruction::Store): {
        // how come we have a store???
        dump_gdblst(dbglst);
        llvm_unreachable("Store to Store?");
        break;
      }
      case (Instruction::Alloca): {
        // store to a stack variable
        // maybe interesting to explore who used this.
        break;
      }
      case (BinaryOperator::Add): {
        // adjust pointer using arithmatic, seems to be weired
        BinaryOperator *bop = dyn_cast<BinaryOperator>(i);
        for (unsigned int i = 0; i < bop->getNumOperands(); i++)
          worklist.push_back(bop->getOperand(i));
        break;
      }
      case (Instruction::PtrToInt): {
        PtrToIntInst *p2int = dyn_cast<PtrToIntInst>(i);
        worklist.push_back(p2int->getOperand(0));
        break;
      }
      default:
        errs() << "unable to handle instruction:" << ANSI_COLOR_RED;
        i->print(errs());
        errs() << ANSI_COLOR_RESET << "\n";
        break;
      }
    } else {
      // we got a function parameter
    }
  }
out:
  return ret;
}

/*
 * part of dynamic KMI - a data flow analysis
 * for value v, we want to know whether it is assigned to a struct field, and
 * we want to know indices and return the struct type
 * NULL is returned if not assigned to struct
 *
 * ! there should be a store instruction in the du-chain
 * TODO: extend this to inter-procedural analysis
 */
// known interesting
inline bool stub_fatst_is_interesting_value(Value *v) {

  if (isa<BitCastInst>(v) || isa<CallInst>(v) || isa<ConstantExpr>(v) ||
      isa<StoreInst>(v) || isa<Function>(v))
    return true;
  if (SelectInst *si = dyn_cast<SelectInst>(v)) {
    // result of select shoule be the same as v
    if (si->getType() == v->getType())
      return true;
  }
  if (PHINode *phi = dyn_cast<PHINode>(v)) {
    if (phi->getType() == v->getType())
      return true;
  }
  // okay if this is a function parameter
  // a value that is not global and not an instruction/phi
  if ((!isa<GlobalValue>(v)) && (!isa<Instruction>(v))) {
    return true;
  }

  return false;
}
// known uninteresting
inline bool stub_fatst_is_uninteresting_value(Value *v) {
  if (isa<GlobalVariable>(v) || isa<Constant>(v) || isa<ICmpInst>(v) ||
      isa<PtrToIntInst>(v))
    return true;
  return false;
}

StructType *find_assignment_to_struct_type(Value *v, Indices &idcs,
                                           ValueSet &visited) {
  if (visited.count(v))
    return NULL;
  visited.insert(v);

  dbglst.push_back(v);

  // FIXME: it is possible to assign to global variable!
  //       but currently we are not handling them
  // skip all global variables,
  // the address is statically assigned to global variable
  if (!stub_fatst_is_interesting_value(v)) {
#if 0
        if (!stub_fatst_is_uninteresting_value(v))
        {
            errs()<<ANSI_COLOR_RED<<"XXX:"
                <<ANSI_COLOR_RESET<<"\n";
            dump_gdblst(dbglst);
        }
#endif
    dbglst.pop_back();
    return NULL;
  }

  //* ! there should be a store instruction in the du-chain
  if (StoreInst *si = dyn_cast<StoreInst>(v)) {
    StructType *ret = resolve_where_is_it_stored_to(si, idcs);
    dbglst.pop_back();
    return ret;
  }

  for (auto *u : v->users()) {
    Value *tu = u;
    Type *t = u->getType();
    if (StructType *t_st = dyn_cast<StructType>(t))
      if ((t_st->hasName()) &&
          t_st->getStructName().startswith("struct.kernel_symbol"))
        continue;
    // inter-procedural analysis
    // we are interested if it is used as a function parameter
    if (CallInst *ci = dyn_cast<CallInst>(tu)) {
      // currently only deal with direct call...
      Function *cif = get_callee_function_direct(ci);
#if (LLVM_VERSION_MAJOR <= 10)
      if ((ci->getCalledValue() == v) || (cif == u)) {
#else
      if ((ci->getCalledOperand() == v) || (cif == u)) {
#endif
        // ignore calling myself..
        continue;
      } else if (cif == NULL) {
        // indirect call...
#if 0
                errs()<<"fptr used in indirect call";
                ci->print(errs());errs()<<"\n";
                errs()<<"arg v=";
                v->print(errs());errs()<<"\n";
#endif
        continue;
      } else if (!cif->isVarArg()) {
        // try to figure out which argument is u corresponds to
        int argidx = -1;
        for (unsigned int ai = 0; ai < ci->getNumArgOperands(); ai++) {
          if (ci->getArgOperand(ai) == v) {
            argidx = ai;
            break;
          }
        }
        // argidx should not ==-1
        if (argidx == -1) {
          errs() << "Calling " << cif->getName() << "\n";
          ci->print(errs());
          errs() << "\n";
          errs() << "arg v=";
          v->print(errs());
          errs() << "\n";
        }
        assert(argidx != -1);
        // errs()<<"Into "<<cif->getName()<<"\n";
        // now are are in the callee function
        // figure out the argument
        auto targ = cif->arg_begin();
        for (int i = 0; i < argidx; i++)
          targ++;
        tu = targ;
      } else {
        // means that this is a vararg
        continue;
      }
    }
    // FIXME: visited?
    if (StructType *st = find_assignment_to_struct_type(tu, idcs, visited)) {
      dbglst.pop_back();
      return st;
    }
  }
  dbglst.pop_back();
  return NULL;
}

InstructionSet get_user_instruction(Value *v) {
  InstructionSet ret;
  ValueSet vset;
  ValueSet visited;
  visited.insert(v);
  for (auto *u : v->users()) {
    vset.insert(u);
  }
  while (vset.size()) {
    for (auto x : vset) {
      v = x;
      break;
    }
    visited.insert(v);
    vset.erase(v);
    // if a user is a instruction add it to ret and remove from vset
    if (Instruction *i = dyn_cast<Instruction>(v)) {
      ret.insert(i);
      continue;
    }
    // otherwise add all user of current one
    for (auto *_u : v->users()) {
      if (visited.count(_u) == 0)
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
static void _get_callsite_inst(Value *u, CallInstSet &cil, int depth) {
  if (depth > 2)
    return;
  Value *v = u;
  CallInst *cs;
  cs = dyn_cast<CallInst>(v);
  if (cs) {
    cil.insert(cs);
    return;
  }
  // otherwise...
  for (auto *u : v->users())
    _get_callsite_inst(u, cil, depth + 1);
}

void get_callsite_inst(Value *u, CallInstSet &cil) {
  _get_callsite_inst(u, cil, 0);
}

/*
 * is this type a function pointer type or
 * this is a composite type which have function pointer type element
 */
static bool _has_function_pointer_type(Type *type, TypeSet &visited) {
  if (visited.count(type) != 0)
    return false;
  visited.insert(type);
strip_pointer:
  if (type->isPointerTy()) {
    type = type->getPointerElementType();
    goto strip_pointer;
  }
  if (type->isFunctionTy())
    return true;

  // ignore array type?
  // if (!type->isAggregateType())
  if (!type->isStructTy())
    return false;
  // for each element in this aggregate type, find out whether the element
  // type is Function pointer type, need to track down more if element is
  // aggregate type
  for (unsigned i = 0; i < type->getStructNumElements(); ++i) {
    Type *t = type->getStructElementType(i);
    if (t->isPointerTy()) {
      if (_has_function_pointer_type(t, visited))
        return true;
    } else if (t->isStructTy()) {
      if (_has_function_pointer_type(t, visited))
        return true;
    }
  }
  // other composite type
  return false;
}

bool has_function_pointer_type(Type *type) {
  TypeSet visited;
  return _has_function_pointer_type(type, visited);
}

/*
 * return global value if this is loaded from global value, otherwise return
 * NULL
 */
GlobalValue *get_loaded_from_gv(Value *v) {
  GlobalValue *ret = NULL;
  IntToPtrInst *i2ptr = dyn_cast<IntToPtrInst>(v);
  LoadInst *li;
  Value *addr;
  if (!i2ptr)
    goto end;
  // next I am expectnig a load instruction
  li = dyn_cast<LoadInst>(i2ptr->getOperand(0));
  if (!li)
    goto end;
  addr = li->getPointerOperand()->stripPointerCasts();
  // could be a constant expr of gep?
  if (ConstantExpr *cxpr = dyn_cast<ConstantExpr>(addr)) {
    GetElementPtrInst *gep =
        dyn_cast<GetElementPtrInst>(cxpr->getAsInstruction());
    if (Value *tpobj = gep->getPointerOperand())
      ret = dyn_cast<GlobalValue>(tpobj);
  }
end:
  return ret;
}

/*
 * is this a load+bitcast of struct into fptr type?
 * could be multiple load + bitcast
 */
StructType *identify_ld_bcst_struct(Value *v) {
#if 0
    LoadInst* li = dyn_cast<LoadInst>(v);
    if (!li)
        return NULL;
    Value* addr = li->getPointerOperand();
    if (BitCastInst* bci = dyn_cast<BitCastInst>(addr))
        addr = bci->getOperand(0);
    else
        return NULL;
    //should be pointer type
    if (PointerType* pt = dyn_cast<PointerType>(addr->getType()))
    {
        Type* et = pt->getElementType();
        if (StructType *st = dyn_cast<StructType>(et))
        {
            //resolved!, they are trying to load the first function pointer
            //from a struct type we already know!
            return st;
        }
    }
    return NULL;
#else
  int num_load = 0;
  Value *nxtv = v;
  while (1) {
    if (LoadInst *li = dyn_cast<LoadInst>(nxtv)) {
      nxtv = li->getPointerOperand();
      num_load++;
      continue;
    }
    if (IntToPtrInst *itoptr = dyn_cast<IntToPtrInst>(nxtv)) {
      nxtv = itoptr->getOperand(0);
      continue;
    }
    break;
  }
  if (num_load == 0)
    return NULL;
  if (BitCastInst *bci = dyn_cast<BitCastInst>(nxtv)) {
    nxtv = bci->getOperand(0);
  } else
    return NULL;
  // num_load = number of * in nxtv
  Type *ret = nxtv->getType();
  while (num_load) {
    // I am expecting a pointer type
    PointerType *pt = dyn_cast<PointerType>(ret);
    if (!pt) {
      errs() << "I am expecting a pointer type! got:";
      ret->print(errs());
      errs() << "\n";
      return NULL;
    }
    // assert(pt);
    ret = pt->getElementType();
    num_load--;
  }
  return dyn_cast<StructType>(ret);
#endif
}

/*
 * trace point function as callee?
 * similar to load+gep, we can not know callee statically, because it is not
 * defined trace point is a special case where the indirect callee is defined at
 * runtime, we simply mark it as resolved since we can find where the callee
 * fptr is loaded from
 */
bool is_tracepoint_func(Value *v) {
  if (StructType *st = identify_ld_bcst_struct(v)) {
#if 0
        errs()<<"Found:";
        if (st->isLiteral())
            errs()<<"Literal\n";
        else
            errs()<<st->getStructName()<<"\n";
#endif
    // no name ...
    if (!st->hasName())
      return false;
    StringRef name = st->getStructName();
    if (name == "struct.tracepoint_func") {
      // errs()<<" ^ a tpfunc:";
      // addr->print(errs());
      LoadInst *li = dyn_cast<LoadInst>(v);
      Value *addr = li->getPointerOperand()->stripPointerCasts();

      // addr should be a phi
      PHINode *phi = dyn_cast<PHINode>(addr);
      assert(phi);
      // one of the incomming value should be a load
      for (unsigned int i = 0; i < phi->getNumIncomingValues(); i++) {
        Value *iv = phi->getIncomingValue(i);
        // should be a load from a global defined object
        if (GlobalValue *gv = get_loaded_from_gv(iv)) {
          // gv->print(errs());
          // errs()<<(gv->getName());
          break;
        }
      }
      // errs()<<"\n";
      return true;
    }
    return false;
  }
  // something else?
  return false;
}

/*
 * FIXME: we are currently not able to handle container_of, which is expanded
 * into gep with negative index and high level type information is stripped
 * maybe we can define a function to repalce container_of... so that high level
 * type information won't be stripped during compilation
 */
bool is_container_of(Value *cv) {
  InstructionSet geps = get_load_from_gep(cv);
  for (auto _gep : geps) {
    GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(_gep);
    // container_of has gep with negative index
    // and must have negative or non-zero index in the first element
    auto i = gep->idx_begin();
    ConstantInt *idc = dyn_cast<ConstantInt>(i);
    if (idc && (idc->getSExtValue() != 0)) {
#if 0
            Type* pty = gep->getSourceElementType();
            if(StructType* sty = dyn_cast<StructType>(pty))
            {
                if (!sty->isLiteral())
                    errs()<<sty->getStructName()<<" ";
            }
#endif
      return true;
    }
  }
  return false;
}

/*
 * get the type where the function pointer is stored
 * could be combined with bitcast/gep/select/phi
 *
 *   addr = (may bit cast) gep(struct addr, field)
 *   ptr = load(addr)
 *   call ptr
 *
 *  may have other form like:
 *  addr1 = gep
 *  addr2 = gep
 *  ptr0 = phi/select addr1, addr2
 *  ptr1 = bitcast ptr0
 *  fptr = load(ptr1)
 *  call fptr
 *
 *  or no gep at all like
 *
 *  fptr_addr = bitcast struct addr, func type*()
 *  fptr = load fptr_addr
 *  call fptr
 *
 */
InstructionSet get_load_from_gep(Value *v) {
  InstructionSet lots_of_geps;
  // handle non load instructions first
  // might be gep/phi/select/bitcast
  // collect all load instruction into loads
  InstructionSet loads;
  ValueSet visited;
  ValueList worklist;

  // first, find all interesting load
  worklist.push_back(v);
  while (worklist.size()) {
    Value *i = worklist.front();
    worklist.pop_front();
    if (visited.count(i))
      continue;
    visited.insert(i);
    assert(i != NULL);
    if (LoadInst *li = dyn_cast<LoadInst>(i)) {
      loads.insert(li);
      continue;
    }
    if (BitCastInst *bci = dyn_cast<BitCastInst>(i)) {
      worklist.push_back(bci->getOperand(0));
      continue;
    }
    if (PHINode *phi = dyn_cast<PHINode>(i)) {
      for (int k = 0; k < (int)phi->getNumIncomingValues(); k++)
        worklist.push_back(phi->getIncomingValue(k));
      continue;
    }
    if (SelectInst *sli = dyn_cast<SelectInst>(i)) {
      worklist.push_back(sli->getTrueValue());
      worklist.push_back(sli->getFalseValue());
      continue;
    }
    if (IntToPtrInst *itptr = dyn_cast<IntToPtrInst>(i)) {
      worklist.push_back(itptr->getOperand(0));
      continue;
    }
    if (PtrToIntInst *ptint = dyn_cast<PtrToIntInst>(i)) {
      worklist.push_back(ptint->getOperand(0));
      continue;
    }
    // binary operand for pointer manupulation
    if (BinaryOperator *bop = dyn_cast<BinaryOperator>(i)) {
      for (int i = 0; i < (int)bop->getNumOperands(); i++)
        worklist.push_back(bop->getOperand(i));
      continue;
    }
    if (ZExtInst *izext = dyn_cast<ZExtInst>(i)) {
      worklist.push_back(izext->getOperand(0));
      continue;
    }
    if (SExtInst *isext = dyn_cast<SExtInst>(i)) {
      worklist.push_back(isext->getOperand(0));
      continue;
    }
    if (isa<GlobalValue>(i) || isa<ConstantExpr>(i) ||
        isa<GetElementPtrInst>(i) || isa<CallInst>(i))
      continue;
    if (!isa<Instruction>(i))
      continue;
    i->print(errs());
    errs() << "\n";
    llvm_unreachable("no possible");
  }
  //////////////////////////
  // For each load instruction's pointer operand, we want to know whether
  // it is derived from gep or not..
  for (auto *lv : loads) {
    LoadInst *li = dyn_cast<LoadInst>(lv);
    Value *addr = li->getPointerOperand();

    // track def-use chain
    worklist.push_back(addr);
    visited.clear();
    while (worklist.size()) {
      Value *i = worklist.front();
      worklist.pop_front();
      if (visited.count(i))
        continue;
      visited.insert(i);
      if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(i)) {
        lots_of_geps.insert(gep);
        continue;
      }
      if (BitCastInst *bci = dyn_cast<BitCastInst>(i)) {
        worklist.push_back(bci->getOperand(0));
        continue;
      }
      if (PHINode *phi = dyn_cast<PHINode>(i)) {
        for (int k = 0; k < (int)phi->getNumIncomingValues(); k++)
          worklist.push_back(phi->getIncomingValue(k));
        continue;
      }
      if (SelectInst *sli = dyn_cast<SelectInst>(i)) {
        worklist.push_back(sli->getTrueValue());
        worklist.push_back(sli->getFalseValue());
        continue;
      }
      if (IntToPtrInst *itptr = dyn_cast<IntToPtrInst>(i)) {
        worklist.push_back(itptr->getOperand(0));
        continue;
      }
      if (PtrToIntInst *ptint = dyn_cast<PtrToIntInst>(i)) {
        worklist.push_back(ptint->getOperand(0));
        continue;
      }
      // binary operand for pointer manupulation
      if (BinaryOperator *bop = dyn_cast<BinaryOperator>(i)) {
        for (int i = 0; i < (int)bop->getNumOperands(); i++)
          worklist.push_back(bop->getOperand(i));
        continue;
      }
      if (ZExtInst *izext = dyn_cast<ZExtInst>(i)) {
        worklist.push_back(izext->getOperand(0));
        continue;
      }
      if (SExtInst *isext = dyn_cast<SExtInst>(i)) {
        worklist.push_back(isext->getOperand(0));
        continue;
      }
      // gep in constantexpr?
      if (ConstantExpr *cxpr = dyn_cast<ConstantExpr>(i)) {
        worklist.push_back(cxpr->getAsInstruction());
        continue;
      }

      if (isa<GlobalValue>(i) || isa<LoadInst>(i) || isa<AllocaInst>(i) ||
          isa<CallInst>(i))
        continue;
      if (!isa<Instruction>(i))
        continue;
      // what else?
      i->print(errs());
      errs() << "\n";
      llvm_unreachable("what else?");
    }
  }
  return lots_of_geps;
}

// only care about case where all indices are constantint
void get_gep_indicies(GetElementPtrInst *gep, Indices &indices) {
  if (!gep)
    return;
  // replace all non-constant with zero
  // because they are literally an array...
  // and we are only interested in the type info
  for (auto i = gep->idx_begin(); i != gep->idx_end(); ++i) {
    ConstantInt *idc = dyn_cast<ConstantInt>(i);
    if (idc)
      indices.push_back(idc->getSExtValue());
    else
      indices.push_back(0);
  }
}

bool function_has_gv_initcall_use(Function *f) {
  static FunctionSet fs_initcall;
  static FunctionSet fs_noninitcall;
  if (fs_initcall.count(f) != 0)
    return true;
  if (fs_noninitcall.count(f) != 0)
    return false;
  for (auto u : f->users())
    if (GlobalValue *gv = dyn_cast<GlobalValue>(u)) {
      if (!gv->hasName())
        continue;
      if (gv->getName().startswith("__initcall_")) {
        fs_initcall.insert(f);
        return true;
      }
    }
  fs_noninitcall.insert(f);
  return false;
}

void str_truncate_dot_number(std::string &str) {
  if (!isdigit(str.back()))
    return;
  std::size_t found = str.find_last_of('.');
  str = str.substr(0, found);
}

bool is_skip_struct(StringRef str) {
  for (int i = 0; i < BUILDIN_STRUCT_TO_SKIP; i++)
    if (str.startswith(_builtin_struct_to_skip[i]))
      return true;
  return false;
}

/*
 * match a type/indices with known ones
 */
static Value *_get_value_from_composit(Value *cv, Indices &indices) {
  // cv must be global value
  GlobalVariable *gi = dyn_cast<GlobalVariable>(cv);
  Constant *initializer = dyn_cast<Constant>(cv);
  Value *ret = NULL;
  Value *v;
  int i;
  dbglst.push_back(cv);

  if (!indices.size())
    goto end;

  i = indices.front();
  indices.pop_front();

  if (gi)
    initializer = gi->getInitializer();
  assert(initializer && "must have a initializer!");
  /*
   * no initializer? the member of struct in question does not have a
   * concreat assignment, we can return now.
   */
  if (initializer == NULL)
    goto end;
  if (initializer->isZeroValue())
    goto end;
  v = initializer->getAggregateElement(i);
  assert(v != cv);
  if (v == NULL)
    goto end; // means that this field is not initialized

  v = v->stripPointerCasts();
  assert(v);
  if (isa<Function>(v)) {
    ret = v;
    goto end;
  }
  if (indices.size())
    ret = _get_value_from_composit(v, indices);
end:
  dbglst.pop_back();
  return ret;
}

Value *get_value_from_composit(Value *cv, Indices &indices) {
  Indices i = Indices(indices);
  return _get_value_from_composit(cv, i);
}

/*
 * is this function's address taken?
 * ignore all use by EXPORT_SYMBOL and perf probe trace defs.
 */
bool is_address_taken(Function *f) {
  bool ret = false;
  for (auto &u : f->uses()) {
    auto *user = u.getUser();
    if (CallInst *ci = dyn_cast<CallInst>(user)) {
      // used inside inline asm?
      if (ci->isInlineAsm())
        continue;
      // used as direct call, or parameter inside llvm.*
      if (Function *_f = get_callee_function_direct(ci)) {
        if ((_f == f) || (_f->isIntrinsic()))
          continue;
        // used as function parameter
        ret = true;
        goto end;
      } else {
        // used as function parameter
        ret = true;
        goto end;
      }
      llvm_unreachable("should not reach here");
    }
    // not call instruction
    ValueList vs;
    ValueSet visited;
    vs.push_back(dyn_cast<Value>(user));
    while (vs.size()) {
      Value *v = vs.front();
      vs.pop_front();
      if (v->hasName()) {
        auto name = v->getName();
        if (name.startswith("__ksymtab") || name.startswith("trace_event") ||
            name.startswith("perf_trace") || name.startswith("trace_raw") ||
            name.startswith("llvm.") || name.startswith("event_class"))
          continue;
        ret = true;
        goto end;
      }
      for (auto &u : v->uses()) {
        auto *user = dyn_cast<Value>(u.getUser());
        if (!visited.count(user)) {
          visited.insert(user);
          vs.push_back(user);
        }
      }
    }
  }
end:
  return ret;
}

bool is_using_function_ptr(Function *f) {
  bool ret = false;
  for (Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi) {
    BasicBlock *bb = dyn_cast<BasicBlock>(fi);
    for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
         ++ii) {
      if (CallInst *ci = dyn_cast<CallInst>(ii)) {
        if (Function *f = get_callee_function_direct(ci)) {
          // should skip those...
          if (f->isIntrinsic())
            continue;
          // parameters have function pointer in it?
          for (auto &i : ci->arg_operands()) {
            // if (isa<Function>(i->stripPointerCasts()))
            if (PointerType *pty = dyn_cast<PointerType>(i->getType())) {
              if (isa<FunctionType>(pty->getElementType())) {
                ret = true;
                goto end;
              }
            }
          }
          // means that direct call is not using a function pointer
          // in the parameter
          continue;
        } else if (ci->isInlineAsm()) {
          // ignore inlineasm
          // InlineAsm* iasm = dyn_cast<InlinAsm>(ci->getCalledValue());
          continue;
        } else {
          ret = true;
          goto end;
        }
      }
      // any other use of function is considered using function pointer
      for (auto &i : ii->operands()) {
        // if (isa<Function>(i->stripPointerCasts()))
        if (PointerType *pty = dyn_cast<PointerType>(i->getType())) {
          if (isa<FunctionType>(pty->getElementType())) {
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
SimpleSet *skip_vars;
SimpleSet *skip_funcs;
SimpleSet *crit_syms;
SimpleSet *kernel_api;

void initialize_gatlin_sets(StringRef knob_skip_func_list,
                            StringRef knob_skip_var_list,
                            StringRef knob_crit_symbol,
                            StringRef knob_kernel_api) {
  llvm::errs() << "Load supplimental files...\n";
  StringList builtin_skip_functions(std::begin(_builtin_skip_functions),
                                    std::end(_builtin_skip_functions));
  skip_funcs = new SimpleSet(knob_skip_func_list, builtin_skip_functions);
  if (!skip_funcs->use_builtin())
    llvm::errs() << "    - Skip function list, total:" << skip_funcs->size()
                 << "\n";

  StringList builtin_skip_var(std::begin(_builtin_skip_var),
                              std::end(_builtin_skip_var));
  skip_vars = new SimpleSet(knob_skip_var_list, builtin_skip_var);
  if (!skip_vars->use_builtin())
    llvm::errs() << "    - Skip var list, total:" << skip_vars->size() << "\n";

  StringList builtin_crit_symbol;
  crit_syms = new SimpleSet(knob_crit_symbol, builtin_crit_symbol);
  if (!crit_syms->use_builtin())
    llvm::errs() << "    - Critical symbols, total:" << crit_syms->size()
                 << "\n";

  StringList builtin_kapi;
  kernel_api = new SimpleSet(knob_kernel_api, builtin_kapi);
  if (!kernel_api->use_builtin())
    llvm::errs() << "    - Kernel API list, total:" << kernel_api->size()
                 << "\n";
}

////////////////////////////////////////////////////////////////////////////////
void dump_callstack(InstructionList &callstk) {
  errs() << ANSI_COLOR_GREEN << "Call Stack:" << ANSI_COLOR_RESET << "\n";
  int cnt = 0;

  for (auto *I : callstk) {
    errs() << "" << cnt << " " << I->getFunction()->getName() << " ";
    I->getDebugLoc().print(errs());
    errs() << "\n";
    cnt++;
  }
  errs() << ANSI_COLOR_GREEN << "-------------" << ANSI_COLOR_RESET << "\n";
}

bool dump_a_path_worker(std::vector<BasicBlock *> &bbl, Function *f,
                        BasicBlockSet &visited) {
  BasicBlock *bb = bbl.back();
  if (bb == &f->getEntryBlock())
    return true;
  auto I = pred_begin(bb);
  auto E = pred_end(bb);
  for (; I != E; ++I) {
    if (visited.find(*I) != visited.end())
      continue;
    visited.insert(*I);
    bbl.push_back(*I);
    if (dump_a_path_worker(bbl, f, visited))
      return true;
    bbl.pop_back();
  }
  return false;
}

void dump_a_path(InstructionList &callstk) {
  errs() << ANSI_COLOR_GREEN << "Path: " << ANSI_COLOR_RESET << "\n";

  std::vector<std::vector<Instruction *>> ill;
  for (auto cI = callstk.rbegin(), E = callstk.rend(); cI != E; ++cI) {
    Instruction *I = *cI;
    BasicBlockSet visited;
    std::vector<BasicBlock *> bbl;
    std::vector<Instruction *> il;
    Function *f = I->getFunction();
    // errs()<<f->getName()<<":";
    // trace back till we reach the entry point of the function
    bbl.push_back(I->getParent());
    dump_a_path_worker(bbl, f, visited);
    // print instructions from ebb till the end
    for (auto bI = bbl.rbegin(), bE = bbl.rend(); bI != bE; ++bI) {
      BasicBlock *bb = *bI;
      for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
           ++ii) {
        Instruction *i = dyn_cast<Instruction>(ii);
        if (CallInst *ci = dyn_cast<CallInst>(ii))
          if (Function *cf = ci->getCalledFunction())
            if (cf->getName().startswith("llvm."))
              continue;
        il.push_back(i);
        // errs()<<f->getName()<<":";
        // i->print(errs());
        // errs()<<"\n";
        if (i == I)
          break;
      }
    }
    ill.push_back(il);
  }
  for (unsigned int i = 0; i < ill.size(); i++) {
    auto &il = ill[i];
    Function *f = il[0]->getFunction();
    auto fname = f->getName();
    errs() << "Function:" << fname << "\n";
    for (unsigned int j = 0; j < il.size(); j++) {
      il[j]->print(errs());
      errs() << "\n";
    }
  }
  errs() << ANSI_COLOR_GREEN << "-------------" << ANSI_COLOR_RESET << "\n";
}

void dump_dbgstk(InstructionList &dbgstk) {
  errs() << ANSI_COLOR_GREEN << "Process Stack:" << ANSI_COLOR_RESET << "\n";
  int cnt = 0;

  for (auto *I : dbgstk) {
    errs() << "" << cnt << " " << I->getFunction()->getName() << " ";
    I->getDebugLoc().print(errs());
    errs() << "\n";
    cnt++;
  }
  errs() << ANSI_COLOR_GREEN << "-------------" << ANSI_COLOR_RESET << "\n";
}

void dump_gdblst(ValueList &list) {
  errs() << ANSI_COLOR_GREEN << "Process List:" << ANSI_COLOR_RESET << "\n";
  int cnt = 0;
  for (auto *I : list) {
    errs() << "  " << cnt << ":";
    if (Function *f = dyn_cast<Function>(I))
      errs() << f->getName();
    else {
      I->print(errs());
      if (Instruction *i = dyn_cast<Instruction>(I)) {
        errs() << "  ";
        i->getDebugLoc().print(errs());
      }
    }
    errs() << "\n";
    cnt++;
  }
  errs() << ANSI_COLOR_GREEN << "-------------" << ANSI_COLOR_RESET << "\n";
}
