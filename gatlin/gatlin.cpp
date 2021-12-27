/*
 * PeX
 * Linux kernel permission check checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "gatlin.h"

// my aux headers
#include "color.h"
#include "stopwatch.h"
#include "utility.h"

#define TOTOAL_NUMBER_OF_STOP_WATCHES 2
#define WID_0 0
#define WID_KINIT 1
#define WID_CC 1
#define WID_PI 1

STOP_WATCH(TOTOAL_NUMBER_OF_STOP_WATCHES);

using namespace llvm;

#include "capstat.h"
#include "knobs.h"

#include "module_duplicator.h"

#include <mutex>
#include <pthread.h>
#include <thread>

char gatlin::ID;
Instruction *x_dbg_ins;
std::list<int> x_dbg_idx;

std::mutex x_lock;

////////////////////////////////////////////////////////////////////////////////

/*
 * deal with struct name alias
 */
void gatlin::find_in_mi2m(Type *t, ModuleSet &ms) {
  ms.clear();
  StructType *st = dyn_cast<StructType>(t);
  if (!st) {
    // t->print(errs());
    // errs()<<"\n";
    return;
  }
  assert(st);
  if (!st->hasName()) {
    if (mi2m.find(t) != mi2m.end())
      for (auto i : *mi2m[t])
        ms.insert(i);
    return;
  }
  // match using struct name
  auto name = std::string(t->getStructName());
  str_truncate_dot_number(name);
  for (auto msi : mi2m) {
    StructType *stype = dyn_cast<StructType>(msi.first);
    if (!stype->hasName())
      continue;
    auto struct_name = std::string(stype->getName());
    str_truncate_dot_number(struct_name);
    if (struct_name != name)
      continue;
    for (auto i : (*msi.second)) {
      ms.insert(i);
    }
  }
}
/*
 * interesting type which contains functions pointers to deal with user request
 */
bool gatlin::is_interesting_type(Type *ty) {
  if (!ty->isStructTy())
    return false;
  if (!dyn_cast<StructType>(ty)->hasName())
    return false;
  StringRef tyn = ty->getStructName();
  for (int i = 0; i < BUILTIN_INTERESTING_TYPE_WORD_LIST_SIZE; i++) {
    if (tyn.startswith(_builtin_interesting_type_word[i]))
      return true;
  }
  if (discovered_interesting_type.count(ty) != 0)
    return true;
  return false;
}
bool gatlin::_is_used_by_static_assign_to_interesting_type(
    Value *v, std::unordered_set<Value *> &duchain) {
  if (duchain.count(v))
    return false;
  duchain.insert(v);
  if (is_interesting_type(v->getType())) {
    duchain.erase(v);
    return true;
  }
  for (auto *u : v->users()) {
    if (isa<Instruction>(u))
      continue;
    if (_is_used_by_static_assign_to_interesting_type(u, duchain)) {
      duchain.erase(v);
      return true;
    }
  }
  duchain.erase(v);
  return false;
}

bool gatlin::is_used_by_static_assign_to_interesting_type(Value *v) {
  std::unordered_set<Value *> duchain;
  return _is_used_by_static_assign_to_interesting_type(v, duchain);
}

////////////////////////////////////////////////////////////////////////////////
/*
 * debug function
 */
void gatlin::dump_as_good(InstructionList &callstk) {
  if (!knob_dump_good_path)
    return;
  errs() << ANSI_COLOR_MAGENTA << "Use:";
  callstk.front()->getDebugLoc().print(errs());
  errs() << ANSI_COLOR_RESET;
  errs() << "\n"
         << ANSI_COLOR_GREEN << "=GOOD PATH=" << ANSI_COLOR_RESET << "\n";
  dump_callstack(callstk);
}

void gatlin::dump_as_bad(InstructionList &callstk) {
  if (!knob_dump_bad_path)
    return;
  errs() << ANSI_COLOR_MAGENTA << "Use:";
  callstk.front()->getDebugLoc().print(errs());
  errs() << ANSI_COLOR_RESET;
  errs() << "\n" << ANSI_COLOR_RED << "=BAD PATH=" << ANSI_COLOR_RESET << "\n";
  dump_callstack(callstk);
  dump_a_path(callstk);
}

void gatlin::dump_as_ignored(InstructionList &callstk) {
  if (!knob_dump_ignore_path)
    return;
  errs() << ANSI_COLOR_MAGENTA << "Use:";
  callstk.front()->getDebugLoc().print(errs());
  errs() << ANSI_COLOR_RESET;
  errs() << "\n"
         << ANSI_COLOR_YELLOW << "=IGNORE PATH=" << ANSI_COLOR_RESET << "\n";
  dump_callstack(callstk);
}

void gatlin::dump_v2ci() {
  if (!knob_gatlin_v2c)
    return;
  errs() << ANSI_COLOR(BG_BLUE, FG_WHITE)
         << "--- Variables Protected By Gating Function---" << ANSI_COLOR_RESET
         << "\n";
  for (auto &cis : v2ci) {
    Value *v = cis.first;
    errs() << ANSI_COLOR_GREEN << v->getName() << ANSI_COLOR_RESET << "\n";
    gating->dump_interesting(cis.second);
  }
}

void gatlin::dump_f2ci() {
  if (!knob_gatlin_f2c)
    return;
  errs() << ANSI_COLOR(BG_BLUE, FG_WHITE)
         << "--- Function Protected By Gating Function---" << ANSI_COLOR_RESET
         << "\n";
  for (auto &cis : f2ci) {
    Function *func = cis.first;
    errs() << ANSI_COLOR_GREEN << func->getName() << ANSI_COLOR_RESET << "\n";
    gating->dump_interesting(cis.second);
  }
}

/*
 * dump interesting type field and guarding checks
 */
void gatlin::dump_tf2ci() {
  if (!knob_gatlin_t2c)
    return;

  errs() << ANSI_COLOR(BG_CYAN, FG_WHITE)
         << "--- Interesting Type fields and checks ---" << ANSI_COLOR_RESET
         << "\n";
  for (auto &cis : t2ci) {
    StructType *t = dyn_cast<StructType>(cis.first);
    if (t->hasName())
      errs() << ANSI_COLOR_GREEN << t->getName();
    else
      errs() << ANSI_COLOR_RED << "AnnonymouseType";
    errs() << ":";
    std::unordered_set<int> &fields = critical_typefields[t];
    for (auto i : fields)
      errs() << i << ",";
    errs() << ANSI_COLOR_RESET << "\n";
    gating->dump_interesting(cis.second);
  }
}

void gatlin::dump_kinit() {
  if (!knob_gatlin_kinit)
    return;
  errs() << ANSI_COLOR(BG_BLUE, FG_WHITE)
         << "=Kernel Init Functions=" << ANSI_COLOR_RESET << "\n";
  for (auto I : kernel_init_functions) {
    errs() << I->getName() << "\n";
  }
  errs() << "=o=\n";
}

void gatlin::dump_non_kinit() {
  if (!knob_gatlin_nkinit)
    return;
  errs() << ANSI_COLOR(BG_BLUE, FG_WHITE)
         << "=NON-Kernel Init Functions=" << ANSI_COLOR_RESET << "\n";
  for (auto I : non_kernel_init_functions) {
    errs() << I->getName() << "\n";
  }
  errs() << "=o=\n";
}

void gatlin::dump_gating() {
  if (!knob_gatlin_caw)
    return;
  gating->dump();
}

void gatlin::dump_kmi() {
  if (!knob_gatlin_kmi)
    return;
  errs() << ANSI_COLOR(BG_BLUE, FG_WHITE)
         << "=Kernel Module Interfaces=" << ANSI_COLOR_RESET << "\n";
  for (auto msi : mi2m) {
    StructType *stype = dyn_cast<StructType>(msi.first);
    if (stype->hasName())
      errs() << ANSI_COLOR_RED << stype->getName() << ANSI_COLOR_RESET << "\n";
    else
      errs() << ANSI_COLOR_RED << "AnnonymouseType" << ANSI_COLOR_RESET << "\n";
    for (auto m : (*msi.second)) {
      if (m->hasName())
        errs() << "    " << ANSI_COLOR_CYAN << m->getName() << ANSI_COLOR_RESET
               << "\n";
      else
        errs() << "    " << ANSI_COLOR_CYAN << "Annoymous" << ANSI_COLOR_RESET
               << "\n";
    }
  }
  errs() << "=o=\n";
}

////////////////////////////////////////////////////////////////////////////////
/*
 * is this function type contains non-trivial(non-primary) type?
 */
bool gatlin::is_complex_type(Type *t) {
  if (!t->isFunctionTy())
    return false;
  if (t->isFunctionVarArg())
    return true;
  FunctionType *ft = dyn_cast<FunctionType>(t);
  // params
  int number_of_complex_type = 0;
  for (int i = 0; i < (int)ft->getNumParams(); i++) {
    Type *argt = ft->getParamType(i);
  strip_pointer:
    if (argt->isPointerTy()) {
      argt = argt->getPointerElementType();
      goto strip_pointer;
    }

    if (argt->isSingleValueType())
      continue;
    number_of_complex_type++;
  }
  // return type
  Type *rt = ft->getReturnType();

again: // to strip pointer
  if (rt->isPointerTy()) {
    Type *pet = rt->getPointerElementType();
    if (pet->isPointerTy()) {
      rt = pet;
      goto again;
    }
    if (!pet->isSingleValueType()) {
      number_of_complex_type++;
    }
  }

  return (number_of_complex_type != 0);
}

/*
 * def/use global?
 * take care of phi node using `visited'
 */
Value *gatlin::get_global_def(Value *val, ValueSet &visited) {
  if (visited.count(val) != 0)
    return NULL;
  visited.insert(val);
  if (isa<GlobalValue>(val))
    return val;
  if (Instruction *vali = dyn_cast<Instruction>(val)) {
    for (auto &U : vali->operands()) {
      Value *v = get_global_def(U, visited);
      if (v)
        return v;
    }
  } /*else if (Value* valv = dyn_cast<Value>(val))
   {
       //llvm_unreachable("how can this be ?");
   }*/
  return NULL;
}

Value *gatlin::get_global_def(Value *val) {
  ValueSet visited;
  return get_global_def(val, visited);
}

bool gatlin::is_rw_global(Value *val) {
  ValueSet visited;
  return get_global_def(val, visited) != NULL;
}

/*
 * is this functions part of the kernel init sequence?
 * if function f has single user which goes to start_kernel(),
 * then this is a init function
 */
bool gatlin::is_kernel_init_functions(Function *f, FunctionSet &visited) {
  if (kernel_init_functions.count(f) != 0)
    return true;
  if (non_kernel_init_functions.count(f) != 0)
    return false;

  // init functions with initcall prefix belongs to kernel init sequence
  if (function_has_gv_initcall_use(f)) {
    kernel_init_functions.insert(f);
    return true;
  }

  // not found in cache?
  // all path that can reach to f should start from start_kernel()
  // look backward(find who used f)
  FunctionList flist;
  for (auto *U : f->users())
    if (CallInst *cs = dyn_cast<CallInst>(U))
      flist.push_back(cs->getFunction());

  // no user?
  if (flist.size() == 0) {
    non_kernel_init_functions.insert(f);
    return false;
  }

  visited.insert(f);
  while (flist.size()) {
    Function *xf = flist.front();
    flist.pop_front();
    if (visited.count(xf))
      continue;
    visited.insert(xf);
    if (!is_kernel_init_functions(xf, visited)) {
      non_kernel_init_functions.insert(f);
      return false;
    }
  }
  kernel_init_functions.insert(f);
  return true;
}

bool gatlin::is_kernel_init_functions(Function *f) {
  FunctionSet visited;
  return is_kernel_init_functions(f, visited);
}

void gatlin::collect_kernel_init_functions(Module &module) {
  // kstart is the first function in boot sequence
  Function *kstart = NULL;
  // kernel init functions
  FunctionSet kinit_funcs;
  // Step 1: find kernel entry point
  errs() << "Finding Kernel Entry Point and all __initcall_\n";
  STOP_WATCH_START(WID_KINIT);
  for (Module::iterator fi = module.begin(), f_end = module.end(); fi != f_end;
       ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    StringRef fname = func->getName();
    if (fname.startswith("x86_64_start_kernel")) {
      errs() << ANSI_COLOR_GREEN << "Found " << func->getName()
             << ANSI_COLOR_RESET << "\n";
      kstart = func;
      kinit_funcs.insert(kstart);
      kernel_init_functions.insert(func);
    } else if (fname.startswith("start_kernel")) {
      // we should consider start_kernel as kernel init functions no
      // matter what
      kernel_init_functions.insert(func);
      kinit_funcs.insert(func);
      if (kstart == NULL)
        kstart = func;
      // everything calling start_kernel should be considered init
      // for (auto *U: func->users())
      //    if (Instruction *I = dyn_cast<Instruction>(U))
      //        kinit_funcs.insert(I->getFunction());
    } else {
      if (function_has_gv_initcall_use(func))
        kernel_init_functions.insert(func);
    }
  }
  // should always find kstart
  if (kstart == NULL) {
    errs()
        << ANSI_COLOR_RED
        << "kstart function not found, may affect precission, continue anyway\n"
        << ANSI_COLOR_RESET;
  }
  STOP_WATCH_STOP(WID_KINIT);
  STOP_WATCH_REPORT(WID_KINIT);

  errs() << "Initial Kernel Init Function Count:"
         << kernel_init_functions.size() << "\n";

  // Step 2: over approximate kernel init functions
  errs() << "Over Approximate Kernel Init Functions\n";
  STOP_WATCH_START(WID_KINIT);
  FunctionSet func_visited;
  FunctionSet func_work_set;
  for (auto f : kernel_init_functions)
    func_work_set.insert(f);

  while (func_work_set.size()) {
    Function *cfunc = *func_work_set.begin();
    func_work_set.erase(cfunc);

    if (cfunc->isDeclaration() || cfunc->isIntrinsic() || is_syscall(cfunc))
      continue;

    kinit_funcs.insert(cfunc);
    func_visited.insert(cfunc);
    kernel_init_functions.insert(cfunc);

    // explore call graph starting from this function
    for (Function::iterator fi = cfunc->begin(), fe = cfunc->end(); fi != fe;
         ++fi) {
      BasicBlock *bb = dyn_cast<BasicBlock>(fi);
      for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
           ++ii) {
        CallInst *ci = dyn_cast<CallInst>(ii);
        if ((!ci) || (ci->isInlineAsm()))
          continue;
        if (Function *nf = get_callee_function_direct(ci)) {
          if (nf->isDeclaration() || nf->isIntrinsic() ||
              func_visited.count(nf) || is_syscall(nf))
            continue;
          func_work_set.insert(nf);
        } else {
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

  errs() << "Refine Result\n";
  STOP_WATCH_START(WID_KINIT);
  /*
   * ! BUG: query use of inlined function result in in-accurate result?
   * inlined foo();
   * bar(){zoo()} zoo(){foo};
   *
   * query user{foo()} -> zoo()
   * query BasicBlocks in bar -> got call instruction in bar()?
   */
  // remove all non_kernel_init_functions from kernel_init_functions
  // purge all over approximation
  int last_count = 0;

again:
  for (auto f : kinit_funcs) {
    if ((f->getName() == "start_kernel") ||
        (f->getName() == "x86_64_start_kernel") ||
        function_has_gv_initcall_use(f))
      continue;
    for (auto *U : f->users()) {
      CallInstSet cil;
      get_callsite_inst(U, cil);
      bool should_break = false;
      for (auto cs : cil) {
        if (kinit_funcs.count(cs->getFunction()) == 0) {
          // means that we have a user does not belong to kernel init functions
          // we need to remove it
          non_kernel_init_functions.insert(f);
          should_break = true;
          break;
        }
      }
      if (should_break)
        break;
    }
  }
  for (auto f : non_kernel_init_functions) {
    kernel_init_functions.erase(f);
    kinit_funcs.erase(f);
  }

  if (last_count != (int)non_kernel_init_functions.size()) {
    last_count = non_kernel_init_functions.size();
    static int refine_pass = 0;
    errs() << "refine pass " << refine_pass << " "
           << kernel_init_functions.size() << " left\n";
    refine_pass++;
    goto again;
  }

  errs() << " Refine result : count=" << kernel_init_functions.size() << "\n";
  STOP_WATCH_STOP(WID_KINIT);
  STOP_WATCH_REPORT(WID_KINIT);

  dump_kinit();
}

////////////////////////////////////////////////////////////////////////////////
/*
 * resolve indirect callee
 * method 1 suffers from accuracy issue
 * method 2 is too slow
 * method 3 use the fact that most indirect call use function pointer loaded
 *          from struct(mi2m, kernel interface)
 */
FunctionSet gatlin::resolve_indirect_callee_ldcst_kmi(CallInst *ci, int &err,
                                                      int &kmi_cnt,
                                                      int &dkmi_cnt) {
  FunctionSet fs;
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  // non-gep case. loading from bitcasted struct address
  if (StructType *ldbcstty = identify_ld_bcst_struct(cv)) {
#if 0
        errs()<<"Found ld+bitcast sty to ptrty:";
        if (ldbcstty->isLiteral())
            errs()<<"Literal, ";
        else
            errs()<<ldbcstty->getName()<<", ";
#endif
    // dump_kmi_info(ci);
    Indices indices;
    indices.push_back(0);
    err = 2; // got type
    // match - kmi
    ModuleSet ms;
    find_in_mi2m(ldbcstty, ms);
    if (ms.size()) {
      err = 1; // found module object
      for (auto m : ms)
        if (Value *v = get_value_from_composit(m, indices)) {
          Function *f = dyn_cast<Function>(v);
          assert(f);
          fs.insert(f);
        }
    }
    if (fs.size() != 0) {
      kmi_cnt++;
      goto end;
    }
    // match - dkmi
    if (dmi_type_exists(ldbcstty, dmi))
      err = 1;

    indices.clear();
    indices.push_back(0);
    indices.push_back(0);
    if (FunctionSet *_fs = dmi_exists(ldbcstty, indices, dmi)) {
      for (auto *f : *_fs)
        fs.insert(f);
      dkmi_cnt++;
      goto end;
    }
#if 0
        errs()<<"Try rkmi\n";
#endif
  }
end:
  if (fs.size())
    err = 0;
  return fs;
}

// method 3, improved accuracy
FunctionSet gatlin::resolve_indirect_callee_using_kmi(CallInst *ci, int &err) {
  FunctionSet fs;
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  err = 6;
  // GEP case.
  // need to find till gep is exhausted and mi2m doesn't have a match
  InstructionSet geps = get_load_from_gep(cv);
  for (auto _gep : geps) {
    GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(_gep);
    Type *cvt =
        dyn_cast<PointerType>(gep->getPointerOperandType())->getElementType();
    if (!cvt->isAggregateType())
      continue;

    Indices indices;
    x_dbg_ins = gep;
    get_gep_indicies(gep, indices);
    x_dbg_idx = indices;
    assert(indices.size() != 0);
    // should remove first element because it is an array index
    // the actual match
    indices.pop_front();
    while (1) {
      if (err > 2)
        err = 2; // found the type, going to match module
      ModuleSet ms;
      find_in_mi2m(cvt, ms);
      if (ms.size()) {
        if (err > 1)
          err = 1; // found matching module
        for (auto m : ms) {
          Value *v = get_value_from_composit(m, indices);
          if (v == NULL) {
            /*
             * NOTE: some of the method may not be implemented
             *       it is ok to ignore them
             * for example: .release method in
             *      struct tcp_congestion_ops
             */
#if 0
                        errs()<<m->getName();
                        errs()<<" - can not get value from composit [ ";
                        for (auto i: indices)
                            errs()<<","<<i;
                        errs()<<"], this method may not implemented yet.\n";
#endif
            continue;
          }
          Function *f = dyn_cast<Function>(v);
          assert(f);
          fs.insert(f);
        }
        break;
      }
      // not found in mi2m
      if (indices.size() <= 1) {
        // no match! we are also done here, mark it as resolved anyway
        // this object may be dynamically allocated,
        // try dkmi if possible
#if 0
                errs()<<" MIDC err, try DKMI\n";
                cvt = get_load_from_type(cv);
                errs()<<"!!!  : ";
                cvt->print(errs());
                errs()<<"\n";
                
                errs()<<"idcs:";
                for (auto i: x_dbg_idx)
                    errs()<<","<<i;
                errs()<<"\n";
                //gep->print(errs());
                errs()<<"\n";
#endif
        break;
      }
      // no match, we can try inner element
      // deal with array of struct here
      Type *ncvt;
      if (ArrayType *aty = dyn_cast<ArrayType>(cvt)) {
        ncvt = aty->getElementType();
        // need to remove another one index
        indices.pop_front();
      } else {
        int idc = indices.front();
        indices.pop_front();
        if (!cvt->isStructTy()) {
          cvt->print(errs());
          llvm_unreachable("!!!1");
        }
        ncvt = cvt->getStructElementType(idc);
        // FIXME! is this correct?
        if (PointerType *pty = dyn_cast<PointerType>(ncvt)) {
          ncvt = pty->getElementType();
          llvm_unreachable("can't be a pointer!");
        }

        // cvt should be aggregated type!
        if (!ncvt->isAggregateType()) {
          /* bad cast!!!
           * struct sk_buff { cb[48] }
           * XFRM_TRANS_SKB_CB(__skb) ((struct xfrm_trans_cb
           * *)&((__skb)->cb[0]))
           */
          // errs()<<"Can not resolve\n";
          // x_dbg_ins->getDebugLoc().print(errs());
          // errs()<<"\n";
          errs() << ANSI_COLOR_RED << "Bad cast from type:" << ANSI_COLOR_RESET;
          ncvt->print(errs());
          errs() << " we can not resolve this\n";
          // dump_kmi_info(ci);
          // llvm_unreachable("NOT POSSIBLE!");
          err = 5;
          break;
        }
      }
      cvt = ncvt;
    }
  }
  if (fs.size() == 0) {
    if (!isa<Instruction>(cv))
      err = 3;
    else if (load_from_global_fptr(cv))
      err = 4;
  } else
    err = 0;
  return fs;
}

/*
 * this is also kmi, but dynamic one
 */
FunctionSet gatlin::resolve_indirect_callee_using_dkmi(CallInst *ci, int &err) {
  FunctionSet fs;
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  InstructionSet geps = get_load_from_gep(cv);

  err = 6;
  for (auto *_gep : geps) {
    GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(_gep);
    Type *cvt =
        dyn_cast<PointerType>(gep->getPointerOperandType())->getElementType();
    if (!cvt->isAggregateType())
      continue;

    Indices indices;
    // need to find till gep is exhausted and mi2m doesn't have a match
    x_dbg_ins = gep;
    get_gep_indicies(gep, indices);
    x_dbg_idx = indices;
    assert(indices.size() != 0);
    // dig till we are at struct type
    while (1) {
      if (isa<StructType>(cvt))
        break;
      // must be an array
      if (ArrayType *aty = dyn_cast<ArrayType>(cvt)) {
        cvt = aty->getElementType();
        // need to remove another one index
        indices.pop_front();
      } else {
        // no struct inside it and all of them are array?
#if 0
                errs()<<"All array?:";
                cvt->print(errs());
                errs()<<"\n";
#endif
        break;
      }
    }
    if (!dyn_cast<StructType>(cvt))
      continue;
    if (err > 2)
      err = 2;
    if (dmi_type_exists(dyn_cast<StructType>(cvt), dmi) && (err > 1))
      err = 1;
    // OK. now we match through struct type and indices
    if (FunctionSet *_fs =
            dmi_exists(dyn_cast<StructType>(cvt), indices, dmi)) {
      // TODO:iteratively explore basic element type if current one is not found
      if (_fs->size() == 0) {
        // dump_kmi_info(ci);
        errs() << "uk-idcs:";
        if (!dyn_cast<StructType>(cvt)->isLiteral())
          errs() << cvt->getStructName();
        errs() << " [";
        for (auto i : x_dbg_idx)
          errs() << "," << i;
        errs() << "]\n";
      }
      // merge _fs into fs
      for (auto *f : *_fs)
        fs.insert(f);
    }
  }
  if (fs.size())
    err = 0;
  return fs;
}

bool gatlin::load_from_global_fptr(Value *cv) {
  ValueList worklist;
  ValueSet visited;
  worklist.push_back(cv);
  int cnt = 0;
  while (worklist.size() && (cnt++ < 5)) {
    Value *v = worklist.front();
    worklist.pop_front();
    if (visited.count(v))
      continue;
    visited.insert(v);

    if (isa<GlobalVariable>(v))
      return true;

    if (isa<Function>(v) || isa<GetElementPtrInst>(v) || isa<CallInst>(v))
      continue;

    if (LoadInst *li = dyn_cast<LoadInst>(v)) {
      worklist.push_back(li->getPointerOperand());
      continue;
    }
    if (SelectInst *sli = dyn_cast<SelectInst>(v)) {
      worklist.push_back(sli->getTrueValue());
      worklist.push_back(sli->getFalseValue());
      continue;
    }
    if (PHINode *phi = dyn_cast<PHINode>(v)) {
      for (unsigned int i = 0; i < phi->getNumIncomingValues(); i++)
        worklist.push_back(phi->getIncomingValue(i));
      continue;
    }
    // instruction
    if (Instruction *i = dyn_cast<Instruction>(v))
      for (unsigned int j = 0; j < i->getNumOperands(); j++)
        worklist.push_back(i->getOperand(j));
    // constant value
    if (ConstantExpr *cxpr = dyn_cast<ConstantExpr>(v))
      worklist.push_back(cxpr->getAsInstruction());
  }
  return false;
}

void gatlin::dump_kmi_info(CallInst *ci) {
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  ValueList worklist;
  ValueSet visited;
  worklist.push_back(cv);
  int cnt = 0;
  ci->print(errs());
  errs() << "\n";
  while (worklist.size() && (cnt++ < 5)) {
    Value *v = worklist.front();
    worklist.pop_front();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (isa<Function>(v))
      errs() << v->getName();
    else
      v->print(errs());
    errs() << "\n";
    if (LoadInst *li = dyn_cast<LoadInst>(v)) {
      worklist.push_back(li->getPointerOperand());
      continue;
    }
    if (SelectInst *sli = dyn_cast<SelectInst>(v)) {
      worklist.push_back(sli->getTrueValue());
      worklist.push_back(sli->getFalseValue());
      continue;
    }
    if (PHINode *phi = dyn_cast<PHINode>(v)) {
      for (unsigned int i = 0; i < phi->getNumIncomingValues(); i++)
        worklist.push_back(phi->getIncomingValue(i));
      continue;
    }
    if (isa<CallInst>(v))
      continue;
    if (Instruction *i = dyn_cast<Instruction>(v))
      for (unsigned int j = 0; j < i->getNumOperands(); j++)
        worklist.push_back(i->getOperand(j));
  }
}

/*
 * create mapping for
 *  indirect call site -> callee
 *  callee -> indirect call site
 */
void gatlin::populate_indcall_list_through_kmi(Module &module) {
  // indirect call is load+gep and can be found in mi2m?
  int count = 0;
  int targets = 0;
  int fpar_cnt = 0;
  int gptr_cnt = 0;
  int cast_cnt = 0;
  int container_of_cnt = 0;
  ;
  int undefined_1 = 0;
  int undefined_2 = 0;
  int unknown = 0;
  int kmi_cnt = 0;
  int dkmi_cnt = 0;
#if 0
    errs()<<ANSI_COLOR(BG_WHITE,FG_GREEN)
        <<"indirect callsite, match"
        <<ANSI_COLOR_RESET<<"\n";
#endif
  for (auto *idc : idcs) {
#if (LLVM_VERSION_MAJOR <= 10)
    Value *idcv = idc->getCalledValue();
#else
    Value *idcv = idc->getCalledOperand();
#endif
#if 0
        errs()<<ANSI_COLOR_YELLOW<<" * ";
        idc->getDebugLoc().print(errs());
        errs()<<ANSI_COLOR_RESET<<"";
#endif
    // is this a trace point?
    // special condition, ignore tracepoint, we are not interested in them.
    if (is_tracepoint_func(idcv)) {
      count++;
      targets++;
      kmi_cnt++;
#if 0
            errs()<<" [tracepoint]\n";
#endif
      continue;
    }
    if (is_container_of(idcv)) {
      container_of_cnt++;
#if 0
            errs()<<" [container_of]\n";
#endif
      continue;
    }

    // try kmi
    // err - 0 no error
    //    - 1 undefined fptr in module, mark as resolved
    //    - 2 undefined module, mark as resolved(ok to fail)
    //    - 3 fptr comes from function parameter
    //    - 4 fptr comes from global fptr
    //    - 5 bad cast
    //    - 6 max error code- this is the bound
    int err = 6;
    // we resolved type and there's a matching object, but no fptr defined
    bool found_module = false;
    // we resolved type but there's no matching object
    bool udf_module = false;
    FunctionSet fs =
        resolve_indirect_callee_ldcst_kmi(idc, err, kmi_cnt, dkmi_cnt);
    if (err < 2)
      found_module = true;
    else if (err == 2)
      udf_module = true;

    if (fs.size() != 0) {
#if 0
            errs()<<" [LDCST-KMI]\n";
#endif
      goto resolved;
    }
    fs = resolve_indirect_callee_using_kmi(idc, err);
    if (err < 2)
      found_module = true;
    else if (err == 2)
      udf_module = true;

    if (fs.size() != 0) {
#if 0
            errs()<<" [KMI]\n";
#endif
      kmi_cnt++;
      goto resolved;
    }
    // using a fptr not implemented yet
    switch (err) {
    case (6):
    case (0): {
      goto unresolvable;
    }
    case (1):
    case (2): // try dkmi
    {
      // try dkmi
      break;
    }
    case (3): {
      // function parameter, unable to be solved by kmi and dkmi, try SVF
      fpar_cnt++;
      goto unresolvable;
    }
    case (4): {
      gptr_cnt++;
      goto unresolvable;
    }
    case (5): {
      cast_cnt++;
      goto unresolvable;
    }
    default:
      llvm_unreachable("no way!");
    }
    // try dkmi
    fs = resolve_indirect_callee_using_dkmi(idc, err);
    if (err < 2)
      found_module = true;
    else if (err == 2)
      udf_module = true;

    if (fs.size() != 0) {
#if 0
            errs()<<" [DKMI]\n";
#endif
      dkmi_cnt++;
      goto resolved;
    }
    if (found_module) {
#if 0
                errs()<<" [UNDEFINED1-found-m]\n";
#endif
      count++;
      targets++;
      undefined_1++;
      // dump_kmi_info(idc);
      continue;
    }
    if (udf_module) {
#if 0
            errs()<<" [UNDEFINED2-udf-m]\n";
#endif
      count++;
      targets++;
      undefined_2++;
      // dump_kmi_info(idc);
      continue;
    }
  unresolvable:
    // can not resolve
    fuidcs.insert(idc->getFunction());
    switch (err) {
    case (3): {
      // function parameter
#if 0
                errs()<<" [UPARA]\n";
#endif
      break;
    }
    case (4): {
      // global fptr
#if 0
                errs()<<" [GFPTR]\n";
#endif
      break;
    }
    case (5): {
#if 0
                errs()<<" [BAD CAST]\n";
#endif
      break;
    }
    default: {
#if 0
                errs()<<" [UNKNOWN]\n";
#endif
      unknown++;
      // dump the struct
      // dump_kmi_info(idc);
    }
    }
    continue;
  resolved:
    count++;
    targets += fs.size();
    FunctionSet *funcs = idcs2callee[idc];
    if (funcs == NULL) {
      funcs = new FunctionSet;
      idcs2callee[idc] = funcs;
    }
    for (auto f : fs) {
#if 0
            errs()<<"     - "<<f->getName()<<"\n";
#endif
      funcs->insert(f);
      InstructionSet *csis = f2csi_type1[f];
      if (csis == NULL) {
        csis = new InstructionSet;
        f2csi_type1[f] = csis;
      }
      csis->insert(idc);
    }
  }
  errs() << ANSI_COLOR(BG_WHITE, FG_RED) << "------ KMI STATISTICS ------"
         << ANSI_COLOR_RESET "\n";
  errs() << "# of indirect call sites: " << idcs.size() << "\n";
  errs() << "# resolved by KMI:" << count << " " << (100 * count / idcs.size())
         << "%\n";
  errs() << "#     - KMI:" << kmi_cnt << " " << (100 * kmi_cnt / idcs.size())
         << "%\n";
  errs() << "#     - DKMI:" << dkmi_cnt << " " << (100 * dkmi_cnt / idcs.size())
         << "%\n";
  errs() << "# (total target) of callee:" << targets << "\n";
  errs() << "# undefined-found-m : " << undefined_1 << " "
         << (100 * undefined_1 / idcs.size()) << "%\n";
  errs() << "# undefined-udf-m : " << undefined_2 << " "
         << (100 * undefined_2 / idcs.size()) << "%\n";
  errs() << "# fpara(KMI can not handle, try SVF?): " << fpar_cnt << " "
         << (100 * fpar_cnt / idcs.size()) << "%\n";
  errs() << "# global fptr(try SVF?): " << gptr_cnt << " "
         << (100 * gptr_cnt / idcs.size()) << "%\n";
  errs() << "# cast fptr(try SVF?): " << cast_cnt << " "
         << (100 * cast_cnt / idcs.size()) << "%\n";
  errs() << "# call use container_of(), high level type info stripped: "
         << container_of_cnt << " " << (100 * container_of_cnt / idcs.size())
         << "%\n";
  errs() << "# unknown pattern:" << unknown << " "
         << (100 * unknown / idcs.size()) << "%\n";
  // exit(0);
}

/*
 * need to populate idcs2callee before calling this function
 * should not call into this function using direct call
 */
FunctionSet gatlin::resolve_indirect_callee(CallInst *ci) {
  FunctionSet fs;
  if (ci->isInlineAsm())
    return fs;
  if (get_callee_function_direct(ci))
    llvm_unreachable("resolved into direct call!");

  auto _fs = idcs2callee.find(ci);
  if (_fs != idcs2callee.end()) {
    for (auto *f : *(_fs->second))
      fs.insert(f);
  }

#if 0
    //FUZZY MATCHING
    //method 1: signature based matching
    //only allow precise match when collecting protected functions
        Value* cv = ci->getCalledValue();
        Type *ft = cv->getType()->getPointerElementType();
        if (!is_complex_type(ft))
            return fs;
        if (t2fs.find(ft)==t2fs.end())
            return fs;
        FunctionSet *fl = t2fs[ft];
        for (auto* f: *fl)
            fs.insert(f);
#endif
  return fs;
}
////////////////////////////////////////////////////////////////////////////////

/*
 * collect all gating function callsite
 * ----
 * f2chks: Function to Gating Function CallSite
 */
void gatlin::collect_chkps(Module &module) {
  for (auto func : all_functions) {
    if (gating->is_gating_function(func))
      continue;

    InstructionSet *chks = f2chks[func];
    if (!chks) {
      chks = new InstructionSet();
      f2chks[func] = chks;
    }

    for (Function::iterator fi = func->begin(), fe = func->end(); fi != fe;
         ++fi) {
      BasicBlock *bb = dyn_cast<BasicBlock>(fi);
      for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
           ++ii) {
        if (CallInst *ci = dyn_cast<CallInst>(ii))
          if (Function *_f = get_callee_function_direct(ci)) {
            if (gating->is_gating_function(_f))
              chks->insert(ci);
          }
      }
    }
  }
#if 0
    //dump all checks
    for(auto& pair: f2chks)
    {
        ValueSet visited;
        Function* f = pair.first;
        InstructionSet* chkins = pair.second;
        if (chkins->size()==0)
            continue;
        gating->dump_interesting(chkins);
    }
#endif
}

/*
 * track user of functions which have checks, and see whether it is tied
 * to any interesting type(struct)
 */
Value *find_struct_use(Value *f, ValueSet &visited) {
  if (visited.count(f))
    return NULL;
  visited.insert(f);
  for (auto *u : f->users()) {
    if (u->getType()->isStructTy())
      return u;
    if (Value *_u = find_struct_use(u, visited))
      return _u;
  }
  return NULL;
}

void gatlin::identify_interesting_struct(Module &module) {
  // first... functions which have checks in them
  for (auto &pair : f2chks) {
    ValueSet visited;
    Function *f = pair.first;
    InstructionSet *chkins = pair.second;
    if (chkins->size() == 0)
      continue;
    if (Value *u = find_struct_use(f, visited)) {
      StructType *type = dyn_cast<StructType>(u->getType());
      if (!type->hasName())
        continue;
      // should always skip this
      if (type->getStructName().startswith("struct.kernel_symbol"))
        continue;
      bool already_exists = is_interesting_type(type);
      errs() << "Function: " << f->getName() << " used by ";
      if (!already_exists)
        errs() << ANSI_COLOR_GREEN << " new discover:";
      if (type->getStructName().size() == 0)
        errs() << ANSI_COLOR_RED << "Annonymouse Type";
      else
        errs() << type->getStructName();
      errs() << ANSI_COLOR_RESET << "\n";
      discovered_interesting_type.insert(type);
    }
  }
#if 0
    //second... all functions
    for (auto f: all_functions)
    {
        ValueSet visited;
        if (Value* u = find_struct_use(f, visited))
        {
            StructType* type = dyn_cast<StructType>(u->getType());
            if (type->isLiteral())
                continue;
            if (!type->hasName())
                continue;
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
#endif
  // sort functions
  for (auto f : all_functions) {
    StringRef fname = f->getName();
    if (fname.startswith("trace_event") || fname.startswith("perf_trace") ||
        fname.startswith("trace_raw")) {
      trace_event_funcs.insert(f);
      continue;
    }
    if (fname.startswith("bpf") || fname.startswith("__bpf") ||
        fname.startswith("___bpf")) {
      bpf_funcs.insert(f);
      continue;
    }
    if (fname.startswith("irq")) {
      irq_funcs.insert(f);
      continue;
    }

    ValueSet visited;
    Value *u = find_struct_use(f, visited);
    if (u) {
      bool skip = false;
      for (Value *v : visited)
        if (isa<Instruction>(v)) {
          assert("this is impossible\n");
          skip = true;
          break;
        }
      if (!skip)
        kmi_funcs.insert(f);
    }
  }
}

/*
 * this is used to identify any assignment of fptr to struct field, and we
 * collect this in complementary of identify_kmi
 */
void gatlin::identify_dynamic_kmi(Module &module) {
  int cnt_resolved = 0;
  for (auto *f : all_functions) {
    Value *v = dyn_cast<Value>(f);
    Indices inds;
    ValueSet visited;
    StructType *t = find_assignment_to_struct_type(v, inds, visited);
    if (!t)
      continue;
    // Great! we got one! merge to know list or creat new

    cnt_resolved++;
    add_function_to_dmi(f, t, inds, dmi);
  }
  errs() << "#dyn kmi resolved:" << cnt_resolved << "\n";
}

void gatlin::dump_dkmi() {
  if (!knob_gatlin_dkmi)
    return;
  errs() << ANSI_COLOR(BG_WHITE, FG_CYAN) << "=dynamic KMI=" << ANSI_COLOR_RESET
         << "\n";
  for (auto tp : dmi) {
    // type to metadata mapping
    StructType *t = tp.first;
    errs() << "Type:";
    if (t->isLiteral())
      errs() << "Literal\n";
    else
      errs() << t->getStructName() << "\n";
    // here comes the pairs
    IFPairs *ifps = tp.second;
    for (auto ifp : *ifps) {
      // indicies
      Indices *idcs = ifp->first;
      FunctionSet *fset = ifp->second;
      errs() << "  @ [";
      for (auto i : *idcs) {
        errs() << i << ",";
      }
      errs() << "]\n";
      // function names
      for (Function *f : *fset) {
        errs() << "        - ";
        errs() << f->getName();
        errs() << "\n";
      }
    }
  }
  errs() << "\n";
}

/*
 * identify logical kernel module
 * kernel module usually connect its functions to a struct that can be called
 * by upper layer
 * collect all global struct variable who have function pointer field
 */
void gatlin::identify_kmi(Module &module) {
  // Module::GlobalListType &globals = module.getGlobalList();
  // not an interesting type, no function ptr inside this struct
  TypeSet nomo;
  for (GlobalVariable &gvi : module.globals()) {
    GlobalVariable *gi = &gvi;
    if (gi->isDeclaration())
      continue;
    assert(isa<Value>(gi));

    StringRef gvn = gi->getName();
    if (gvn.startswith("__kstrtab") || gvn.startswith("__tpstrtab") ||
        gvn.startswith(".str") || gvn.startswith("llvm.") ||
        gvn.startswith("__setup_str"))
      continue;

    Type *mod_interface = gi->getType();

    if (mod_interface->isPointerTy())
      mod_interface = mod_interface->getPointerElementType();
    if (!mod_interface->isAggregateType())
      continue;
    if (mod_interface->isArrayTy()) {
#if (LLVM_VERSION_MAJOR <= 10)
      mod_interface = dyn_cast<ArrayType>(mod_interface)->getTypeAtIndex(0u);
#else
      mod_interface = dyn_cast<ArrayType>(mod_interface)->getElementType();
#endif
    }
    if (!mod_interface->isStructTy()) {
      if (mod_interface->isFirstClassType())
        continue;
      // report any non-first class type
      errs() << "IDKMI: aggregate type not struct?\n";
      mod_interface->print(errs());
      errs() << "\n";
      errs() << gi->getName() << "\n";
      continue;
    }
    if (nomo.find(mod_interface) != nomo.end())
      continue;
    // function pointer inside struct?
    if (!has_function_pointer_type(mod_interface)) {
      nomo.insert(mod_interface);
      continue;
    }
    // add
    ModuleSet *ms;
    if (mi2m.find(mod_interface) != mi2m.end()) {
      ms = mi2m[mod_interface];
    } else {
      ms = new ModuleSet;
      mi2m[mod_interface] = ms;
    }
    assert(ms);
    ms->insert(gi);
    // if (array_type)
    //    errs()<<"Added ArrayType:"<<gvn<<"\n";
  }
  TypeList to_remove;
  ModuleInterface2Modules to_add;
  // resolve Annoymous type into known type
  for (auto msi : mi2m) {
    StructType *stype = dyn_cast<StructType>(msi.first);
    if (stype->hasName())
      continue;
    StructType *rstype = NULL;
    assert(msi.second);
    for (auto m : (*msi.second)) {
      // constant bitcast into struct
      for (auto *_u : m->users()) {
        ConstantExpr *u = dyn_cast<ConstantExpr>(_u);
        BitCastInst *bciu = dyn_cast<BitCastInst>(_u);
        PointerType *type = NULL;
        if ((u) && (u->isCast())) {
          type = dyn_cast<PointerType>(u->getType());
          goto got_bitcast;
        }
        if (bciu) {
          type = dyn_cast<PointerType>(bciu->getType());
          goto got_bitcast;
        }
        // what else???
        continue;
      got_bitcast:
        // struct object casted into non pointer type?
        if (type == NULL)
          continue;
        StructType *_stype = dyn_cast<StructType>(type->getElementType());
        if ((!_stype) || (!_stype->hasName()))
          continue;
        rstype = _stype;
        goto out;
      }
    }
  out:
    if (!rstype)
      continue;
    // resolved, merge with existing type
    if (mi2m.find(rstype) != mi2m.end()) {
      ModuleSet *ms = mi2m[rstype];
      for (auto m : (*msi.second))
        ms->insert(m);
    } else if (to_add.find(rstype) != to_add.end()) {
      ModuleSet *ms = to_add[rstype];
      for (auto m : (*msi.second))
        ms->insert(m);
    } else {
      // does not exists? reuse current one!
      to_add[rstype] = msi.second;
      /*
       * this should not cause crash as we already parsed current element
       * and this should be set to NULL in order to not be deleted later
       */
      mi2m[stype] = NULL;
    }
    to_remove.push_back(stype);
  }
  for (auto r : to_remove) {
    delete mi2m[r];
    mi2m.erase(r);
  }
  for (auto r : to_add)
    mi2m[r.first] = r.second;
}

/*
 * populate cache
 * --------------
 * all_functions
 * t2fs(Type to FunctionSet)
 * syscall_list
 * f2csi_type0 (Function to BitCast CallSite)
 * idcs(indirect call site)
 */
void gatlin::preprocess(Module &module) {
  for (Module::iterator fi = module.begin(), f_end = module.end(); fi != f_end;
       ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (func->isDeclaration()) {
      ExternalFuncCounter++;
      continue;
    }
    if (func->isIntrinsic())
      continue;

    FuncCounter++;

    all_functions.insert(func);
    Type *type = func->getFunctionType();
    FunctionSet *fl = t2fs[type];
    if (fl == NULL) {
      fl = new FunctionSet;
      t2fs[type] = fl;
    }
    fl->insert(func);

    if (is_syscall_prefix(func->getName()))
      syscall_list.insert(func);

    for (Function::iterator fi = func->begin(), fe = func->end(); fi != fe;
         ++fi) {
      BasicBlock *bb = dyn_cast<BasicBlock>(fi);
      for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
           ++ii) {
        CallInst *ci = dyn_cast<CallInst>(ii);
        if (!ci || ci->getCalledFunction() || ci->isInlineAsm())
          continue;

#if (LLVM_VERSION_MAJOR <= 10)
        Value *cv = ci->getCalledValue();
#else
        Value *cv = ci->getCalledOperand();
#endif
        Function *bcf = dyn_cast<Function>(cv->stripPointerCasts());
        if (bcf) {
          // this is actually a direct call with function type cast
          InstructionSet *csis = f2csi_type0[bcf];
          if (csis == NULL) {
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

/*
 * collect critical resources
 */
void gatlin::collect_crits(Module &module) {
  for (auto pair : f2chks) {
    Function *func = pair.first;
    InstructionSet *_chks = pair.second;
    if ((_chks == NULL) || (_chks->size() == 0) ||
        gating->is_gating_function(func) || is_skip_function(func->getName())) {
      continue;
    }
    dbgstk.push_back(func->getEntryBlock().getFirstNonPHI());
    InstructionList callgraph;
    InstructionList chks;
    forward_all_interesting_usage(func->getEntryBlock().getFirstNonPHI(), 0,
                                  false, callgraph, chks);
    dbgstk.pop_back();
  }

  CRITFUNC = critical_functions.size();
  CRITVAR = critical_variables.size();
  CritFuncSkip = skipped_functions.size();
  errs() << "Critical functions skipped because of skip func list: "
         << CritFuncSkip << "\n";
}

/*
 * discover checks inside functions f, including checks inside other callee
 * this is shared across all workers.
 */
pthread_rwlock_t dc_lock;

InstructionSet *gatlin::discover_chks(Function *f, FunctionSet &visited) {
  InstructionSet *ret = NULL;
  if (visited.count(f)) {
    pthread_rwlock_rdlock(&dc_lock);
    if (f2chks_disc.count(f))
      ret = f2chks_disc[f];
    pthread_rwlock_unlock(&dc_lock);
    return ret;
  }
  visited.insert(f);

  ret = new InstructionSet;

  // any direct check
  if (InstructionSet *chks = f2chks[f])
    for (auto *i : *chks)
      ret->insert(i);

  // indirect check
  for (Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi) {
    BasicBlock *bb = dyn_cast<BasicBlock>(fi);
    for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
         ++ii) {
      CallInst *ci = dyn_cast<CallInst>(ii);
      if (!ci)
        continue;
      if (ci->isInlineAsm())
        continue;

      Function *nextf = get_callee_function_direct(ci);
      if (!nextf) // ignore all indirect call
        continue;
      if (InstructionSet *r = discover_chks(nextf, visited))
        if (r->size())
          ret->insert(ci);
    }
  }
  pthread_rwlock_wrlock(&dc_lock);
  if (f2chks_disc.count(f) == 0) {
    f2chks_disc[f] = ret;
  } else {
    delete ret;
    ret = f2chks_disc[f];
  }
  pthread_rwlock_unlock(&dc_lock);
  return ret;
}

InstructionSet *gatlin::discover_chks(Function *f) {
  pthread_rwlock_rdlock(&dc_lock);
  if (f2chks_disc.count(f) != 0) {
    InstructionSet *ret = f2chks_disc[f];
    pthread_rwlock_unlock(&dc_lock);
    return ret;
  }
  pthread_rwlock_unlock(&dc_lock);

  FunctionSet visited;
  InstructionSet *ret = discover_chks(f, visited);
  return ret;
}

void gatlin::backward_slice_build_callgraph(InstructionList &callgraph,
                                            Instruction *I,
                                            FunctionToCheckResult &fvisited,
                                            int &good, int &bad, int &ignored) {
  // I should be an instruction
  if (!I)
    return;
  // we've reached the limit
  if (callgraph.size() > knob_bwd_depth) {
    BwdAnalysisMaxHit++;
    return;
  }
  Function *f = I->getFunction();
  if (fvisited.find(f) != fvisited.end()) {
    switch (fvisited[f]) {
    case (RCHKED):
      good++;
      break;
    case (RNOCHK):
      bad++;
      break;
    case (RNA):
      break;
    default:
      ignored++;
      break;
    }
    return;
  }
  callgraph.push_back(I);
  // place holder
  fvisited[f] = RNA;
  DominatorTree dt(*f);
  InstructionSet *chks;

  if (is_skip_function(f->getName())) {
    // should skip?
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
  if ((chks != NULL) && chks->size()) {
    for (auto *chk : *chks) {
      if (dt.dominates(chk, I)) {
        if (knob_dump_good_path) {
          errs() << ANSI_COLOR(BG_GREEN, FG_BLACK)
                 << "Hit Check Function:" << get_callee_function_name(chk)
                 << " @ ";
          chk->getDebugLoc().print(errs());
          errs() << ANSI_COLOR_RESET << "\n";
        }
        good++;
        goto good_out;
      }
    }
  }

  if (is_syscall(f)) {
    // this is syscall and no check, report it as bad
    bad++;
    goto bad_out;
  }
  ////////////////////////////////////////////////////////////////////////////////
  /*
   * we havn't got a check yet, we need to go to f's user to see
   * if it is checked there
   */
  // Direct CallSite
  for (auto *U : f->users()) {
    CallInstSet cis;
    get_callsite_inst(U, cis);
    bool resolved_as_call = false;
    for (auto *_ci : cis) {
      if (_ci->getCalledFunction() != f) {
        // this should match otherwise it is used as a call back function
        //(function parameter)which is not our interest
        // errs()<<"Function "<<f->getName()<< " used as a callback @ ";
        //_ci->getDebugLoc().print(errs());
        // errs()<<"\n";
        ignored++;
        dump_as_ignored(callgraph);
        continue;
      }
      resolved_as_call = true;
      backward_slice_build_callgraph(callgraph, dyn_cast<Instruction>(U),
                                     fvisited, good, bad, ignored);
    }
    if (!resolved_as_call) {
      if (!isa<Instruction>(U)) {
        CFuncUsedByStaticAssign++;
        // must be non-instruction
        if (is_used_by_static_assign_to_interesting_type(U)) {
          // used as kernel entry point and no check
          bad++;
          dump_as_bad(callgraph);
        } else {
          ignored++;
          dump_as_ignored(callgraph);
        }
      } else {
        // other use of current function?
        // llvm_unreachable("what?");
        CFuncUsedByNonCallInst++;
      }
    }
  }
  // Indirect CallSite(also user of current function)
  backward_slice_using_indcs(f, callgraph, fvisited, good, bad, ignored);

// intermediate.. just return.
ignored_out:
  callgraph.pop_back();
  return;

good_out:
  fvisited[f] = RCHKED;
  dump_as_good(callgraph);
  callgraph.pop_back();
  return;

bad_out:
  fvisited[f] = RNOCHK;
  dump_as_bad(callgraph);
  callgraph.pop_back();
  return;
}

void gatlin::_backward_slice_reachable_to_chk_function(Instruction *I,
                                                       int &good, int &bad,
                                                       int &ignored) {
  InstructionList callgraph;
  // FIXME: should consider function+instruction pair as visited?
  FunctionToCheckResult fvisited;
  return backward_slice_build_callgraph(callgraph, I, fvisited, good, bad,
                                        ignored);
}

void gatlin::backward_slice_reachable_to_chk_function(Instruction *cs,
                                                      int &good, int &bad,
                                                      int &ignored) {
  // collect all path and meet condition
  _backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
}

/*
 * exact match with bitcast
 */
bool gatlin::match_cs_using_fptr_method_0(Function *func,
                                          InstructionList &callgraph,
                                          FunctionToCheckResult &visited,
                                          int &good, int &bad, int &ignored) {
  bool ret = false;
  InstructionSet *csis;

  if (f2csi_type0.find(func) == f2csi_type0.end())
    goto end;
  csis = f2csi_type0[func];

  ret = true;
  for (auto *csi : *csis)
    backward_slice_build_callgraph(callgraph, csi, visited, good, bad, ignored);
end:
  return ret;
}

/*
 * signature based method to find out indirect callee
 */
bool gatlin::match_cs_using_fptr_method_1(Function *func,
                                          InstructionList &callgraph,
                                          FunctionToCheckResult &visited,
                                          int &good, int &bad, int &ignored) {
  // we want exact match to non-trivial function
  int cnt = 0;
  Type *func_type = func->getFunctionType();
  FunctionSet *fl = t2fs[func_type];
  if (!is_complex_type(func_type))
    goto end;
  if ((fl == NULL) || (fl->size() != 1))
    goto end;
  if ((*fl->begin()) != func)
    goto end;
  for (auto *idc : idcs) {
#if (LLVM_VERSION_MAJOR <= 10)
    Value *cv = idc->getCalledValue();
#else
    Value *cv = idc->getCalledOperand();
#endif
    Type *ft = cv->getType()->getPointerElementType();
    Type *ft2 = cv->stripPointerCasts()->getType()->getPointerElementType();
    if ((func_type == ft) || (func_type == ft2)) {
      cnt++;
      // errs()<<"Found matched functions for indirectcall:"
      //    <<(*fl->begin())->getName()<<"\n";
      backward_slice_build_callgraph(callgraph, idc, visited, good, bad,
                                     ignored);
    }
  }
end:
  return cnt != 0;
}

bool gatlin::backward_slice_using_indcs(Function *func,
                                        InstructionList &callgraph,
                                        FunctionToCheckResult &visited,
                                        int &good, int &bad, int &ignored) {
  /*
   * direct call using bitcast
   * this is exact match don't need to look further
   */
  if (match_cs_using_fptr_method_0(func, callgraph, visited, good, bad,
                                   ignored))
    return true;

  if (match_cs_using_fptr_method_1(func, callgraph, visited, good, bad,
                                   ignored)) {
    MatchCallCriticalFuncPtr++;
    return true;
  } else {
    UnMatchCallCriticalFuncPtr++;
    return false;
  }
}

/*
 * check possible critical function path
 *
 * tid - thread id
 * wgsize - total number of threads
 */
void gatlin::check_critical_function_usage(Module &module) {
  witidx = 0;
  if (knob_mt <= 1) {
    _check_critical_function_usage(&module, 0, 1);
    return;
  }
  pthread_rwlock_init(&dc_lock, NULL);

  std::thread workers[(int)knob_mt];
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i] = std::thread(&gatlin::_check_critical_function_usage, this,
                             &module, i, (int)knob_mt);
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i].join();
}

void gatlin::_check_critical_function_usage(Module *module, int tid,
                                            int wgsize) {
  /*
   * collect critical indirect call site and check them in one shot
   */
  InstructionSet indirect_callsite_set;
  /*
   * for each critical function find out all callsite(use)
   */
  int idx = 0;
  for (Function *func : critical_functions) {
    if (idx < witidx) {
      idx++;
      continue;
    }
    witidx_lock.lock();
    if (idx == witidx) // revalidate
    {
      // success
      idx++;
      witidx = idx;
    } else {
      // failed
      idx++;
      witidx_lock.unlock();
      continue;
    }
    witidx_lock.unlock();

    if (!crit_syms->use_builtin())             // means that not knob specified
      if (!crit_syms->exists(func->getName())) // means that symbol not matched
        continue;
    if (is_skip_function(func->getName()))
      continue;

    // x_lock.lock();
    errs() << ANSI_COLOR_YELLOW << "Check Use of Function:" << func->getName()
           << ANSI_COLOR_RESET << "\n";
    // x_lock.unlock();
    // iterate through all call site
    // direct call
    int good = 0, bad = 0, ignored = 0;
    for (auto *U : func->users()) {
      CallInstSet cil;
      get_callsite_inst(U, cil);
      for (auto cs : cil)
        backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
    }
    // indirect call
#if 0
        for (auto& callees: idcs2callee)
        {
            CallInst *cs = const_cast<CallInst*>
                            (static_cast<const CallInst*>(callees.first));
            for (auto* f: *callees.second)
                if (f==func)
                {
                    indirect_callsite_set.insert(cs);
                    break;
                }
        }
#else
    if (f2csi_type1.find(func) != f2csi_type1.end())
      for (auto cs : *f2csi_type1[func])
        indirect_callsite_set.insert(cs);
#endif
    // summary
    if (bad != 0) {
      errs() << ANSI_COLOR_GREEN << "Good: " << good << " " << ANSI_COLOR_RED
             << "Bad: " << bad << " " << ANSI_COLOR_YELLOW
             << "Ignored: " << ignored << ANSI_COLOR_RESET << "\n";
    }
    BadPath += bad;
    GoodPath += good;
    IgnPath += ignored;
  }
#if 1
  // critical indirect call site
  errs() << ANSI_COLOR_YELLOW << "Check all other indirect call sites"
         << ANSI_COLOR_RESET << "\n";
  int good = 0, bad = 0, ignored = 0;
  for (auto cs : indirect_callsite_set) {
    errs() << ANSI_COLOR_YELLOW << "Check callee group:" << ANSI_COLOR_RESET
           << "\n";
    for (auto func : *idcs2callee[cs]) {
      if (!crit_syms->use_builtin()) // means that not knob specified
        if (!crit_syms->exists(func->getName())) // means that symbol not
                                                 // matched
          continue;
      if (is_skip_function(func->getName()) ||
          (critical_functions.find(func) == critical_functions.end()))
        continue;
      errs() << "    " << func->getName() << "\n";
    }
    backward_slice_reachable_to_chk_function(cs, good, bad, ignored);
  }
  // summary
  if (bad != 0) {
    errs() << ANSI_COLOR_GREEN << "Good: " << good << " " << ANSI_COLOR_RED
           << "Bad: " << bad << " " << ANSI_COLOR_YELLOW
           << "Ignored: " << ignored << ANSI_COLOR_RESET << "\n";
  }
  BadPath += bad;
  GoodPath += good;
  IgnPath += ignored;
#endif
  x_lock.lock();
  errs() << ANSI_COLOR(BG_WHITE, FG_GREEN) << "Thread " << tid << " Done!"
         << ANSI_COLOR_RESET << "\n";
  x_lock.unlock();
}

/*
 * run inter-procedural backward analysis to figure out whether the use of
 * critical variable can be reached from entry point without running check
 *
 * tid - thread id
 * wgsize - total number of threads
 */
void gatlin::check_critical_variable_usage(Module &module) {
  witidx = 0;
  if (knob_mt == 1) {
    _check_critical_variable_usage(&module, 0, 1);
    return;
  }
  std::thread *workers;
  workers = new std::thread[knob_mt];
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i] = std::thread(&gatlin::_check_critical_variable_usage, this,
                             &module, i, (int)knob_mt);
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i].join();
  delete workers;
}
void gatlin::_check_critical_variable_usage(Module *module, int tid,
                                            int wgsize) {
  int idx = 0;
  for (auto *V : critical_variables) {
    if (idx < witidx) {
      idx++;
      continue;
    }
    witidx_lock.lock();
    if (idx == witidx) // revalidate
    {
      // success
      idx++;
      witidx = idx;
    } else {
      // failed
      idx++;
      witidx_lock.unlock();
      continue;
    }
    witidx_lock.unlock();

    FunctionList flist; // known functions
    errs() << ANSI_COLOR_YELLOW << "Inspect Use of Variable:" << V->getName()
           << ANSI_COLOR_RESET << "\n";

    // figure out all use-def, put them info workset
    InstructionSet workset;
    for (auto *U : V->users()) {
      Instruction *ui = dyn_cast<Instruction>(U);
      if (!ui) // not an instruction????
      {
        // llvm_unreachable("not an instruction?");
        continue;
      }
      Function *f = ui->getFunction();
      // make sure this is not inside a kernel init function
      if (is_kernel_init_functions(f))
        continue;
      // TODO: value flow
      workset.insert(ui);
    }
    for (auto *U : workset) {
      Function *f = U->getFunction();
      errs() << " @ " << f->getName() << " ";
      U->getDebugLoc().print(errs());
      errs() << "\n";
      flist.push_back(f);

      // is this instruction reachable from non-checked path?
      int good = 0, bad = 0, ignored = 0;
      _backward_slice_reachable_to_chk_function(dyn_cast<Instruction>(U), good,
                                                bad, ignored);
      if (bad != 0) {
        errs() << ANSI_COLOR_GREEN << "Good: " << good << " " << ANSI_COLOR_RED
               << "Bad: " << bad << " " << ANSI_COLOR_YELLOW
               << "Ignored: " << ignored << ANSI_COLOR_RESET << "\n";
      }
      BadPath += bad;
      GoodPath += good;
      IgnPath += ignored;
    }
  }
}

void gatlin::check_critical_type_field_usage(Module &module) {
  witidx = 0;
  if (knob_mt == 1) {
    _check_critical_type_field_usage(&module, 0, 1);
    return;
  }
  std::thread *workers;
  workers = new std::thread[knob_mt];
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i] = std::thread(&gatlin::_check_critical_type_field_usage, this,
                             &module, i, (int)knob_mt);
  for (unsigned int i = 0; i < knob_mt; i++)
    workers[i].join();
  delete workers;
}

void gatlin::_check_critical_type_field_usage(Module *module, int tid,
                                              int wgsize) {
  int idx = 0;

  for (auto V : critical_typefields) {
    if (idx < witidx) {
      idx++;
      continue;
    }
    witidx_lock.lock();
    if (idx == witidx) // revalidate
    {
      // success
      idx++;
      witidx = idx;
    } else {
      // failed
      idx++;
      witidx_lock.unlock();
      continue;
    }
    witidx_lock.unlock();

    StructType *t = dyn_cast<StructType>(V.first);
    // std::set<int>& fields = V.second;

    errs() << ANSI_COLOR_YELLOW << "Inspect Use of Type:" << t->getStructName()
           << ANSI_COLOR_RESET << "\n";

    // figure out all use-def, put them info workset
    InstructionSet workset;
    // figure out where the type is used, and add all of them in workset
    // mainly gep
    figure_out_gep_using_type_field(workset, V, *module);

    for (auto *U : workset) {
      Function *f = U->getFunction();
      errs() << " @ " << f->getName() << " ";
      U->getDebugLoc().print(errs());
      errs() << "\n";

      // is this instruction reachable from non-checked path?
      int good = 0, bad = 0, ignored = 0;
      _backward_slice_reachable_to_chk_function(dyn_cast<Instruction>(U), good,
                                                bad, ignored);
      if (bad != 0) {
        errs() << ANSI_COLOR_GREEN << "Good: " << good << " " << ANSI_COLOR_RED
               << "Bad: " << bad << " " << ANSI_COLOR_YELLOW
               << "Ignored: " << ignored << ANSI_COLOR_RESET << "\n";
      }
      BadPath += bad;
      GoodPath += good;
      IgnPath += ignored;
    }
  }
}

void gatlin::figure_out_gep_using_type_field(
    InstructionSet &workset,
    const std::pair<Type *, std::unordered_set<int>> &v, Module &module) {
  for (Module::iterator f = module.begin(), f_end = module.end(); f != f_end;
       ++f) {
    if (is_skip_function(dyn_cast<Function>(f)->getName()))
      continue;
    for (Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi) {
      BasicBlock *bb = dyn_cast<BasicBlock>(fi);
      for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
           ++ii) {
        if (!isa<GetElementPtrInst>(ii))
          continue;
        GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(ii);
        /*if (!gep_used_by_call_or_store(gep))
            continue;*/
        Type *gep_operand_type =
            dyn_cast<PointerType>(gep->getPointerOperandType())
                ->getElementType();
        // check type
        if (gep_operand_type == v.first) {
          // check field
          assert(gep->hasIndices());
          ConstantInt *cint = dyn_cast<ConstantInt>(gep->idx_begin());
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
/*
 * collect critical function calls,
 * callee of direct call is collected directly,
 * callee of indirect call is reasoned by its type or struct
 */
void gatlin::crit_func_collect(CallInst *cs, FunctionSet &current_crit_funcs,
                               InstructionList &chks) {
  // ignore inline asm
  if (cs->isInlineAsm())
    return;
  if (Function *csf = get_callee_function_direct(cs)) {
    if (csf->isIntrinsic() || is_skip_function(csf->getName()) ||
        gating->is_gating_function(csf)) {
      if (is_skip_function(csf->getName()))
        skipped_functions.insert(csf);
      return;
    }
    current_crit_funcs.insert(csf);

    if (knob_gatlin_ccfv) {
      errs() << "Add call<direct> " << csf->getName() << " use @ ";
      cs->getDebugLoc().print(errs());
      errs() << "\n cause:";
      dump_dbgstk(dbgstk);
    }

    InstructionSet *ill = f2ci[csf];
    if (ill == NULL) {
      ill = new InstructionSet;
      f2ci[csf] = ill;
    }
    for (auto chki : chks)
      ill->insert(chki);

  } // else if (Value* csv = cs->getCalledValue())
#if (LLVM_VERSION_MAJOR <= 10)
  else if (cs->getCalledValue() != NULL) {
#else
  else if (cs->getCalledOperand() != NULL) {
#endif
    if (knob_gatlin_ccfv) {
      errs() << "Resolve indirect call @ ";
      cs->getDebugLoc().print(errs());
      errs() << "\n";
    }
    // TODO:solve as gep function pointer of struct
    FunctionSet fs = resolve_indirect_callee(cs);
    if (!fs.size()) {
      if (knob_gatlin_ccfv)
        errs() << ANSI_COLOR_RED << "[NO MATCH]" << ANSI_COLOR_RESET << "\n";
      CPUnResolv++;
      return;
    }
    if (knob_gatlin_ccfv)
      errs() << ANSI_COLOR_GREEN << "[FOUND " << fs.size() << " MATCH]"
             << ANSI_COLOR_RESET << "\n";
    CPResolv++;
    for (auto *csf : fs) {
      if (csf->isIntrinsic() || is_skip_function(csf->getName()) ||
          gating->is_gating_function(csf) || (csf == cs->getFunction())) {
        if (is_skip_function(csf->getName()))
          skipped_functions.insert(csf);
        continue;
      }

      current_crit_funcs.insert(csf);
      if (knob_gatlin_ccfv) {
        errs() << "Add call<indirect> " << csf->getName() << " use @ ";
        cs->getDebugLoc().print(errs());
        errs() << "\n cause:";
        dump_dbgstk(dbgstk);
      }
      InstructionSet *ill = f2ci[csf];
      if (ill == NULL) {
        ill = new InstructionSet;
        f2ci[csf] = ill;
      }
      // insert all chks?
      for (auto chki : chks)
        ill->insert(chki);
    }
  }
}

/*
 * collect critical variable usage, if it uses global
 */
void gatlin::crit_vars_collect(Instruction *ii,
                               ValueList &current_critical_variables,
                               InstructionList &chks) {
  Value *gv = get_global_def(ii);
  if (gv && (!isa<Function>(gv)) && (!is_skip_var(gv->getName()))) {
    if (knob_gatlin_ccvv) {
      errs() << "Add " << gv->getName() << " use @ ";
      ii->getDebugLoc().print(errs());
      errs() << "\n cause:";
      dump_dbgstk(dbgstk);
    }
    current_critical_variables.push_back(gv);
    InstructionSet *ill = v2ci[gv];
    if (ill == NULL) {
      ill = new InstructionSet;
      v2ci[gv] = ill;
    }
    for (auto chki : chks)
      ill->insert(chki);
  }
}

/*
 * figure whether this instruction is reading/writing any struct field
 * inter-procedural
 */
void gatlin::crit_type_field_collect(Instruction *i,
                                     Type2Fields &current_t2fmaps,
                                     InstructionList &chks) {
  StructType *t = NULL;
  if (LoadInst *li = dyn_cast<LoadInst>(i)) {
    /*
     * we are expecting that we load a pointer from a struct type
     * which will be like:
     *
     * addr = (may bit cast) gep(struct addr, field)
     * ptr = load(addr)
     */
    // only interested in pointer type
    if (!li->getType()->isPointerTy())
      return;
    Value *addr = li->getPointerOperand()->stripPointerCasts();
    // now we are expecting a gep
    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(addr)) {
      // great we got a gep
      // Value* gep_operand = gep->getPointerOperand();
      Type *gep_operand_type =
          dyn_cast<PointerType>(gep->getPointerOperandType())->getElementType();
      if (!isa<StructType>(gep_operand_type))
        return;
      // FIXME: only handle the first field as of now
      assert(gep->hasIndices());
      if (!(dyn_cast<ConstantInt>(gep->idx_begin()))) {
        /*errs()<<"gep has no indices @ position 0 ";
        gep->getDebugLoc().print(errs());
        errs()<<"\n";
        gep->print(errs());
        errs()<<"\n";*/
        return;
      }
      // what is the first indice?
      StructType *stype = dyn_cast<StructType>(gep_operand_type);
      if (is_skip_struct(stype->getStructName()))
        return;
      int idx = dyn_cast<ConstantInt>(gep->idx_begin())->getSExtValue();
      current_t2fmaps[gep_operand_type].insert(idx);
      t = stype;
      goto goodret;
    } else {
      // what else? maybe phi?
    }
  } else if (StoreInst *si = dyn_cast<StoreInst>(i)) {
    /*
     * we are expecting that we store a pointer into a struct type
     * which will be like:
     *
     * addr = (may bit cast) gep(struct addr, field)
     * store(interesting_ptr, addr);
     */
    if (!si->getValueOperand()->getType()->isPointerTy())
      return;
    Value *addr = si->getPointerOperand()->stripPointerCasts();
    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(addr)) {
      // great we got a gep
      // Value* gep_operand = gep->getPointerOperand();
      Type *gep_operand_type =
          dyn_cast<PointerType>(gep->getPointerOperandType())->getElementType();
      if (!isa<StructType>(gep_operand_type))
        return;
      // FIXME: only handle the first field as of now
      assert(gep->hasIndices());
      if (!(dyn_cast<ConstantInt>(gep->idx_begin()))) {
        /*errs()<<"gep has no indices @ position 0 ";
        gep->getDebugLoc().print(errs());
        errs()<<"\n";
        gep->print(errs());
        errs()<<"\n";*/
        return;
      }
      // what is the first indice?
      StructType *stype = dyn_cast<StructType>(gep_operand_type);
      if (is_skip_struct(stype->getStructName()))
        return;

      int idx = dyn_cast<ConstantInt>(gep->idx_begin())->getSExtValue();
      current_t2fmaps[gep_operand_type].insert(idx);
      t = stype;
      goto goodret;
    } else {
      // what else? maybe phi?
    }
  } else {
    // what else can it be?
  }
  return;
goodret:
  InstructionSet *ill = t2ci[t];
  if (ill == NULL) {
    ill = new InstructionSet;
    t2ci[t] = ill;
  }
  for (auto i : chks)
    ill->insert(i);
  if (knob_gatlin_cctv) {
    errs() << "Add struct " << t->getStructName() << " use @ ";
    i->getDebugLoc().print(errs());
    errs() << "\n cause:";
    dump_dbgstk(dbgstk);
  }

  return;
}

/*
 * IPA: figure out all global variable usage and function calls
 *
 * @I: from where are we starting, all following instructions should be
 * dominated by I, if checked=true
 * @depth: are we going too deep?
 * @checked: is this function already checked? means that `I' will dominate all,
 *     means that the caller of current function have already been dominated by
 *     a check
 * @callgraph: how do we get here
 * @chks: which checks are protecting us?
 */
void gatlin::forward_all_interesting_usage(Instruction *I, unsigned int depth,
                                           bool checked,
                                           InstructionList &callgraph,
                                           InstructionList &chks) {
  Function *func = I->getFunction();
  DominatorTree dt(*func);

  if (is_skip_function(std::string(func->getName()))) {
    skipped_functions.insert(func);
    return;
  }

  bool is_function_permission_checked = checked;
  /*
   * collect interesting variables/functions found in this function
   */
  FunctionSet current_crit_funcs;
  ValueList current_critical_variables;
  Type2Fields current_critical_type_fields;

  // don't allow recursive
  if (std::find(callgraph.begin(), callgraph.end(), I) != callgraph.end())
    return;

  callgraph.push_back(I);

  if (depth > knob_fwd_depth) {
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
  // already checked?
  if (is_function_permission_checked)
    goto rescan_and_add_all;

  bb_work_list.push_back(I->getParent());
  while (bb_work_list.size()) {
    BasicBlock *bb = bb_work_list.front();
    bb_work_list.pop_front();
    if (bb_visited.count(bb))
      continue;
    bb_visited.insert(bb);

    for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
         ++ii) {
      if (isa<CallInst>(ii)) {
        // only interested in call site
        CallInst *ci = dyn_cast<CallInst>(ii);
        if (Function *csfunc = get_callee_function_direct(ci)) {
          if (gating->is_gating_function(csfunc)) {
            is_function_permission_checked = true;
            chk_instruction_list.push_back(ci);
            chks.push_back(ci);
          }
        } else if (!ci->isInlineAsm()) {
          // don't really care inline asm
          // FIXME:this is in-direct call, could there be a check inside
          // indirect call we are missing?
        }
      }
    }
    // insert all successor of current basic block to work list
    for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si)
      bb_work_list.push_back(cast<BasicBlock>(*si));
  }

  if (!is_function_permission_checked)
    goto out;

/*******************************************************************
 * second, re-scan all instructions and figure out
 * which one can be dominated by those check instructions(protected)
 */
rescan_and_add_all:

  for (Function::iterator fi = func->begin(), fe = func->end(); fi != fe;
       ++fi) {
    BasicBlock *bb = dyn_cast<BasicBlock>(fi);
    for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii != ie;
         ++ii) {
      Instruction *si = dyn_cast<Instruction>(ii);
      /*
       * if any check dominate si then go ahead and
       * add them to protected list
       */
      // already checked before entering current scope
      // all following usage should be dominated by incoming Instruction
      if (checked) {
        // should dominate use
        if (dt.dominates(I, si))
          goto add;
      }
      // or should have newly discovered check.. and
      // there should be at least one check dominate the use
      for (auto *_ci : chk_instruction_list)
        if (dt.dominates(_ci, si))
          goto add;
      // dont care if not protected
      continue;

    add:
      if (CallInst *cs = dyn_cast<CallInst>(ii)) {
        crit_func_collect(cs, current_crit_funcs, chks);
        // continue;
        // need to look at argument
      }
      crit_vars_collect(si, current_critical_variables, chks);
      crit_type_field_collect(si, current_critical_type_fields, chks);
    }
  }
  // still not checked???
  if (!is_function_permission_checked)
    goto out;
  /*
   * checked, merge forward slicing result(intra-) and collect more(inter-)
   */
  for (auto i : current_crit_funcs)
    critical_functions.insert(i);
  for (auto v : current_critical_variables)
    critical_variables.insert(v);
  for (auto v : current_critical_type_fields) {
    Type *t = v.first;
    std::unordered_set<int> &sset = v.second;
    std::unordered_set<int> &dset = critical_typefields[t];
    for (auto x : sset)
      dset.insert(x);
  }
  // FIXME: handle indirect callsite
  for (auto *U : func->users()) {
    if (CallInst *cs = dyn_cast<CallInst>(U)) {
      Function *pfunc = cs->getFunction();
      if (pfunc->isIntrinsic())
        continue;
      if (is_kernel_init_functions(pfunc)) {
        if (knob_warn_gatlin_during_kinit) {
          dbgstk.push_back(cs);
          errs() << ANSI_COLOR_YELLOW
                 << "capability check used during kernel initialization\n"
                 << ANSI_COLOR_RESET;
          dump_dbgstk(dbgstk);
          dbgstk.pop_back();
        }
        continue;
      }

      dbgstk.push_back(cs);
      forward_all_interesting_usage(cs, depth + 1, true, callgraph, chks);
      dbgstk.pop_back();
    }
  }
out:
  callgraph.pop_back();
  return;
}

FunctionSet gatlin::function_signature_match(CallInst *ci) {
  FunctionSet fs;
#if (LLVM_VERSION_MAJOR <= 10)
  Value *cv = ci->getCalledValue();
#else
  Value *cv = ci->getCalledOperand();
#endif
  Type *ft = cv->getType()->getPointerElementType();
  if (t2fs.find(ft) == t2fs.end())
    return fs;
  FunctionSet *fl = t2fs[ft];
  for (auto *f : *fl)
    fs.insert(f);
  return fs;
}

void gatlin::my_debug(Module &module) {
  int resolved = 0;
  int targets = 0;
  for (auto *idc : idcs) {
    FunctionSet fs = function_signature_match(idc);
    if (fs.size() != 0) {
      resolved++;
    }
    targets += fs.size();
  }
  errs() << "# fsm total idcs to resolve:" << idcs.size() << "\n";
  errs() << "# fsm resolved:" << resolved << "\n";
  errs() << "# fsm targets:" << targets << "\n";
}

/*
 * process capability protected globals and functions
 */
void gatlin::process_cpgf(Module &module) {
  // my_debug(module);
  /*
   * pre-process
   * generate resource/functions from syscall entry function
   */
  initialize_gatlin_sets(knob_skip_func_list, knob_skip_var_list,
                         knob_crit_symbol, knob_kernel_api);

  errs() << "Pre-processing...\n";
  STOP_WATCH_MON(WID_0, preprocess(module));
  errs() << "Found " << syscall_list.size() << " syscalls\n";

  errs() << "Process Gating Functions\n";
  STOP_WATCH_START(WID_0);
  if (knob_gating_type == "cap")
    gating = new GatingCap(module, knob_cap_function_list);
  else if (knob_gating_type == "lsm")
    gating = new GatingLSM(module, knob_lsm_function_list);
  else if (knob_gating_type == "dac")
    gating = new GatingDAC(module);
  else
    llvm_unreachable("invalid setting!");
  STOP_WATCH_STOP(WID_0);
  STOP_WATCH_REPORT(WID_0);
  dump_gating();

  // pass 0
  errs() << "Collect Checkpoints\n";
  STOP_WATCH_MON(WID_0, collect_chkps(module));
  errs() << "Identify interesting struct\n";
  STOP_WATCH_MON(WID_0, identify_interesting_struct(module));

  errs() << "Collecting Initialization Closure.\n";
  STOP_WATCH_MON(WID_0, collect_kernel_init_functions(module));

  // statistics for function signature based approache
  // STOP_WATCH_MON(WID_0, my_debug(module));
  // exit (0);

  errs() << "Identify Kernel Modules Interface\n";
  STOP_WATCH_MON(WID_0, identify_kmi(module));
  dump_kmi();
  errs() << "dynamic KMI\n";
  STOP_WATCH_MON(WID_0, identify_dynamic_kmi(module));
  dump_dkmi();

  errs() << "Populate indirect callsite using kernel module interface\n";
  STOP_WATCH_MON(WID_0, populate_indcall_list_through_kmi(module));

  // exit(0);
  // pass 1
  errs() << "Collect all permission-checked variables and functions\n";
  STOP_WATCH_MON(WID_0, collect_crits(module));
  errs() << "Collected " << critical_functions.size()
         << " critical functions\n";
  errs() << "Collected " << critical_variables.size()
         << " critical variables\n";
  errs() << "Collected " << critical_typefields.size()
         << " critical type/fields\n";

  dump_v2ci();
  dump_f2ci();
  dump_tf2ci();

  // pass 2
  errs() << "Run Analysis, Threads:" << knob_mt << "\n";

  if (knob_gatlin_critical_var) {
    errs() << "Critical variables\n";
    STOP_WATCH_MON(WID_0, check_critical_variable_usage(module));
  }
  if (knob_gatlin_critical_fun) {
    errs() << "Critical functions\n";
    STOP_WATCH_MON(WID_0, check_critical_function_usage(module));
  }
  if (knob_gatlin_critical_type_field) {
    errs() << "Critical Type Field\n";
    STOP_WATCH_MON(WID_0, check_critical_type_field_usage(module));
  }
  dump_non_kinit();
  delete skip_funcs;
  delete skip_vars;
  delete crit_syms;
  delete kernel_api;
  delete gating;
}

bool gatlin::runOnModule(Module &module) {
  m = &module;
  return gatlinPass(module);
}

bool gatlin::gatlinPass(Module &module) {
  errs() << ANSI_COLOR_CYAN << "--- PROCESS FUNCTIONS ---" << ANSI_COLOR_RESET
         << "\n";
  process_cpgf(module);
  errs() << ANSI_COLOR_CYAN << "--- DONE! ---" << ANSI_COLOR_RESET << "\n";

#if CUSTOM_STATISTICS
  dump_statistics();
#endif
  // just quit
  exit(0);
  // never reach here
  return false;
}

static RegisterPass<gatlin>
    XXX("gatlin", "gatlin Pass (with getAnalysisUsage implemented)");
