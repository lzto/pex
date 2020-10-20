/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#ifndef _GATLING_UTILITY_
#define _GATLING_UTILITY_

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"

#include "commontypes.h"
#include "simple_set.h"

using namespace llvm;

int use_parent_func_arg(Value *v, Function *f);
int use_parent_func_arg_deep(Value *v, Function *f);
Instruction *GetNextInstruction(Instruction *i);
Instruction *GetNextNonPHIInstruction(Instruction *i);
Function *get_callee_function_direct(Instruction *i);
StringRef get_callee_function_name(Instruction *i);
InstructionSet get_user_instruction(Value *);
StructType *find_assignment_to_struct_type(Value *, Indices &, ValueSet &);
void get_callsite_inst(Value *, CallInstSet &);
bool has_function_pointer_type(Type *);

StructType *identify_ld_bcst_struct(Value *);

InstructionSet get_load_from_gep(Value *);

void get_gep_indicies(GetElementPtrInst *, Indices &);
Value *get_value_from_composit(Value *, Indices &);

void add_function_to_dmi(Function *, StructType *, Indices &, DMInterface &);
FunctionSet *dmi_exists(StructType *, Indices &, DMInterface &);
bool dmi_type_exists(StructType *, DMInterface &);

bool function_has_gv_initcall_use(Function *);
void str_truncate_dot_number(std::string &);

bool is_skip_struct(StringRef);
bool is_using_function_ptr(Function *);
bool is_address_taken(Function *f);
bool is_tracepoint_func(Value *);
bool is_container_of(Value *);

extern Instruction *x_dbg_ins;
extern std::list<int> x_dbg_idx;

void dump_callstack(InstructionList &);
void dump_dbgstk(InstructionList &);
void dump_gdblst(ValueList &);
/*
 * dump a path consisted of Instructions in the list
 */
void dump_a_path(InstructionList &);

////////////////////////////////////////////////////////////////////////////////
// some interesting list is also defined as global
extern SimpleSet *skip_vars;
extern SimpleSet *skip_funcs;
extern SimpleSet *crit_syms;
extern SimpleSet *kernel_api;

void initialize_gatlin_sets(StringRef knob_skip_func_list,
                            StringRef knob_skip_var_list,
                            StringRef knob_crit_symbol,
                            StringRef knob_kernel_api);
#endif //_GATLING_UTILITY_
