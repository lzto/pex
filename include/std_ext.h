/*
 * hash function for std::set/map etc.
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _STD_EXT_
#define _STD_EXT_

#include <llvm/IR/Module.h>

namespace std {
template <> struct hash<std::pair<llvm::CallSite, const llvm::Function *>> {
  std::size_t
  operator()(const std::pair<llvm::CallSite, const llvm::Function *> &k) const {
    return std::hash<unsigned long>{}(
        ((unsigned long)k.first.getInstruction()) + ((unsigned long)k.second));
  }
};
template <> struct hash<llvm::CallSite> {
  std::size_t operator()(const llvm::CallSite &k) const {
    return std::hash<unsigned long>{}(((unsigned long)k.getInstruction()));
  }
};
} // namespace std

#endif //_STD_EXT_
