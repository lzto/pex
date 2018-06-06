/*
 * XChecker
 */

#include "MSSA/SVFGStat.h"
#include "Util/GraphUtil.h"
#include "XChecker/DDA.h"

using namespace llvm;

class XChecker : public DDA, public llvm::ModulePass
{

public:
    typedef std::map<const SVFGNode*,llvm::CallSite> SVFGNodeToCSIDMap;
    typedef FIFOWorkList<llvm::CallSite> CSWorkList;
    typedef ProgSlice::VFWorkList WorkList;
    typedef NodeBS SVFGNodeBS;
    typedef PAG::CallSiteSet CallSiteSet;

    static char ID;

    XChecker(char id = ID): ModulePass(ID) {}
    virtual ~XChecker() {}

    virtual bool runOnModule(llvm::Module& module) {
        return runOnModule(module);
    }

    virtual bool runOnModule(SVFModule module) {
        analyze(module);
        return false;
    }

    virtual llvm::StringRef getPassName() const {
        return "XChecker using SVF";
    }

    virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const {
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
    }

    virtual void initSrcs();
    virtual void initSnks();

    /// Whether the function is a heap allocator/reallocator (allocate memory)
    virtual bool isSourceLikeFun(const llvm::Function* fun);
    /// Whether the function is a heap deallocator (free/release memory)
    virtual bool isSinkLikeFun(const llvm::Function* fun);

    /// Identify allocation wrappers
    bool isInAWrapper(const SVFGNode* src, CallSiteSet& csIdSet);

    /// A SVFG node is source if it is an actualRet at malloc site
    inline bool isSource(const SVFGNode* node) {
        return getSources().find(node)!=getSources().end();
    }

    /// A SVFG node is source if it is an actual parameter at dealloca site
    inline bool isSink(const SVFGNode* node) {
        return getSinks().find(node)!=getSinks().end();
    }

protected:
    /// Get PAG
    PAG* getPAG() const {
        return PAG::getPAG();
    }

    virtual void reportBug(ProgSlice* slice);

    /// Record a source to its callsite
    inline void addSrcToCSID(const SVFGNode* src, llvm::CallSite cs) {
        srcToCSIDMap[src] = cs;
    }
    inline llvm::CallSite getSrcCSID(const SVFGNode* src) {
        SVFGNodeToCSIDMap::iterator it =srcToCSIDMap.find(src);
        assert(it!=srcToCSIDMap.end() && "source node not at a callsite??");
        return it->second;
    }

private:
    SVFGNodeToCSIDMap srcToCSIDMap;
};




