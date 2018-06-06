/*
 * XChecker
 * - capability or unprotected critical variable access checker
 * 2018 Tong Zhang
 *
 * ---------------------------------------------------------------------------- 
 * Design:
 *
 * 1. scan use of critical permission check functions like capable/ns_capable
 * 2. for call site, figure out whether a use of variable is alias to global 
 *    variable, if true, add that global variable to check list(protected by
 *    check function)
 * 3. scan all functions, figure out all use of variables in check list, and 
 *    do forward slicing to figure out whether the use of such variables are 
 *    properly checked, report any path that does not have a check.
 *
 */
#include "XChecker/XChecker.h"
#include "Util/AnalysisUtil.h"
#include "llvm/Support/CommandLine.h"


using namespace llvm;
using namespace analysisUtil;

char XChecker::ID = 0;

static RegisterPass<XChecker> XCHECKER("XChecker", "X-Checker");

#if 1
/*
 * called from DFA::initialize
 */
void XChecker::initSrcs()
{
    PAG* pag = getPAG();
    for(PAG::CSToRetMap::iterator it = pag->getCallSiteRets().begin(),
            eit = pag->getCallSiteRets().end(); it!=eit; ++it)
    {
        CallSite cs = it->first;
        if(isPtrInDeadFunction(cs.getInstruction()))
            continue;

        const Function* fun = getCallee(cs);
        if(isSourceLikeFun(fun)) {
            CSWorkList worklist;
            SVFGNodeBS visited;
            worklist.push(it->first);
            while (!worklist.empty()) {
                CallSite cs = worklist.pop();
                const PAGNode* pagNode = pag->getCallSiteRet(cs);
                const SVFGNode* node = getSVFG()->getDefSVFGNode(pagNode);
                if(visited.test(node->getId())==0)
                    visited.set(node->getId());
                else
                    continue;

                CallSiteSet csSet;
                // if this node is in an allocation wrapper, find all its call nodes
                if(isInAWrapper(node,csSet)) {
                    for(CallSiteSet::iterator it = csSet.begin(), eit = csSet.end(); it!=eit ; ++it) {
                        worklist.push(*it);
                    }
                }
                // otherwise, this is the source we are interested
                else {
                    // exclude sources in dead functions
                    if(isPtrInDeadFunction(cs.getInstruction()) == false) {
                        addToSources(node);
                        addSrcToCSID(node,cs);
                    }
                }
            }
        }
    }


}

void XChecker::initSnks()
{
    PAG* pag = getPAG();
    for(PAG::CSToArgsListMap::iterator it = pag->getCallSiteArgsMap().begin(),
        eit = pag->getCallSiteArgsMap().end(); it!=eit; ++it)
    {
        const Function* fun = getCallee(it->first);
        if(isSinkLikeFun(fun)) {
            PAG::PAGNodeList& arglist =	it->second;
            assert(!arglist.empty() && "no actual parameter at deallocation site?");
            /// we only pick the first parameter of all the actual parameters
            const SVFGNode* snk = getSVFG()->getActualParmSVFGNode(arglist.front(),it->first);
            addToSinks(snk);
        }
    }
}
#endif

bool XChecker::isInAWrapper(const SVFGNode* src, CallSiteSet& csIdSet)
{
    return false;
}


void XChecker::reportBug(ProgSlice* slice)
{
    if(isAllPathReachable() == false && isSomePathReachable() == false) {
        const SVFGNode* src = slice->getSource();
        CallSite cs = getSrcCSID(src);
        errs() << bugMsg1("\t NeverFree :") <<  " memory allocation at : ("
               << getSourceLoc(cs.getInstruction()) << ")\n";

    }
    else if (isAllPathReachable() == false && isSomePathReachable() == true) {
        const SVFGNode* src = slice->getSource();
        CallSite cs = getSrcCSID(src);
        errs() << bugMsg2("\t PartialLeak :") <<  " memory allocation at : ("
               << getSourceLoc(cs.getInstruction()) << ")\n";

        errs() << "\t\t conditional free path: \n" << slice->evalFinalCond() << "\n";
        slice->annotatePaths();
    }
}

bool XChecker::isSourceLikeFun(const llvm::Function* func)
{
    if (!func)
        return false;
    if(func->hasName() && func->getName().startswith("malloc"))
        return true;
    return false;
}

bool XChecker::isSinkLikeFun(const llvm::Function* func)
{
    if (!func)
        return false;
    if(func->hasName() && func->getName().startswith("free"))
        return true;
    return false;
}



