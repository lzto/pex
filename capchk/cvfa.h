/*
 * complex value flow analysis
 * 2018 Tong Zhang <t.zhang2@partner.samsung.com>
 */
#ifndef _CVFA_H_
#define _CVFA_H_

#include "commontypes.h"

#include "SABER/CFLSolver.h"
#include "MSSA/SVFGOPT.h"
#include "SABER/ProgSlice.h"
#include "SABER/SaberSVFGBuilder.h"
#include "WPA/Andersen.h"

using namespace llvm;

typedef CFLSolver<SVFG*,CxtDPItem> CFLAASolver;
typedef ProgSlice::SVFGNodeSet SVFGNodeSet;
typedef std::map<const SVFGNode*,ProgSlice*> SVFGNodeToSliceMap;
typedef SVFGNodeSet::iterator SVFGNodeSetIter;
typedef CxtDPItem DPIm;
//dpitem set
typedef std::set<DPIm> DPImSet;
//map a SVFGNode to its visited dpitems
typedef std::map<const SVFGNode*, DPImSet> SVFGNodeToDPItemsMap;

class CVFA : public CFLAASolver
{
private:
    ProgSlice* _curSlice;		/// current program slice
    SVFGNodeSet sources;		/// source nodes
    SVFGNodeSet sinks;		/// source nodes
    PathCondAllocator* pathCondAllocator;
    SVFGNodeToDPItemsMap nodeToDPItemsMap;	///<  record forward visited dpitems
    SVFGNodeSet visitedSet;	///<  record backward visited nodes
    SaberSVFGBuilder memSSA;
    SVFG* svfg;
    PTACallGraph* ptaCallGraph;
    Module* m;
    void collect_reachable_src(ProgSlice* slice);

public:
    CVFA() : _curSlice(NULL), svfg(NULL), ptaCallGraph(NULL)
    {
        pathCondAllocator = new PathCondAllocator();
    }
    virtual ~CVFA()
    {
        if (svfg != NULL)
            delete svfg;
        svfg = NULL;

        if (ptaCallGraph != NULL)
            delete ptaCallGraph;
        ptaCallGraph = NULL;

        if(pathCondAllocator)
            delete pathCondAllocator;
        pathCondAllocator = NULL;
    }
    

    virtual void initialize(Module& module);
    virtual void analyze();

    /// Finalize analysis
    virtual void finalize();

    /// Get SVFG
    inline SVFG* getSVFG() const {
        return graph();
    }

    /// Whether this svfg node may access global variable
    inline bool isGlobalSVFGNode(const SVFGNode* node) const {
        return memSSA.isGlobalSVFGNode(node);
    }
    //Slice operations
    void setCurSlice(const SVFGNode* src);

    inline ProgSlice* getCurSlice() const
    {
        return _curSlice;
    }
    inline void addSinkToCurSlice(const SVFGNode* node)
    {
        _curSlice->addToSinks(node);
        addToCurForwardSlice(node);
    }
    inline bool isInCurForwardSlice(const SVFGNode* node)
    {
        return _curSlice->inForwardSlice(node);
    }
    inline bool isInCurBackwardSlice(const SVFGNode* node)
    {
        return _curSlice->inBackwardSlice(node);
    }
    inline void addToCurForwardSlice(const SVFGNode* node)
    {
        _curSlice->addToForwardSlice(node);
    }
    inline void addToCurBackwardSlice(const SVFGNode* node)
    {
        _curSlice->addToBackwardSlice(node);
    }

    virtual bool isSource(const SVFGNode* node);
    virtual bool isSink(const SVFGNode* node);

    //Get sources/sinks
    inline const SVFGNodeSet& getSources() const
    {
        return sources;
    }
    inline SVFGNodeSetIter sourcesBegin() const
    {
        return sources.begin();
    }
    inline SVFGNodeSetIter sourcesEnd() const
    {
        return sources.end();
    }
    inline void addToSources(const SVFGNode* node)
    {
        sources.insert(node);
    }
    inline const SVFGNodeSet& getSinks() const
    {
        return sinks;
    }
    inline SVFGNodeSetIter sinksBegin() const
    {
        return sinks.begin();
    }
    inline SVFGNodeSetIter sinksEnd() const
    {
        return sinks.end();
    }
    inline void addToSinks(const SVFGNode* node)
    {
        sinks.insert(node);
    }

    /// Get path condition allocator
    PathCondAllocator* getPathAllocator() const
    {
        return pathCondAllocator;
    }

    void get_indirect_callee_for_func(const Function* callee, std::set<const Instruction*>& css);

protected:
    /// Forward traverse
    virtual inline void forwardProcess(const DPIm& item) {
        const SVFGNode* node = getNode(item.getCurNodeID());
        if(isSink(node)) {
            addSinkToCurSlice(node);
            _curSlice->setPartialReachable();
        }
        else
            addToCurForwardSlice(node);
    }
    /// Backward traverse
    virtual inline void backwardProcess(const DPIm& item) {
        const SVFGNode* node = getNode(item.getCurNodeID());
        if(isInCurForwardSlice(node)) {
            addToCurBackwardSlice(node);
        }
    }
    /// Propagate information forward by matching context
    virtual void forwardpropagate(const DPIm& item, SVFGEdge* edge);
    /// Propagate information backward without matching context,
    //as forward analysis already did it
    virtual void backwardpropagate(const DPIm& item, SVFGEdge* edge);
    /// Whether has been visited or not, in order to avoid recursion on SVFG
    //@{
    inline bool forwardVisited(const SVFGNode* node, const DPIm& item)
    {
        SVFGNodeToDPItemsMap::iterator it = nodeToDPItemsMap.find(node);
        if(it!=nodeToDPItemsMap.end())
            return it->second.find(item)!=it->second.end();
        else
            return false;
    }
    inline void addForwardVisited(const SVFGNode* node, const DPIm& item)
    {
        nodeToDPItemsMap[node].insert(item);
    }
    inline bool backwardVisited(const SVFGNode* node)
    {
        return visitedSet.find(node)!=visitedSet.end();
    }
    inline void addBackwardVisited(const SVFGNode* node)
    {
        visitedSet.insert(node);
    }
    inline void clearVisitedMap()
    {
        nodeToDPItemsMap.clear();
        visitedSet.clear();
    }
    //@}

    // Guarded reachability search
    virtual void AllPathReachability();
    inline bool isSatisfiableForAll(ProgSlice* slice)
    {
        return slice->isSatisfiableForAll();
    }
    inline bool isSatisfiableForPairs(ProgSlice* slice)
    {
        return slice->isSatisfiableForPairs();
    }

    // Whether it is all path reachable from a source
    virtual bool isAllPathReachable()
    {
        return _curSlice->isAllReachable();
    }

    // Whether it is some path reachable from a source
    virtual bool isSomePathReachable()
    {
        return _curSlice->isPartialReachable();
    }

    // Dump SVFG with annotated slice informaiton
    void dumpSlices();
    void annotateSlice(ProgSlice* slice);
    void printBDDStat();

};

#endif//_CVFA_H_

