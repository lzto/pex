add_subdirectory(CUDD)

# Due to a mutual dependencies, all the sub projects of the SVG are merged here
# Otherwise it is impossible to load the dependencies in opt
# NOTE: if the SVF should be linked into opt, we should probably use the individual sub projects here, rather than the combined project 
set(SOURCES
    Util/AnalysisUtil.cpp
    Util/CPPUtil.cpp
    Util/DataFlowUtil.cpp
    Util/PTACallGraph.cpp
    Util/BreakConstantExpr.cpp
    Util/Conditions.cpp
    Util/ExtAPI.cpp
    Util/PathCondAllocator.cpp
    Util/PTAStat.cpp
    Util/SVFModule.cpp
    MemoryModel/ConsG.cpp
    MemoryModel/LocationSet.cpp
    MemoryModel/LocMemModel.cpp
    MemoryModel/MemModel.cpp
    MemoryModel/PAGBuilder.cpp
    MemoryModel/PAG.cpp
    MemoryModel/CHA.cpp
    MemoryModel/PointerAnalysis.cpp
    MSSA/MemPartition.cpp
    MSSA/MemRegion.cpp
    MSSA/MemSSA.cpp
    MSSA/SVFGBuilder.cpp
    MSSA/SVFG.cpp 
    MSSA/SVFGOPT.cpp
    MSSA/SVFGStat.cpp
    WPA/Andersen.cpp
    WPA/AndersenLCD.cpp
    WPA/AndersenStat.cpp
    WPA/AndersenWave.cpp
    WPA/AndersenWaveDiff.cpp
    WPA/AndersenWaveDiffWithType.cpp
    WPA/FlowSensitive.cpp
    WPA/FlowSensitiveStat.cpp
)

add_llvm_library(LLVMSvf ${SOURCES})

link_directories( ${CMAKE_BINARY_DIR}/libsvf/lib/Cudd )

if(DEFINED IN_SOURCE_BUILD)
    add_dependencies(LLVMSvf intrinsics_gen)
endif()

