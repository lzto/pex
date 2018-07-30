add_llvm_loadable_module( libgatlin
    utility.cpp
    simple_set.cpp
    gating_function.cpp
    module_duplicator.cpp
    cvfa.cpp
    gatlin.cpp

    DEPENDS
    PLUGIN_TOOL
    opt
    )

target_compile_features(libgatlin PRIVATE cxx_range_for cxx_auto_type)

if ( CMAKE_SYSTEM_NAME MATCHES "Darwin")
    llvm_map_components_to_libnames(llvm_libs bitwriter
        core ipo irreader instcombine instrumentation target linker analysis
        scalaropts support )
    target_link_libraries( libgatlin LLVMSvf LLVMCudd ${llvm_libs})
else()
    target_link_libraries( libgatlin LLVMSvf LLVMCudd )
endif()

