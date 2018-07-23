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

target_link_libraries( libgatlin LLVMSvf LLVMCudd )

