add_llvm_loadable_module( libcapchk
    utility.cpp
    gating_function.cpp
    cvfa.cpp
    capchk.cpp

    DEPENDS
    PLUGIN_TOOL
    opt
    )

target_compile_features(libcapchk PRIVATE cxx_range_for cxx_auto_type)

target_link_libraries( libcapchk LLVMSvf LLVMCudd )

