add_llvm_loadable_module( libcapchk
    capchk.cpp
    cvfa.cpp

    DEPENDS
    PLUGIN_TOOL
    opt
    )

target_compile_features(libcapchk PRIVATE cxx_range_for cxx_auto_type)

target_link_libraries( libcapchk LLVMSvf LLVMCudd )

#set_target_properties(libcapchk PROPERTIES
#	COMPILE_FLAGS "-fno-rtti"
#	)


