
if(DEFINED IN_SOURCE_BUILD)
    set(LLVM_LINK_COMPONENTS BitWriter Core IPO IrReader InstCombine Instrumentation Target Linker Analysis ScalarOpts Support Svf Cudd)
    add_llvm_tool( capchk capchk.cpp )
else()
    llvm_map_components_to_libnames(llvm_libs BitWriter Core IPO IrReader InstCombine Instrumentation Target Linker Analysis ScalarOpts Support )
    add_executable( capchk capchk.cpp )

    target_link_libraries( capchk LLVMSvf LLVMCudd ${llvm_libs} )

    set_target_properties( capchk PROPERTIES
                           RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
endif()
