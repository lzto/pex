add_library(capchk MODULE capchk.cpp)

#target_compile_features(capchk PRIVATE cxx_range_for cxx_auto_type)

#llvm 7.0 breaks out of tree .so for opt, resulting in undefined symbol
# _ZN4llvm23EnableABIBreakingChecksE
#adding _GLIBCXX_USE_CXX11_ABI=0 to fix this

set_target_properties(capchk PROPERTIES
	COMPILE_FLAGS "-fno-rtti -D_GLIBCXX_USE_CXX11_ABI=0"
	)


