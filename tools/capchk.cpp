/*
 * standalone checker
 */
#include "XChecker/XChecker.h"

#include <llvm-c/Core.h> // for LLVMGetGlobalContext()
#include <llvm/Support/CommandLine.h>	// for cl
#include <llvm/Bitcode/BitcodeWriterPass.h>  // for bitcode write
#include <llvm/IR/LegacyPassManager.h>		// pass manager
#include <llvm/Support/Signals.h>	// singal for command line
#include <llvm/IRReader/IRReader.h>	// IR reader for bit file
#include <llvm/Support/ToolOutputFile.h> // for tool output file
#include <llvm/Support/PrettyStackTrace.h> // for pass list
#include <llvm/IR/LLVMContext.h>		// for llvm LLVMContext
#include <llvm/Support/SourceMgr.h> // for SMDiagnostic
#include <llvm/Bitcode/BitcodeWriterPass.h> // for createBitcodeWriterPass


using namespace llvm;

static cl::opt<std::string> InputFilename(cl::Positional,
        cl::desc("<input bitcode>"), cl::init("-"));

int main(int argc, char ** argv) {

    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    analysisUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value, "woof\n");

    SVFModule svfModule(moduleNameVec);

    XChecker *xaber;
    xaber = new XChecker();

    xaber->runOnModule(svfModule);

    //svfModule.dumpModulesToFile(".dvf");

    return 0;

}

