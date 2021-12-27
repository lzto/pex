/*
 * This is knobs for gatlin
 * This file should only be included in gatlin.cpp
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _CAPCHK_KNOBS_
#define _CAPCHK_KNOBS_

#include "llvm/Support/CommandLine.h"
/*
 * command line options
 */
cl::opt<std::string>
    knob_gating_type("gating",
                     cl::desc("gating function: cap/lsm - default: cap"),
                     cl::init("cap"));

cl::opt<bool> knob_gatlin_critical_var(
    "ccv", cl::desc("check critical variable usage - disabled by default"),
    cl::init(false));

cl::opt<bool> knob_gatlin_critical_fun(
    "ccf", cl::desc("check critical function usage - enabled by default"),
    cl::init(true));

cl::opt<bool> knob_gatlin_critical_type_field(
    "cct", cl::desc("check critical type field usage - disable by default"),
    cl::init(false));

cl::opt<bool> knob_gatlin_ccfv(
    "ccfv",
    cl::desc(
        "print path to critical function(collect phase) - disabled by default"),
    cl::init(false));

cl::opt<bool> knob_gatlin_ccvv(
    "ccvv",
    cl::desc(
        "print path to critical variable(collect phase) - disabled by default"),
    cl::init(false));

cl::opt<bool>
    knob_gatlin_cctv("cctv",
                     cl::desc("print path to critical type field(collect "
                              "phase) - disabled by default"),
                     cl::init(false));

cl::opt<bool> knob_gatlin_f2c("f2c",
                              cl::desc("print critical function to gating "
                                       "function mapping - enabled by default"),
                              cl::init(true));

cl::opt<bool> knob_gatlin_v2c("v2c",
                              cl::desc("print critical variable to gating "
                                       "function mapping - enabled by default"),
                              cl::init(true));

cl::opt<bool> knob_gatlin_t2c("t2c",
                              cl::desc("print critical type field to gating "
                                       "function mapping - enable by default"),
                              cl::init(true));

cl::opt<bool> knob_gatlin_caw(
    "caw",
    cl::desc(
        "print check functions and wrappers discovered - enabled by default"),
    cl::init(true));

cl::opt<bool> knob_gatlin_kinit(
    "kinit", cl::desc("print kernel init functions - enabled by default"),
    cl::init(true));

cl::opt<bool> knob_gatlin_nkinit(
    "nkinit", cl::desc("print kernel non init functions - enabled by default"),
    cl::init(true));

cl::opt<bool>
    knob_gatlin_kmi("kmi",
                    cl::desc("print kernel interface - disabled by default"),
                    cl::init(false));

cl::opt<bool>
    knob_gatlin_dkmi("dkmi",
                     cl::desc("print dkmi result - disabled by default"),
                     cl::init(false));

cl::opt<bool>
    knob_gatlin_cvf("cvf", cl::desc("complex value flow analysis - deprecated"),
                    cl::init(false));

cl::opt<string> knob_skip_func_list("skipfun",
                                    cl::desc("non-critical function list"),
                                    cl::init("skip.fun"));

cl::opt<string> knob_skip_var_list("skipvar",
                                   cl::desc("non-critical variable name list"),
                                   cl::init("skip.var"));

cl::opt<string>
    knob_cap_function_list("capfunc",
                           cl::desc("capability check function name list"),
                           cl::init("cap.func"));

cl::opt<string> knob_lsm_function_list("lsmhook",
                                       cl::desc("lsm hook function name list"),
                                       cl::init("lsm.hook"));

cl::opt<string> knob_crit_symbol(
    "critsym",
    cl::desc("list of symbols to be treated as critical and ignore others"),
    cl::init("crit.sym"));

cl::opt<string> knob_kernel_api("kapi", cl::desc("kernel api function list"),
                                cl::init("kernel.api"));

cl::opt<bool>
    knob_dump_good_path("prt-good",
                        cl::desc("print good path - disabled by default"),
                        cl::init(false));

cl::opt<bool> knob_dump_bad_path(
    "prt-bad", cl::desc("print bad path - enabled by default"), cl::init(true));

cl::opt<bool>
    knob_dump_ignore_path("prt-ign",
                          cl::desc("print ignored path - disabled by default"),
                          cl::init(false));

cl::opt<bool> knob_warn_gatlin_during_kinit(
    "wcapchk-kinit",
    cl::desc("warn capability check during kernel boot process - disabled by "
             "default"),
    cl::init(false));

cl::opt<unsigned int>
    knob_fwd_depth("fwd-depth",
                   cl::desc("forward search max depth - default 100"),
                   cl::init(100));

cl::opt<unsigned int>
    knob_bwd_depth("bwd-depth",
                   cl::desc("backward search max depth - default 100"),
                   cl::init(100));

cl::opt<unsigned int>
    knob_mt("mt", cl::desc("Multi-threading, number of threads - default 1"),
            cl::init(1));

#endif //_CAPCHK_KNOBS_
