#!/bin/bash
# this little script will make life easier
# 2018 Tong Zhang<t.zhang2@partner.samsung.com>

function build
{
#specify non default compiler here
#-DCMAKE_C_COMPILER= 
#-DCMAKE_CXX_COMPILER= 
    mkdir build
    pushd build
    cmake ../ \
        -DLLVM_DIR=/opt/toolchain/llvm-git \
        -DLLVM_ROOT=/opt/toolchain/llvm-git \
        -DCMAKE_BUILD_TYPE=Debug \

    make -j
    popd
}

codedir=(
capchk
include
libsvf
)
scope_file=".scopefile"
tag_file="tags"

function gen_scope
{
    > ${scope_file}
    for d in ${codedir[@]}; do
        find $d -type f \
            -a \( -name "*.h" -o -name "*.hpp" -o -name "*.cpp" -o -name "*.c" \
            -o -name "*.cc" \) >> ${scope_file}
    done
    rm -f scope.* ${tag_file}
    ctags -I "__THROW __nonnull __attribute_pure__ __attribute__ G_GNUC_PRINTF+" \
    --file-scope=yes --c++-kinds=+px --c-kinds=+px --fields=+iaS -Ra --extra=+fq \
    --langmap=c:.c.h.pc.ec --languages=c,c++ --links=yes \
    -f ${tag_file} -L ${scope_file}
    cscope -Rb -i ${scope_file}
}

case $1 in
    "tag")
        gen_scope
        ;;
    "build")
        build
        ;;
    "clean")
        rm -rf build
        rm -f ${tag_file} ${scope_file} cscope.out
        ;;
    *)
        build
        ;;
esac

