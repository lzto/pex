#!/bin/bash
# this little script will make life easier
# 2018 Tong Zhang<t.zhang2@partner.samsung.com>
# 2020-2021 Tong Zhang<ztong0001@gmail.com>

function build
{
    echo "NOTE: specify your own LLVM_DIR and LLVM_ROOT"
    JOBS=`getconf _NPROCESSORS_ONLN`
#specify non default compiler here
#        -DCMAKE_C_COMPILER=clang-10  \
#        -DCMAKE_CXX_COMPILER=clang++-10
    mkdir build
    pushd build
    cmake ../ \
        -DLLVM_CMAKE_PATH=/usr/lib/llvm-11/lib/cmake \
        -DCMAKE_BUILD_TYPE=Debug \

    make -j${JOBS}
    popd
}

codedir=(
gatlin
include
#pex
)

formatdir=(
gatlin
include
#pex
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

function indent
{
    for d in ${formatdir[@]}; do
	    clang-format -i -style=llvm `find $d -name '*.cpp' -or -name "*.h"`
    done
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
    "indent")
        indent
        ;;
    *)
        echo ./build.sh tag build clean indent
        ;;
esac

