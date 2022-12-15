#!/bin/bash
#
# test-build.sh - 
# Copyright Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#

set -eu
set -o pipefail
set -x

# export CCACHE_DISABLE=true

main() {
    pwd
    rm -rf build-x64 __pycache__ gnulib
    # git clean -X -f
    mkdir build-x64
    if [[ -e ../include ]] ; then
        echo WHAT THE HELL
        exit 1
    fi
    cd build-x64
    local BUILDARGS="--upstream-gnulib \
                     --no-hostutils \
                     --upstream \
                     --no-werror \
                     --autogen \
                     --configure"
    # shellcheck disable=SC2086
    time ../../build.sh ${BUILDARGS} || time ../../build.sh ${BUILDARGS}
}

main "${@}"

# vim:fenc=utf-8:tw=75
