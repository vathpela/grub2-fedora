#! /bin/sh
#
# build.sh
# Copyright (C) 2017 Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#

set -u
set -e

let virt=0 || :
if [ "$#" -ge 1 ]; then
    if [ "$1" == "--virt" ]; then
        virt=1
    fi
fi

if [ ! -e configure ]; then
    ./autogen.sh
fi

cd build
if [ "${virt}" -eq 1 ]; then
    sudo virsh suspend netboot >/dev/null 2>&1
fi
./build.sh
if [ "${virt}" -eq 1 ]; then
    sudo virsh reset netboot >/dev/null 2>&1
    sudo virsh resume netboot >/dev/null 2>&1
fi
