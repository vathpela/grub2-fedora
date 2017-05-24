#!/bin/bash
#
# build.sh
# Copyright (C) 2018 Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#
set -e
set -u

autogen=0 || :
configure=0 || :
annobin=1
scp=0 || :
werror="" || :
clean=0 || :
clean_set=0 || :
host=192.168.124.72
CFLAGS=""
dbgcfg=()
std=""
verbose=""

while [[ $# -gt 0 ]]; do
    case " ${1} " in
        " --scp ")
            scp=1
            ;;
        " --no-scp ")
            scp=0
            ;;
        " --std ")
            std=--std=$2
            shift
            ;;
        " --std="*)
            std=${1}
            ;;

        " --annobin ")
            annobin=1
            ;;
        " --no-annobin ")
            annobin=0 || :
            ;;
        " --autogen ")
            autogen=1
            ;;
        " --no-autogen ")
            autogen=0
            ;;
        " --configure ")
            configure=1
            ;;
        " --no-configure ")
            configure=0
            ;;
        " --clean ")
            clean_set=1
            clean=1
            ;;
        " --no-clean ")
            clean_set=1
            clean=0
            ;;
        " --no-werror ")
            werror="--disable-werror"
            ;;
        " --werror ")
            werror=""
            CFLAGS="-Werror ${CFLAGS}"
            ;;
        " --host="*)
            host="${1:7}"
            ;;
        " --host ")
            host="${2}"
            shift
            ;;
        " --debugcfg ")
            dbgcfg=("-c" "grubgdb.cfg")
            ;;
        " --debugcfg="*)
            dbgcfg=("-c" "${1:11}")
            ;;
        " --no-debugcfg ")
            dbgcfg=()
            ;;
        " --verbose ")
            verbose="-v"
            ;;
        *)
            echo "Bad argument '${1}'" 1>&2
            exit 1
            ;;
    esac
    shift
done

if [[ ${clean_set} -lt 1 && ${configure} -gt 0 ]] ; then
    clean=1
fi

if [[ ${configure} -gt 0 ]] || [[ ! -e Makefile ]] ; then
    declare annobin_str=""
    if [[ ${annobin} -gt 0 ]]; then
        annobin_str="-specs=/usr/lib/rpm/redhat/redhat-annobin-cc1"
    fi
    if [[ ${autogen} -gt 0 ]] || [[ ! -f ../configure ]] ; then
        pushd ..
        ./autogen.sh
        popd
    fi
    echo ../configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info "CFLAGS=${CFLAGS} ${std} -fno-strict-aliasing -g3 -pipe -Wall -Wextra -Werror=format-security  -Wp,-D_GLIBCXX_ASSERTIONS   -grecord-gcc-switches ${annobin_str} -m64 -mtune=generic  -fstack-clash-protection -I/home/pjones/devel/github.com/grub2/for-upstream/build-x64/" 'CPPFLAGS= -I/home/pjones/devel/github.com/grub2/for-upstream/build-x64/' TARGET_LDFLAGS=-static --with-platform=efi --target=x86_64-redhat-linux-gnu --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount $werror --enable-eh-frame --enable-unwind-tables --enable-async-unwind-tables
    ../configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info "CFLAGS=${CFLAGS} ${std} -fno-strict-aliasing -g3 -pipe -Wall -Wextra -Werror=format-security  -Wp,-D_GLIBCXX_ASSERTIONS   -grecord-gcc-switches ${annobin_str} -m64 -mtune=generic  -fstack-clash-protection -I/home/pjones/devel/github.com/grub2/for-upstream/build-x64/" 'CPPFLAGS= -I/home/pjones/devel/github.com/grub2/for-upstream/build-x64/' TARGET_LDFLAGS=-static --with-platform=efi --target=x86_64-redhat-linux-gnu --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount $werror --enable-eh-frame --enable-unwind-tables --enable-async-unwind-tables
    if [[ ${clean} -gt 0 ]] ; then
        make clean
    fi
fi

for x in ../util/grub-mkimage32.c ../util/grub-mkimage64.c ; do
    if [[ ${x} -ot ../util/grub-mkimagexx.c ]] ; then
        touch "${x}"
    fi
done

make

set -x
./grub-mkimage ${verbose} -O x86_64-efi -o grubx64.efi.orig "${dbgcfg[@]}" -p /EFI/test -d grub-core all_video boot btrfs cat chain configfile echo efifwsetup efinet ext2 fat font gfxmenu gfxterm gzio halt hfsplus iso9660 jpeg loadenv loopback lvm lsefi mdraid09 mdraid1x minicmd normal part_apple part_msdos part_gpt password_pbkdf2 png reboot search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg test tftp video xfs backtrace http linux usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug
rm -vf grubx64.efi
pesign -i grubx64.efi.orig -o grubx64.efi -c 'Red Hat Test Certificate' -n /etc/pki/pesign-rh-test/ -s
if [[ "${annobin}" -eq 0 ]] ; then
    cp -f grubx64.efi grubx64.efi.no-annobin
fi

if [[ "${scp}" -gt 0 ]] ; then
    scp grubx64.efi "root@${host}:/boot/efi/EFI/test/grubx64.efi"
    ssh "root@${host}" systemctl reboot --firmware-setup
fi
