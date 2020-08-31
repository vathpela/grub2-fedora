#!/bin/bash
#
# build.sh
# Copyright (C) 2018 Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#
set -e
set -u

annobin=1
arch=x64
autogen=0 || :
blscfg="blscfg"
ccache="" || :
CFLAGS=""
clean=0 || :
clean_set=0 || :
configure=0 || :
dbgcfg=()
efiarch=x64
efidir=BOOT
eject=0
gnulib_url="https://github.com/vathpela/gnulib.git"
gnulib_revision="gcc-warnings"
grubarch=x64
harden="yes" || :
host="" || :
instfile=grub${efiarch}.efi
inst=0
mountpoint=/run/media/pjones/6DE3-F128
pie=""
platform=efi
pubhtml=0
scp=0 || :
scphost=10.20.1.111
std="" || :
target="" || :
unwind="--enable-eh-frame --enable-unwind-tables --enable-async-unwind-tables"
werror="" || :
verbose="" || :
scan=0
MAKE="make"
DISTRO_CFLAGS=""

usage() {
    local status="${1}" && shift
    local out=/dev/stdout
    if [[ "${status}" -gt 0 ]] ; then
      out=/dev/stderr
    fi
    (
        echo "usage: build [--efidir DIR] [--arch ARCH] [--bootnum ####] \\"
        echo "             [--scp|--no-scp] [--scphost SCPHOST] \\"
        echo "             [--std STD] [--pubhtml] [--annobin|--no-annobin] [--autogen|--no-autogen] \\"
        echo "             [--configure|--no-configure] [--clean|--no-clean] [--werror|--no-werror] \\"
        echo "             [--host HOST] [--debugcfg|--debugcfg=CFG|--no-debugcfg] \\"
        echo "             [--platform PLATFORM] [--scrub] [--scrub-objs] \\"
        echo "             [--ccache|--no-ccache] [--verbose] [--scan]"
    ) >> "${out}"
    exit "${status}"
}

while [[ $# -gt 0 ]]; do
    case " ${1} " in
        " --annobin ")
            annobin=1
            ;;
        " --no-annobin ")
            annobin=0 || :
            ;;
        " --arch ")
            arch=${2}
            shift
            ;;
        " --arch="*)
            arch="${1:7}"
            ;;
        " --autogen ")
            autogen=1
            ;;
        " --no-autogen ")
            autogen=0
            ;;
        " --blscfg ")
            blscfg="blscfg"
            ;;
        " --no-blscfg ")
            blscfg="" || :
            ;;
        " --ccache "|" --with=ccache "|" --with-ccache ")
            ccache=yes
            ;;
        " --no-ccache "|" --without=ccache "|" --without-ccache ")
            ccache=""
            ;;
        " --configure ")
            configure=1
            ;;
        " --no-configure ")
            configure=0 || :
            ;;
        " --clean ")
            clean_set=1
            clean=1
            ;;
        " --no-clean ")
            clean_set=1
            clean=0 || :
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
        " --eject ")
            eject=1
            ;;
        " --no-eject ")
            eject=0
            ;;
        " --ejectdev ")
            ejectdev="${2}"
            shift
            ;;
        " --ejectdev="*)
            ejectdev="${1:11}"
            ;;
        " --gnulib-url="*)
            gnulib_url="${1:13}"
            ;;
        " --gnulib-url ")
            gnulib_url="${2}"
            shift
            ;;
        " --gnulib-revision="*)
            gnulib_revision="${1:18}"
            ;;
        " --gnulib-revision ")
            gnulib_revision="${2}"
            shift
            ;;
        " --harden ")
            harden=yes
            ;;
        " --no-harden ")
            harden=no
            ;;
        " --host="*)
            host="${1:7}"
            ;;
        " --host ")
            host="${2}"
            shift
            ;;
        " --install ")
            inst=1
            ;;
        " --no-inst ")
            inst=0
            ;;
        " --pie ")
            pie="${2}"
            shift
            ;;
        " --pie="*)
            pie="${1:6}"
            ;;
        " --platform ")
            platform="${2}"
            shift
            ;;
        " --platform="*)
            platform=${1:11}
            ;;
        " --pubhtml ")
            pubhtml=1
            ;;
        " --scan ")
            scan=1
            ;;
        " --no-scan ")
            scan=0
            ;;
        " --scp ")
            scp=1
            ;;
        " --no-scp ")
            scp=0
            ;;
        " --scphost ")
            scphost="${2}"
            shift
            ;;
        " --scphost="*)
            scphost="${1:7}"
            ;;
        " --scp-host ")
            scp-host="${2}"
            shift
            ;;
        " --scp-host="*)
            scphost="${1:11}"
            ;;
        " --scrub ")
            rm -rf [0123456789Macdefghijklmnopqrstuvwxyz]* build-grub-mkfont build ../gnulib
            ;;
        " --scrub-o"*" ")
            find . '(' -iname '*.[oa138]' -o -iname '*.mod' -o -iname '*.module' -o -iname '*.img' -o -iname '*.exec' -o -iname '.dirstamp' -o -iname '*.marker' -o -iname '*.lst' ')' -exec rm -vf {} \;
            ;;
        " --std ")
            std=--std=$2
            shift
            ;;
        " --std="*)
            std=${1}
            ;;
        " --target ")
            target="${2}"
            shift
            ;;
        " --target="*)
            target="${1:9}"
            ;;
        " --no-werror ")
            werror="--disable-werror"
            ;;
        " --werror ")
            werror=""
            CFLAGS="-Werror ${CFLAGS}"
            ;;
        " --rhel7 "|" --rhel-7 ")
            DISTRO_CFLAGS="-Wno-error=implicit-fallthrough -Wno-error=address-of-packed-member -Wno-error=pointer-sign -Wno-pointer-sign -Wno-sign-compare -Wno-error=sign-compare"
            ;;
        " --no-unwind ")
            unwind="" || :
            ;;
        " --verbose ")
            verbose="-v"
            ;;
        *)
            echo "Bad argument '${1}'" 1>&2
            usage 1
            ;;
    esac
    shift
done

TARGET_CC=${TARGET_CC:-gcc}
if [[ -z "${target}" ]] || [[ "${TARGET_CC}" = gcc ]] && [[ -n "${target}" ]] ; then
    if [[ -z "${target}" ]] ; then
        target="${arch}-linux-gnu"
    fi
    if [[ -f "/usr/bin/${target}-gcc" ]] ; then
        TARGET_CC="${target}-gcc"
    fi
fi

HOST_CC=${HOST_CC:-gcc}
if [[ -z "${host}" ]] || [[ "$HOST_CC" = gcc ]] && [[ -n "${host}" ]] ; then
    if [[ -z "${host}" ]] ; then
        host="${arch}-linux-gnu"
    fi
    if [[ -f /usr/bin/${host}-gcc ]] ; then
        HOST_CC="${host}-gcc"
    fi
fi

case "$(uname -m | sed -e 's,i.86,i686,g' -e 's,arm.*,arm,g')" in
  x86_64)
    host_arch_cflags="-fcf-protection"
    ;;
  i686)
    host_arch_cflags="-fcf-protection"
    ;;
  arm)
    host_arch_cflags=""
    ;;
  aarch64)
    host_arch_cflags=""
    ;;
esac

case "${arch}" in
  x64|x86_64)
    grubarch=x86_64
    efiarch=x64
    arch=x86_64
    compiler=gcc
    target_arch_cflags="-m64 -fcf-protection"
    ;;
  i?86|ia32)
    grubarch=i386
    efiarch=ia32
    arch=i386
    compiler=gcc
    target_arch_cflags="-m32 -fcf-protection"
    ;;
  arm)
    grubarch=arm
    efiarch=arm
    arch=arm
    compiler=${arch}-linux-gnu-gcc
    target_arch_cflags="-mabi=aapcs-linux -mno-unaligned-access -fno-common -ffixed-r9 -msoft-float -march=armv7-a -mtune=generic-armv7-a"
    ;;
  arm64|aa64|aarch64)
    grubarch=arm64
    efiarch=aa64
    arch=aarch64
    compiler=${arch}-linux-gnu-gcc
    target_arch_cflags=""
    ;;
  *)
    echo "Bad arch ${arch}" 1>&2
    exit 1
esac

if [[ "${compiler}" = gcc ]] && [[ -f "/usr/bin/${target}-${compiler}" ]] ; then
    TARGET_CC="${target}-${compiler}"
fi

if [[ "${harden}" = yes ]] ; then
    hardened_cc="-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1"
    hardened_ld="-Wl,-z,relro -Wl,--as-needed -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld"
else
    hardened_cc="" || :
    hardened_ld="" || :
fi

if [[ "${ccache}" = yes ]] ; then
    ccache=$(find /usr/lib*/ccache/ '(' -type f -o -type l ')' -a -iname "${target}-gcc" 2>/dev/null | head -1)
fi

if [[ "${efidir}" = BOOT ]] ; then
  instfile="BOOT${efiarch^^*}.EFI"
else
  instfile="grub${efiarch}.efi"
fi

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
        if [[ -f bootstrap ]] ; then
            declare -a bootstrap_vars=()
            if [[ -n "${gnulib_url}" ]] ; then
              bootstrap_vars[${#bootstrap_vars[@]}]="GNULIB_URL=\"${gnulib_url}\""
            fi
            if [[ -n "${gnulib_revision}" ]] ; then
              bootstrap_vars[${#bootstrap_vars[@]}]="GNULIB_REVISION=\"${gnulib_revision}\""
            fi
            eval echo "${bootstrap_vars[@]}" PYTHON=python3 ./bootstrap
            eval "${bootstrap_vars[@]}" PYTHON=python3 ./bootstrap
        else
            autoreconf -vi
            autoconf
            PYTHON=python3 ./autogen.sh
        fi
        popd
    fi
    if [[ -f "${ccache}${HOST_CC}" ]] ; then
        HOST_CC="${ccache}${HOST_CC}"
    fi
    if [[ -f "${ccache}${TARGET_CC}" ]] ; then
        TARGET_CC="${ccache}${TARGET_CC}"
    fi
    HOST_CPPFLAGS="-I$PWD"
    HOST_CFLAGS="${CFLAGS} ${std} ${annobin_str} -Og -g3 -fno-strict-aliasing -g -pipe -Wall -Wno-unused-parameter -Wno-unused-variable -Werror=format-security -Wp,-D_GLIBCXX_ASSERTIONS -grecord-gcc-switches ${host_arch_cflags} -fstack-clash-protection ${hardened_cc} -Wno-error=format-nonliteral ${pie} ${DISTRO_CFLAGS}"
    HOST_LDFLAGS="${hardened_ld}" 
    TARGET_CPPFLAGS="-I$PWD"
    TARGET_CFLAGS="-Os -fno-strict-aliasing -g -pipe -Wall -Wno-unused-parameter -Wno-unused-variable -Werror=format-security -Wp,-D_GLIBCXX_ASSERTIONS -grecord-gcc-switches ${target_arch_cflags} -fstack-clash-protection -Wno-error=format-nonliteral ${pie} ${DISTRO_CFLAGS}"
    if [[ "${harden}" == yes ]] ; then
        TARGET_LDFLAGS="-Wl,-z,relro -Wl,--as-needed -static"
    else
        TARGET_LDFLAGS="-Wl,--as-needed -static"
    fi

    TARGETSTUFF=("HOST_CC=${HOST_CC}" \
                 "HOST_CFLAGS=${HOST_CFLAGS}" \
                 "HOST_CPPFLAGS=${HOST_CPPFLAGS}" \
                 "HOST_LDFLAGS=${HOST_LDFLAGS}" \
                 "TARGET_CC=${TARGET_CC}" \
                 "TARGET_CFLAGS=${TARGET_CFLAGS}" \
                 "TARGET_CPPFLAGS=${TARGET_CPPFLAGS}" \
                 "TARGET_LDFLAGS=${TARGET_LDFLAGS}" \
             )

    echo PYTHON=python3 ../configure PYTHON=python3 --build=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info "${TARGETSTUFF[@]}" --with-platform="${platform}" --without-werror --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount $werror ${unwind} --target="${target}" --with-rpm-version=grub2-2.02-56.fc29 --host="${host}"
    PYTHON=python3 ../configure PYTHON=python3 --build=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info "${TARGETSTUFF[@]}" --with-platform="${platform}" --without-werror --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount $werror ${unwind} --target="${target}" --with-rpm-version=grub2-2.02-56.fc29 --host="${host}"
#    ../configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info "CFLAGS=${CFLAGS} ${std} -fno-strict-aliasing -g3 -pipe -Wall -Wextra -Werror=format-security  -Wp,-D_GLIBCXX_ASSERTIONS   -grecord-gcc-switches ${annobin_str} -mtune=generic  -fstack-clash-protection -I\"${PWD}\"" "CPPFLAGS= -I\"${PWD}\"" TARGET_LDFLAGS=-static --with-platform="${platform}" --target="${target}" --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount $werror ${unwind} ${TARGETSTUFF[@]}
    if [[ ${clean} -gt 0 ]] ; then
        make clean
    fi
    find . -name Makefile -print0 | grep -Z -z -l -e '-mtune=generic' | xargs -0 sed -i -e 's/ -mtune=generic / /g' || :
fi

for x in ../util/grub-mkimage32.c ../util/grub-mkimage64.c ; do
    if [[ ${x} -ot ../util/grub-mkimagexx.c ]] ; then
        touch "${x}"
    fi
done

curdir="$(basename "$(pwd)")"
if [[ "${curdir:0:5}" == "build" ]] ; then
  build_pfx="" || :;
else
  build_pfx="build/"
fi
rm -vf ${build_pfx}include/grub/{cpu,machine}
mkdir -p include/grub/
ln -vs ../../../include/grub/${grubarch} ${build_pfx}include/grub/cpu
ln -vs ../../../include/grub/${grubarch}/efi ${build_pfx}include/grub/machine

if [[ "${scan}" = yes ]] ; then
    MAKE="scan-build"
fi

echo PYTHON=python3 ${MAKE} PYTHON=python3
PYTHON=python3 ${MAKE} PYTHON=python3 -j8

MODULES="\
 all_video \
 backtrace ${blscfg} boot btrfs cat chain configfile \
 echo efifwsetup efinet ext2 \
 fat font \
 gfxmenu gfxterm gzio \
 halt hfsplus http \
 iso9660 jpeg \
 linux loadenv loopback lvm lsefi lsefimmap \
 mdraid09 mdraid1x minicmd normal \
 part_apple part_msdos part_gpt password_pbkdf2 png \
 raid6rec reboot \
 search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg \
 test tftp \
 usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug \
 video xfs \
"

set -x
# shellcheck disable=SC2086
echo ./grub-mkimage ${verbose} -O ${grubarch}-efi -o grub${efiarch}.efi.orig "${dbgcfg[@]}" -p /EFI/${efidir} -d grub-core ${MODULES}
# shellcheck disable=SC2086
./grub-mkimage ${verbose} -O ${grubarch}-efi -o grub${efiarch}.efi.orig "${dbgcfg[@]}" -p /EFI/${efidir} -d grub-core ${MODULES}
echo pesign -f -i grub${efiarch}.efi.orig -o grub${efiarch}.efi -c 'Red Hat Test Certificate' -n /etc/pki/pesign-rh-test/ -s
pesign -f -i grub${efiarch}.efi.orig -o grub${efiarch}.efi -c 'Red Hat Test Certificate' -n /etc/pki/pesign-rh-test/ -s
if [[ "${annobin}" -eq 0 ]] ; then
    cp -vf grub${efiarch}.efi grub${efiarch}.efi.no-annobin
fi

if [[ "${scp}" -gt 0 ]] ; then
    ssh "root@${scphost}" ./start.sh
    scp grubx64.efi "root@${scphost}:/boot/efi/EFI/test/grubx64.efi"
    ssh "root@${scphost}" sh -c ": ; ./stop.sh ; efibootmgr -n 0003 ; systemctl reboot ; :"
    # ssh "root@${scphost}" sh -c ": ; ./setup.sh ; systemctl reboot --firmware-setup ; :"
fi

if [[ "${pubhtml}" -gt 0 ]] ; then
    cp -v grub${efiarch}.efi ~pjones/public_html/f28-ws-netinst/EFI/"${efidir}/${instfile}"
fi

if [[ -d "${mountpoint}" ]] ; then
  if [[ "${inst}" -eq 1 ]] ; then
    cp -v grub${efiarch}.efi "${mountpoint}/EFI/${efidir}/${instfile}"
    umount -v "${mountpoint}"
  fi

  if [[ "${eject}" -eq 1 ]] ; then
    echo "ejecting ${ejectdev}"
    eject "${ejectdev}"
  fi
fi

# vim:sw=4:sts=4:ts=4:et
