#!/bin/bash
#
# build.sh
# Copyright (C) 2018 Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#
set -eu

export PS4='${LINENO}: '

annobin=yes
arch=x64
autogen=no
bear=no
blscfg="blscfg"
ccache="" || :
CFLAGS_PRE=(
            -fno-strict-aliasing
            -fstack-clash-protection
            -g3
            -grecord-gcc-switches
            -pipe
            "-Wp,-D_GLIBCXX_ASSERTIONS"
        )
DISTRO_CFLAGS_PRE=() || :
W_CFLAGS=(
          -Wno-unused-parameter
          -Wno-unused-variable
          -Wall
          -Wextra
      )
CFLAGS_POST=(-Wno-error=format-nonliteral)
DISTRO_CFLAGS_POST=() || :
clean=no
clean_set=no
configure=no
declare -a configargs
configargs=()
DASHX=""
declare -a dbgcfg
dbgcfg=()
efiarch=x64
efidir=BOOT
eject=no
gnulib_url="https://github.com/rhboot/gnulib.git"
gnulib_revision="fixes"
upstream_gnulib="no"
upstream="no"
grubarch=x64
harden="yes" || :
host="" || :
instfile=grub${efiarch}.efi
inst=no
mountpoint=/run/media/pjones/6DE3-F128
declare -a smp_flags
smp_flags=(-j)
paths=(
       --bindir=/usr/bin
       --datadir=/usr/share
       --exec-prefix=/usr
       --includedir=/usr/include
       --infodir=/usr/share/info
       --localstatedir=/var
       --libdir=/usr/lib
       --libexecdir=/usr/libexec
       --mandir=/usr/share/man
       --prefix=/usr
       --sbindir=/usr/sbin
       --sharedstatedir=/var/lib
       --sysconfdir=/etc
   )
pie=()
platform=efi
pubhtml=no
scp=no
scphost=10.20.1.111
std=(-std=gnu99) || :
target="" || :
unwind=()
with_werror=yes
verbose="" || :
scan="no"
MAKE="make"
deploysh="" || :
declare -a enables
enables=() || :
hostutils=() || :

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
        echo "             [--ccache|--no-ccache] [--verbose] [--scan] \\"
        echo "             [--upstream-gnulib|--no-upstream-gnulib] \\"
        echo "             [--no-parallel-make] \\"
        echo "             [--deploy DEPLOYSCRIPT] [--hostutils] \\"
        echo "             [--enable-FOO] [--disable-FOO] "
    ) >> "${out}"
    exit "${status}"
}

while [[ $# -gt 0 ]]; do
    case " ${1} " in
        " --annobin ")
            annobin=yes
            ;;
        " --no-annobin ")
            annobin=no
            ;;
        " --arch ")
            arch=${2}
            shift
            ;;
        " --arch="*)
            arch="${1:7}"
            ;;
        " --autogen ")
            autogen=yes
            ;;
        " --no-autogen ")
            autogen=no
            ;;
        " --bear ")
            bear=yes
            ;;
        " --no-bear ")
            bear=no
            ;;
        " --blscfg ")
            blscfg="blscfg"
            ;;
        " --no-blscfg ")
            blscfg="" || :
            ;;
        " --clang ")
            HOST_CC=clang
            TARGET_CC=clang
            BUILD_CC=clang
            ;;
        " --ccache "|" --with=ccache "|" --with-ccache ")
            ccache=yes
            ;;
        " --no-ccache "|" --without=ccache "|" --without-ccache ")
            ccache=""
            ;;
        " --configure ")
            configure=yes
            ;;
        " --no-configure ")
            configure=no
            ;;
        " --clean ")
            clean_set=yes
            clean=yes
            ;;
        " --no-clean ")
            clean_set=yes
            clean=no
            ;;
        " --deploy ")
            deploysh="${2}"
            shift
            ;;
        " --deploy="*)
            deploysh="${1:9}"
            ;;
        " --debugcfg ")
            dbgcfg=("-c" "../../debug.cfg")
            ;;
        " --debugcfg="*)
            dbgcfg=("-c" "${1:11}")
            ;;
        " --no-debugcfg ")
            dbgcfg=()
            ;;
        " --disable-"*" "|" --enable-"*" ")
            enables[${#enables[@]}]="${1}"
            ;;
        " --eject ")
            eject=yes
            ;;
        " --no-eject ")
            eject=no
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
        " --hostutils ")
            hostutils=(--with-utils=host)
            ;;
        " --install ")
            inst=yes
            ;;
        " --no-inst ")
            inst=no
            ;;
        " --no-parallel-make ")
            smp_flags=() || :
            ;;
        " --pie ")
            pie=("${2}")
            shift
            ;;
        " --pie="*)
            pie=("${1:6}")
            ;;
        " --platform ")
            platform="${2}"
            shift
            ;;
        " --platform="*)
            platform=${1:11}
            ;;
        " --pubhtml ")
            pubhtml=yes
            ;;
        " --no-pubhtml ")
            pubhtml=no
            ;;
        " --scan ")
            scan="yes"
            HOST_CC=clang
            BUILD_CC=clang
            TARGET_CC=clang
            ;;
        " --no-scan ")
            scan="no"
            ;;
        " --scp ")
            scp=yes
            ;;
        " --no-scp ")
            scp=no
            ;;
        " --scphost ")
            scphost="${2}"
            shift
            ;;
        " --scphost="*)
            scphost="${1:7}"
            ;;
        " --scp-host ")
            scphost="${2}"
            shift
            ;;
        " --scp-host="*)
            scphost="${1:11}"
            ;;
        " --scrub-a"*" ")
            rm -rf [0123456789Macdefghijklmnopqrstuvwxyz]* build-grub-mkfont build ../gnulib
            ;;
        " --scrub ")
            rm -rf [0123456789Macdefghijklmnopqrstuvwxyz]* build-grub-mkfont build
            ;;
        " --scrub-o"*" ")
            find . '(' -iname '*.[oa138]' -o -iname '*.mod' -o -iname '*.module' -o -iname '*.img' -o -iname '*.exec' -o -iname '.dirstamp' -o -iname '*.marker' -o -iname '*.lst' ')' -exec rm -vf {} \;
            ;;
        " --std "|" -std ")
            std=("-std=$2")
            shift
            ;;
        " --std="*)
            std=("${1:6}")
            ;;
        " -std="*)
            std=("${1:5}")
            ;;
        " --target ")
            target="${2}"
            shift
            ;;
        " --target="*)
            target="${1:9}"
            ;;
        " --trace ")
            DASHX="-x"
            ;;
        " --no-trace ")
            DASHX=""
            ;;
        " --upstream-gnulib ")
            upstream_gnulib="yes"
            ;;
        " --no-upstream-gnulib ")
            upstream_gnulib="no"
            ;;
        " --upstream ")
            shift
            upstream="yes"
            set -- --upstream --disable-werror --no-annobin --upstream-gnulib --no-blscfg --no-unwind --no-harden --pie=--no-pie "${@}"
            ;;
        " --no-werror ")
            with_werror=no
            ;;
        " --werror ")
            with_werror=yes
            ;;
        " --rhel7 "|" --rhel-7 ")
            DISTRO_CFLAGS_PRE=(
                               -Wformat-security
                               -Wno-pointer-sign
                               -Wno-sign-compare
                           )
            DISTRO_CFLAGS_POST=(
                                -Wno-error=address-of-packed-member
                                -Wno-error=implicit-fallthrough
                                -Wno-error=pointer-sign
                                -Wno-error=sign-compare
                            )
            ;;
        " --unwind ")
            unwind=(--enable-eh-frame --enable-unwind-tables --enable-async-unwind-tables)
            ;;
        " --no-unwind ")
            unwind=() || :
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

if [[ "${bear}" = yes ]] ; then
    BUILD_CC=clang
    HOST_CC=clang
    TARGET_CC=clang
    SCAN="bear --"
    #configure=yes
fi

if [[ "${with_werror}" = yes ]] ; then
    werror=(--enable-werror)
    W_CFLAGS=("${W_CFLAGS[@]}" -Werror)
else
    werror=(--disable-werror)
fi

if [[ "${upstream}" == "no" ]] ; then
    configargs[${#configargs[@]}]="--with-rpm-version=grub2-2.02-56.fc29"
fi

TARGET_CC=${TARGET_CC:-gcc}
if [[ -z "${target}" ]] || [[ "${TARGET_CC}" = gcc ]] && [[ -n "${target}" ]] ; then
    if [[ -z "${target}" ]] ; then
        target="${arch}-linux-gnu"
    fi
    if [[ -f "/usr/bin/${target}-gcc" ]] ; then
        TARGET_CC="${target}-gcc"
    fi
fi

BUILD_CC=${BUILD_CC:-gcc}
HOST_CC=${HOST_CC:-gcc}
if [[ -z "${host}" ]] || [[ "$HOST_CC" = gcc ]] && [[ -n "${host}" ]] ; then
    if [[ -z "${host}" ]] ; then
        host="${arch}-linux-gnu"
    fi
    if [[ -f /usr/bin/${host}-gcc ]] ; then
        HOST_CC="${host}-gcc"
    fi
fi

host="${host:-x86_64-redhat-linux-gnu}"
target="${target:-x86_64-redhat-linux-gnu}"

case "$(uname -m | sed -e 's,i.86,i686,g' -e 's,arm.*,arm,g')" in
  x86_64)
    host_arch_cflags=(-fcf-protection)
    ;;
  i686)
    host_arch_cflags=(-fcf-protection)
    ;;
  arm)
    host_arch_cflags=()
    ;;
  aarch64)
    host_arch_cflags=()
    ;;
esac

case "${arch}" in
  x64|x86_64)
    grubarch=x86_64
    efiarch=x64
    arch=x86_64
    compiler=gcc
    target_arch_cflags=(-m64 -fcf-protection)
    ;;
  i?86|ia32)
    grubarch=i386
    efiarch=ia32
    arch=i386
    compiler=gcc
    target_arch_cflags=(-m32 -fcf-protection)
    ;;
  arm)
    grubarch=arm
    efiarch=arm
    arch=arm
    compiler=${arch}-linux-gnu-gcc
    target_arch_cflags=(
                        -ffixed-r9
                        -fno-common
                        -mabi=aapcs-linux
                        -march=armv7-a
                        -mno-unaligned-access
                        -msoft-float
                        -mtune=generic-armv7-a
                    )
    ;;
  arm64|aa64|aarch64)
    grubarch=arm64
    efiarch=aa64
    arch=aarch64
    compiler=${arch}-linux-gnu-gcc
    target_arch_cflags=() || :
    ;;
  *)
    echo "Bad arch ${arch}" 1>&2
    exit 1
esac

if [[ "${compiler}" = gcc ]] && [[ -f "/usr/bin/${target}-${compiler}" ]] ; then
    TARGET_CC="${target}-${compiler}"
fi

if [[ "${TARGET_CC}" != gcc ]] ; then
    harden=no
fi

if [[ "${scan}" = yes ]] ; then
    if [[ "${harden}" = yes ]] ; then
        echo "Warning: disabling --harden for --scan"
        harden=no
    fi
    if [[ "${annobin}" = yes ]] ; then
        echo "Warning: disabling --annobin for --scan"
        annobin=no
    fi
fi

if [[ "${harden}" = yes ]] ; then
    hardened_cc=(-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1)
    hardened_ld=(\
                 -specs=/usr/lib/rpm/redhat/redhat-hardened-ld
             )
else
    hardened_cc=() || :
    hardened_ld=() || :
fi

hardened_ld=("${hardened_ld[@]}"
             "-Wl,--as-needed"
             "-Wl,-z,now"
             "-Wl,-z,relro"
         )

if [[ "${ccache}" = yes ]] ; then
    ccache=$(find /usr/lib*/ccache/ '(' -type f -o -type l ')' -a -iname "${target}-gcc" 2>/dev/null | head -1)
fi

if [[ "${efidir}" = BOOT ]] ; then
  instfile="BOOT${efiarch^^*}.EFI"
else
  instfile="grub${efiarch}.efi"
fi

if [[ ${clean_set} = yes ]] && [[ ${configure} = yes ]] ; then
    clean=yes
fi

declare annobin_str=()
if [[ ${configure} = yes ]] || [[ ! -e Makefile ]] ; then
    if [[ ${annobin} = yes ]]; then
        annobin_str=(-specs=/usr/lib/rpm/redhat/redhat-annobin-cc1)
    fi
    if [[ -f ../configure ]] ; then
        CONFIGURE=../configure
    elif [[ -f ./configure ]] ; then
        CONFIGURE=./configure
    fi
    if [[ ${autogen} != "no" ]] || [[ -z "${CONFIGURE}" ]] ; then
        if [[ -f configure.ac ]] || [[ -f configure.in ]] ; then
            pushd .
        else
            pushd ..
        fi
        if [[ -f bootstrap ]] ; then
            declare -a bootstrap_vars=()
            if [[ "${upstream_gnulib}" = "yes" ]] ; then
                if [[ -n "${gnulib_url}" ]] ; then
                  bootstrap_vars[${#bootstrap_vars[@]}]="GNULIB_URL=\"${gnulib_url}\""
                fi
                if [[ -n "${gnulib_revision}" ]] ; then
                  bootstrap_vars[${#bootstrap_vars[@]}]="GNULIB_REVISION=\"${gnulib_revision}\""
                fi
            fi
            eval echo "${bootstrap_vars[@]}" PYTHON=python3 ./bootstrap
            eval "${bootstrap_vars[@]}" PYTHON=python3 ./bootstrap
        else
            autoreconf -vi || :
            autoconf
            # shellcheck disable=SC2086
            PYTHON=python3 bash ${DASHX} ./autogen.sh
        fi
        popd
    fi
    if [[ -f ../configure ]] ; then
        CONFIGURE=../configure
    elif [[ -f ./configure ]] ; then
        CONFIGURE=./configure
    fi
    if [[ -f "${ccache}${HOST_CC}" ]] ; then
        HOST_CC="${ccache}${HOST_CC}"
    fi
    if [[ -f "${ccache}${TARGET_CC}" ]] ; then
        TARGET_CC="${ccache}${TARGET_CC} ${pie[*]}"
    fi
    CFLAGS=("${CFLAGS_PRE[@]}" "${DISTRO_CFLAGS_PRE[@]}" "${W_CFLAGS[@]}" "${CFLAGS_POST[@]}" "${DISTRO_CFLAGS_POST[@]}")
    HOST_CPPFLAGS=("-I$PWD")
    HOST_CFLAGS=(-Og "${CFLAGS[@]}" "${std[@]}" "${annobin_str[@]}" "${host_arch_cflags[@]}" "${hardened_cc[@]}" "${pie[@]}")
    HOST_LDFLAGS=("${hardened_ld[@]}")
    TARGET_CPPFLAGS=("-I$PWD")
    TARGET_CFLAGS=(-Os "${target_arch_cflags[@]}" "${pie[@]}")
    if [[ "${harden}" == yes ]] ; then
        TARGET_LDFLAGS=("-Wl,-z,relro" "-Wl,--as-needed" -static)
    else
        TARGET_LDFLAGS=("-Wl,--as-needed" -static)
    fi

    TARGETSTUFF=("BUILD_CC=${BUILD_CC}"
                 "CC=${BUILD_CC} ${pie[@]}"
                 "HOST_CC=${HOST_CC}"
                 "HOST_CFLAGS=${HOST_CFLAGS[*]}"
                 "HOST_CPPFLAGS=${HOST_CPPFLAGS[*]}"
                 "HOST_LDFLAGS=${HOST_LDFLAGS[*]}"
                 "TARGET_CC=${TARGET_CC}"
                 "TARGET_CFLAGS=${TARGET_CFLAGS[*]}"
                 "TARGET_CPPFLAGS=${TARGET_CPPFLAGS[*]}"
                 "TARGET_LDFLAGS=${TARGET_LDFLAGS[*]}"
             )
    set +x
    echo PYTHON=python3 "${CONFIGURE}" PYTHON=python3 --build=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking "${paths[*]}" "${TARGETSTUFF[@]}" --with-platform="${platform}" --disable-werror --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount --disable-efiemu "${werror[@]}" "${unwind[@]}" --target="${target}" "${configargs[@]}" --host="${host}" "${enables[@]}" "${hostutils[@]}"
    # shellcheck disable=SC2086
    PYTHON=python3 bash ${DASHX} ${CONFIGURE} PYTHON=python3 --build=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking "${paths[*]}" "${TARGETSTUFF[@]}" --with-platform="${platform}" --disable-werror --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount --disable-efiemu "${werror[@]}" "${unwind[@]}" --target="${target}" "${configargs[@]}" --host="${host}" "${enables[@]}" "${hostutils[@]}"
    set -x
    if [[ ${clean} = yes ]] ; then
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
if [[ "${curdir:0:5}" == "build" ]] || [[ -f ./configure ]] ; then
  build_pfx="" || :;
else
  build_pfx="build/"
fi
rm -vf ${build_pfx}include/grub/{cpu,machine}
mkdir -p include/grub/
ln -vs ../../../include/grub/${grubarch} ${build_pfx}include/grub/cpu
ln -vs ../../../include/grub/${grubarch}/efi ${build_pfx}include/grub/machine

SCAN="${SCAN:-}" || :
if [[ "${scan}" = yes ]] ; then
    export SCAN="scan-build"
fi

set +x
echo PYTHON=python3 ${SCAN} ${MAKE} PYTHON=python3 ${HOST_CC:+HOST_CC="${HOST_CC}"} ${TARGET_CC:+TARGET_CC="${TARGET_CC}"}
PYTHON=python3 ${SCAN} ${MAKE} PYTHON=python3 "${smp_flags[@]}" ${HOST_CC:+HOST_CC="${HOST_CC}"} ${TARGET_CC:+TARGET_CC="${TARGET_CC}"}
set -x

declare -a MODULE_CANDIDATES
MODULE_CANDIDATES=(\
 all_video \
 backtrace "${blscfg}" boot btrfs \
 cat chain configfile \
 echo efifwsetup efinet ext2 \
 fat font \
 gfxmenu gfxterm gzio \
 halt hfsplus http \
 iso9660 \
 jpeg \
 linux loadenv loopback lvm lsefi lsefimmap \
 mdraid09 mdraid1x minicmd \
 part_apple part_msdos part_gpt password_pbkdf2 png \
 raid6rec reboot \
 search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg \
 test tftp \
 usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug \
 video \
 xfs \
)

declare -a MODULES
MODULES=(normal)

mkmodlist() {
    local mods="MODULES"
    local -n mods
    local mod
    for mod in "${MODULE_CANDIDATES[@]}" ; do
        if [[ -f grub-core/${mod}.mod ]] ; then
            mods[${#mods[@]}]="${mod}"
        else
            echo "warning: ${mod}.mod not found"
        fi
    done
}

set -x
mkmodlist
echo ./grub-mkimage ${verbose} -O ${grubarch}-efi -o grub${efiarch}.efi.orig "${dbgcfg[@]}" -p /EFI/${efidir} -d grub-core "${MODULES[@]}"
./grub-mkimage ${verbose} -O ${grubarch}-efi -o grub${efiarch}.efi.orig "${dbgcfg[@]}" -p /EFI/${efidir} -d grub-core "${MODULES[@]}"
echo pesign -f -i grub${efiarch}.efi.orig -o grub${efiarch}.efi -c 'Red Hat Test Certificate' -n /etc/pki/pesign-rh-test/ -s
pesign -f -i grub${efiarch}.efi.orig -o grub${efiarch}.efi -c 'Red Hat Test Certificate' -n /etc/pki/pesign-rh-test/ -s
if [[ "${annobin}" != yes ]] ; then
    cp -vf grub${efiarch}.efi grub${efiarch}.efi.no-annobin
fi

if [[ -n "${deploysh}" ]] ; then
    "${deploysh}" "grub${efiarch}.efi"
fi

if [[ "${scp}" = yes ]] ; then
    ssh "root@${scphost}" ./start.sh
    scp grubx64.efi "root@${scphost}:/boot/efi/EFI/test/grubx64.efi"
    ssh "root@${scphost}" sh -c ": ; ./stop.sh ; efibootmgr -n 0003 ; systemctl reboot ; :"
    # ssh "root@${scphost}" sh -c ": ; ./setup.sh ; systemctl reboot --firmware-setup ; :"
fi

if [[ "${pubhtml}" = yes ]] ; then
    cp -v grub${efiarch}.efi ~pjones/public_html/f28-ws-netinst/EFI/"${efidir}/${instfile}"
fi

if [[ -d "${mountpoint}" ]] ; then
  if [[ "${inst}" = yes ]] ; then
    cp -v grub${efiarch}.efi "${mountpoint}/EFI/${efidir}/${instfile}"
    umount -v "${mountpoint}"
  fi

  if [[ "${eject}" = yes ]] ; then
    echo "ejecting ${ejectdev}"
    eject "${ejectdev}"
  fi
fi

# vim:sw=4:sts=4:ts=8:sw=4:et
