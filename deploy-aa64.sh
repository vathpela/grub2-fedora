#!/usr/bin/sudo bash
# SPDX-License-Identifier: GPLv2-or-later
#
# deploy.sh - deploy $1 to wherever
# Copyright Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
# shellcheck shell=bash
# shellcheck disable=SC2034

set -eu

guestfishcfg() {
    echo run
    echo mount /dev/sda1 /
    while [[ $# -ne 0 ]] ; do
        if [[ "${1}" =~ .*grub[[:alnum:]]+\.efi$ ]] || \
           [[ "${1}" =~ .*shim[[:alnum:]]+\.efi$ ]] ; then
            echo copy-in "${1}" /EFI/test/
            shift
        else
            echo "Dunno what to do with \"${1}\"" >/dev/stderr
            exit 1
        fi
    done
    echo "umount /"
}

set -x

main() {
    if ! [[ -e .gdbinit ]] && [[ -f ../../gdbinit ]] ; then
        ln ../../gdbinit .gdbinit
    fi

    local sb=no
    local waitgdb=no

    local -a args
    args=() || :
    while [[ $# -ne 0 ]] ; do
        case " $1 " in
            " --nosb "|" --no-sb ")
                sb=no
                ;;
            " --sb ")
                sb=yes
                ;;
            " --no-wait-gdb "|" --nowait-gdb "|" --no-waitgdb "|" --nowaitgdb ")
                waitgdb=no
                ;;
            " --waitgdb "|" --wait-gdb ")
                waitgdb=yes
                ;;
            *)
                args[${#args[@]}]="$1"
                ;;
        esac
        shift
    done
    if [[ ${#args[@]} -ne 0 ]] ; then
        set -- "${args[*]}"
    fi

    local pflash
    local codefd
    local vars
    local iso
    if [[ "$sb" = yes ]] ; then
        pflash=/usr/share/edk2/aa64-debug/QEMU_EFI-pflash.secboot.raw
        codefd=/usr/share/edk2/aa64-debug/QEMU_EFI.secboot.fd
        vars=/var/lib/libvirt/qemu/nvram/aa64-sb_VARS.fd
        iso=/usr/share/edk2/aa64-debug/UefiShell.iso
    else
        pflash=/usr/share/edk2/aa64-debug/QEMU_EFI-pflash.raw
        codefd=/usr/share/edk2/aa64-debug/QEMU_EFI.fd
        vars=/var/lib/libvirt/qemu/nvram/aa64-nosb_VARS.fd
        iso=/home/pjones/media/software/Fedora-Server-dvd-aarch64-32-1.6.iso
    fi
    local -a gdb
    if [[ "${waitgdb}" = yes ]] ; then
        gdb=(-S)
    else
        gdb=()
    fi
    if [[ $# -ne 0 ]] ; then
        virsh destroy aa64-nosb || :;
        guestfish -d aa64-nosb < <(guestfishcfg "${@}")
    fi
#        -drive if=pflash,format=raw,file="${pflash}",readonly \
#        -drive if=pflash,format=raw,file="${vars}" \
#
#        -blockdev '{"driver":"file","filename":"'"${codefd}"'","node-name":"libvirt-pflash0-storage","auto-read-only":true,"discard":"unmap"}' \
#        -blockdev '{"node-name":"libvirt-pflash0-format","read-only":true,"driver":"raw","file":"libvirt-pflash0-storage"}' \
#        -blockdev '{"driver":"file","filename":"'"${vars}"'","node-name":"libvirt-pflash1-storage","auto-read-only":true,"discard":"unmap"}' \
#        -blockdev '{"node-name":"libvirt-pflash1-format","read-only":true,"driver":"raw","file":"libvirt-pflash1-storage"}' \
#        -blockdev '{"driver":"file","filename":"/var/lib/libvirt/qemu/nvram/'"${vars}"'","node-name":"libvirt-pflash1-storage","auto-read-only":true,"discard":"unmap"}' \
#        -blockdev '{"node-name":"libvirt-pflash1-format","read-only":false,"driver":"raw","file":"libvirt-pflash1-storage"}' \
#        -drive file=/var/lib/libvirt/images/aarch64.qcow2,format=qcow2,if=none,id=sd0,index=0 \
#        -device virtio-blk-device,drive=sd0 \
#        -drive file="${iso}",format=raw,if=none,id=sr0,index=1 \
#        -device virtio-blk-device,drive=sr0 \
#
    exec sudo /usr/bin/qemu-system-aarch64 \
        "${gdb[@]}" \
        -drive if=pflash,format=raw,file="${pflash}",readonly \
        -drive if=pflash,format=raw,file="${vars}" \
        -drive file=/var/lib/libvirt/images/aarch64.qcow2,format=qcow2,if=none,id=sd0,index=0 \
        -device virtio-blk-device,drive=sd0 \
        -drive file="${iso}",format=raw,if=none,id=sr0,index=1 \
        -device virtio-blk-device,drive=sr0 \
        -nodefaults \
        -no-user-config \
        -display none \
        -name guest=aa64-nosb,debug-threads=on \
        -M virt \
        -cpu cortex-a57 \
        -machine accel=tcg,dump-guest-core=off \
        -m 1024 \
        -overcommit mem-lock=off \
        -smp sockets=1,cores=4,threads=2 \
        -uuid 0ddaa1d1-e70b-4e2f-9bef-98434f4dca41 \
        -rtc base=utc,driftfix=slew \
        -device pcie-root-port,port=1,chassis=1,id=pcie.1,bus=pcie.0,addr=0x1c.0,multifunction=on \
        -boot menu=on,strict=on \
        -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56 \
        -netdev bridge,id=n0,br=virbr0,helper=/usr/libexec/qemu-bridge-helper \
        -object rng-random,id=objrng0,filename=/dev/urandom \
        -device virtio-rng-pci,rng=objrng0,id=rng0,bus=pcie.0,addr=0x1c.1 \
        -gdb tcp::1234 \
        -chardev pty,id=charmonitor0,nowait \
        -mon chardev=charmonitor0,id=monitor0,mode=readline \
        -chardev backend=stdio,mux=on,id=char0 \
        -serial chardev:char0 \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=allow,resourcecontrol=deny \
        -msg timestamp=on
        
#    gdb -ix ../../gdbinit
    
}

#         file:/tmp/baytrail-x64-nosb.firmware.log \

main "${@}"

# vim:fenc=utf-8:tw=1000
