#!/usr/bin/sudo bash
# SPDX-License-Identifier: GPLv2-or-later
#
# deploy.sh - deploy $1 to wherever
# Copyright Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
# shellcheck shell=bash

set -eu

guestfishcfg() {
    cat <<EOF
run
mount /dev/sda1 /
copy-in ${grubefi} /EFI/test-fedora-33/
umount /
EOF
}

set -x

main() {
    local grubefi="${1}" && shift

    if ! [[ -e .gdbinit ]] && [[ -f ../../gdbinit ]] ; then
        ln ../../gdbinit .gdbinit
    fi



    virsh destroy baytrail-x64-nosb || :;
    guestfish -d baytrail-x64-nosb < <(guestfishcfg)
    exec sudo /usr/bin/qemu-system-x86_64 -machine accel=kvm \
        -name guest=baytrail-x64-nosb,debug-threads=on \
        -S \
        -blockdev '{"driver":"file","filename":"/usr/share/edk2/ovmf-debug/OVMF_CODE.fd","node-name":"libvirt-pflash0-storage","auto-read-only":true,"discard":"unmap"}' \
        -blockdev '{"node-name":"libvirt-pflash0-format","read-only":true,"driver":"raw","file":"libvirt-pflash0-storage"}' \
        -blockdev '{"driver":"file","filename":"/var/lib/libvirt/qemu/nvram/baytrail-x64-nosb_VARS.fd","node-name":"libvirt-pflash1-storage","auto-read-only":true,"discard":"unmap"}' \
        -blockdev '{"node-name":"libvirt-pflash1-format","read-only":false,"driver":"raw","file":"libvirt-pflash1-storage"}' \
        -machine pc-q35-2.9,accel=kvm,usb=off,vmport=off,smm=on,dump-guest-core=off,pflash0=libvirt-pflash0-format,pflash1=libvirt-pflash1-format \
        -cpu EPYC-IBPB,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,clwb=on,umip=on,rdpid=on,stibp=on,arch-capabilities=on,ssbd=on,xsaves=on,cmp-legacy=on,perfctr-core=on,clzero=on,xsaveerptr=on,wbnoinvd=on,amd-stibp=on,amd-ssbd=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,monitor=off \
        -m 1024 \
        -overcommit mem-lock=off \
        -smp 1,sockets=1,cores=1,threads=1 \
        -uuid 0ddaa1d1-e70b-4e2f-9bef-98434f4dca40 \
        -no-user-config \
        -nodefaults \
        -rtc base=utc,driftfix=slew \
        -global kvm-pit.lost_tick_policy=delay \
        -no-hpet \
        -no-shutdown \
        -global ICH9-LPC.disable_s3=1 \
        -global ICH9-LPC.disable_s4=1 \
        -boot menu=on,strict=on \
        -device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=pcie.0,multifunction=on,addr=0x2 \
        -device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=pcie.0,addr=0x2.0x1 \
        -device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=pcie.0,addr=0x2.0x2 \
        -device pcie-root-port,port=0x13,chassis=4,id=pci.4,bus=pcie.0,addr=0x2.0x3 \
        -device pcie-root-port,port=0x14,chassis=5,id=pci.5,bus=pcie.0,addr=0x2.0x4 \
        -device pcie-root-port,port=0x15,chassis=6,id=pci.6,bus=pcie.0,addr=0x2.0x5 \
        -device pcie-root-port,port=0x16,chassis=7,id=pci.7,bus=pcie.0,addr=0x2.0x6 \
        -device ich9-usb-ehci1,id=usb,bus=pcie.0,addr=0x1d.0x7 \
        -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pcie.0,multifunction=on,addr=0x1d \
        -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pcie.0,addr=0x1d.0x1 \
        -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pcie.0,addr=0x1d.0x2 \
        -device virtio-scsi-pci,id=scsi0,bus=pci.6,addr=0x0 \
        -device virtio-serial-pci,id=virtio-serial0,bus=pci.2,addr=0x0 \
        -blockdev '{"driver":"file","filename":"/var/lib/libvirt/images/baytrail.qcow2","node-name":"libvirt-2-storage","auto-read-only":true,"discard":"unmap"}' \
        -blockdev '{"node-name":"libvirt-2-format","read-only":false,"driver":"qcow2","file":"libvirt-2-storage","backing":null}' \
        -device virtio-blk-pci,bus=pci.3,addr=0x0,drive=libvirt-2-format,id=virtio-disk0,bootindex=1 \
        -device scsi-cd,bus=scsi0.0,channel=0,scsi-id=0,lun=0,device_id=drive-scsi0-0-0-0,id=scsi0-0-0-0 \
        -chardev stdio,id=charserial0 \
        -device isa-serial,chardev=charserial0,id=serial0 \
        -device usb-tablet,id=input0,bus=usb.0,port=1 \
        -spice port=5900,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on \
        -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pcie.0,addr=0x1 \
        -chardev spicevmc,id=charredir0,name=usbredir \
        -device usb-redir,chardev=charredir0,id=redir0,bus=usb.0,port=2 \
        -chardev spicevmc,id=charredir1,name=usbredir \
        -device usb-redir,chardev=charredir1,id=redir1,bus=usb.0,port=3 \
        -device virtio-balloon-pci,id=balloon0,bus=pci.4,addr=0x0 \
        -object rng-random,id=objrng0,filename=/dev/urandom \
        -device virtio-rng-pci,rng=objrng0,id=rng0,bus=pci.5,addr=0x0 \
        -gdb tcp::1234 \
        -chardev pty,id=charmonitor0,nowait \
        -mon chardev=charmonitor0,id=monitor0,mode=readline \
        -global isa-debugcon.iobase=0x402 \
        -debugcon file:/dev/stdout \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
        -msg timestamp=on
        

#    gdb -ix ../../gdbinit
    
}

#         file:/tmp/baytrail-x64-nosb.firmware.log \

main "${@}"

# vim:fenc=utf-8:tw=1000
