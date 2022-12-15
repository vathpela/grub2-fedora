#!/bin/bash
# SPDX-License-Identifier: GPLv3-or-later 
#
# mkimage.sh - make my image
# Copyright Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#

set -eu
set -x
./grub-mkimage -O x86_64-efi -o grubx64.efi.orig -p /EFI/fedora -d grub-core all_video boot blscfg btrfs cat configfile cryptodisk echo efi_netfs efifwsetup efinet ext2 fat font gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool gfxmenu gfxterm gzio halt hfsplus http increment iso9660 jpeg loadenv loopback linux lvm lsefi lsefimmap luks mdraid09 mdraid1x minicmd net normal part_apple part_msdos part_gpt password_pbkdf2 pgp png reboot regexp search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg test tftp version video xfs zstd backtrace chain usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug

scp grubx64.efi.orig root@baytrail-x64:/boot/efi/EFI/test/grubx64.efi
ssh root@baytrail-x64 reboot

# vim:fenc=utf-8:tw=75
