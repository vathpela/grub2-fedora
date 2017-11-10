#!/bin/bash
set -e
if [ ${0} -nt Makefile ]; then
    ../configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --disable-dependency-tracking --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info 'CFLAGS= -fno-omit-frame-pointer -Wno-frame-address -fno-strict-aliasing -g3 -Og -pipe -Wall     -grecord-gcc-switches -m64 -mtune=generic ' TARGET_LDFLAGS=-static --with-platform=efi --target=x86_64-redhat-linux-gnu --with-grubdir=grub2 --program-transform-name=s,grub,grub2, --disable-grub-mount --disable-werror
fi
make
set -x
./grub-mkimage -O x86_64-efi -o gcdx64.efi -p /EFI/BOOT -d grub-core all_video boot btrfs cat chain configfile echo efifwsetup efinet ext2 fat font gfxmenu gfxterm gzio halt hfsplus iso9660 jpeg loadenv loopback lvm mdraid09 mdraid1x minicmd normal part_apple part_msdos part_gpt password_pbkdf2 png reboot search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg test tftp video xfs backtrace http linuxefi usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug
cp -v gcdx64.efi ~/public_html/EFI/BOOT/grubx64.efi

