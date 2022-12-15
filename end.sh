#!/bin/bash
set -eu

if ping -q -4 -c 2 -W 1 -w 3 baytrail-x64 ; then
    ssh root@baytrail-x64 grub2-editenv - set next_entry=2
    ssh root@baytrail-x64 shutdown -h now || :
    sleep 1
fi
sudo virsh destroy q35nx-x64-sb || :
sudo virsh start baytrail-x64-nosb

# vim:fenc=utf-8:tw=75
