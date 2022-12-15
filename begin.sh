#!/bin/bash
set -eu
set -x

if ping -q -4 -c 2 -W 1 -w 3 baytrail-x64 ; then
    ssh root@baytrail-x64 grub2-editenv - set next_entry=0
    ssh root@baytrail-x64 shutdown -h now || :
    sleep 5
fi
for x in /tmp/q35nx-x64-sb.firmware.* ; do
    if [[ -f "${x}" ]] ; then
        sudo chmod o+rw "${x}" || :
        sudo setfacl -m u:pjones:rw -m u:root:rw "${x}" || :
        sudo truncate -s 0 "${x}" || :
    fi
done
sudo virsh start q35nx-x64-sb
sleep 1
for x in /tmp/q35nx-x64-sb.firmware.* ; do
    if [[ -f "${x}" ]] ; then
        sudo chmod o+rw "${x}" || :
        sudo setfacl -m u:pjones:rw -m u:root:rw "${x}" || :
        sudo truncate -s 0 "${x}" || :
    fi
done


# vim:fenc=utf-8:tw=75
