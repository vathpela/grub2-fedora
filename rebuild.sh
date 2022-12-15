#!/bin/bash
set -eu
set pipefail

time fedpkg local |& tee grub.build.log
scp /home/pjones/devel/fedora/grub2/f36/x86_64/grub2-efi-x64-2.06-16.fc36~pjnx*.x86_64.rpm root@baytrail-x64:
ssh root@baytrail-x64 ./deploy.sh

# vim:fenc=utf-8:tw=75
