/* This file is intentionally empty: it's used to generate modules with no code or data.  (purely dependency modules)  */
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");
GRUB_MOD_INIT(fakemod ## __COUNTER__)
{
	return;
}
