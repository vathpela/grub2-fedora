/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KERNEL_CPU_TIME_HEADER
#define KERNEL_CPU_TIME_HEADER	1

/* FIXME: Make grub_get_time_raw () and grub_get_time_scale () that actually
 * examine our real clock hardware or whatever time source we've calibrated.
 */
#include <grub/i386/tsc.h>
#define grub_get_time_raw() grub_get_tsc()
/* tsc scale was 0x6ff on my 2.4GHz laptop, so here's a value that's a
 * bit sloppy but probably won't undershoot.
 */
#define grub_get_time_scale() (0x6ff << 1)

static __inline void
grub_cpu_idle (void)
{
  /* Wait an amount of time our clock can measure. */
  grub_uint64_t b, a = grub_get_time_raw ();
  grub_uint64_t scale = grub_get_time_scale () + 1;

  while ((b = grub_get_time_raw ()) - a < scale)
    ;
}

#endif /* ! KERNEL_CPU_TIME_HEADER */
