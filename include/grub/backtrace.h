/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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

#ifndef GRUB_BACKTRACE_HEADER
#define GRUB_BACKTRACE_HEADER	1

#include <grub/symbol.h>
#include <grub/types.h>

void EXPORT_FUNC(grub_debug_backtrace) (const char * const debug,
					unsigned long skip);
void EXPORT_FUNC(grub_backtrace) (unsigned long skip);
void grub_backtrace_arch (unsigned long skip);
void grub_backtrace_pointer (void *ptr, unsigned long skip);
void grub_backtrace_print_address (void *addr);

#endif
