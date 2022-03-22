/* dxe.h - declare DXE types and functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023  Free Software Foundation, Inc.
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

#ifndef GRUB_EFI_DXE_HEADER
#define GRUB_EFI_DXE_HEADER	1

#include <grub/types.h>
#include <grub/symbol.h>
#include <grub/efi/api.h>

#define GRUB_EFI_DXE_SERVICES_TABLE_SIGNATURE ((grub_efi_uint64_t)0x565245535f455844ULL)

typedef enum
{
  efi_gcd_memory_type_non_existent,
  efi_gcd_memory_type_reserved,
  efi_gcd_memory_type_system_memory,
  efi_gcd_memory_type_memory_mapped_io,
  efi_gcd_memory_type_persistent,
  efi_gcd_memory_type_more_reliable,
  efi_gcd_memory_type_maximum
} grub_efi_gcd_memory_type_t;

struct grub_efi_gcd_memory_space_descriptor
{
  grub_efi_physical_address_t base_address;
  grub_efi_uint64_t length;
  grub_efi_uint64_t capabilities;
  grub_efi_uint64_t attributes;
  grub_efi_gcd_memory_type_t gcd_memory_type;
  grub_efi_handle_t image_handle;
  grub_efi_handle_t device_handle;
} GRUB_PACKED;
typedef struct grub_efi_gcd_memory_space_descriptor grub_efi_gcd_memory_space_descriptor_t;

struct grub_dxe_services_table {
  grub_efi_table_header_t hdr;
  void *add_memory_space;
  void *allocate_memory_space;
  void *free_memory_space;
  void *remove_memory_space;
  grub_efi_status_t (*get_memory_space_descriptor) (grub_efi_physical_address_t base_address,
						    grub_efi_gcd_memory_space_descriptor_t *desc);
  grub_efi_status_t (*set_memory_space_attributes) (grub_efi_physical_address_t base_address,
						    grub_efi_uint64_t length,
						    grub_efi_uint64_t attributes);
  void *get_memory_space_map;
  void *add_io_space;
  void *allocate_io_space;
  void *free_io_space;
  void *remove_io_space;
  void *get_io_space_descriptor;
  void *get_io_space_map;
  void *dispatch;
  void *schedule;
  void *trust;
  void *process_firmware_volume;
  void *set_memory_space_capabilities;
};
typedef struct grub_dxe_services_table grub_dxe_services_table_t;

#endif /* ! GRUB_EFI_DXE_HEADER */
