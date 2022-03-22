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

#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

#include <grub/efi/efi.h>
#include <grub/efi/loader.h>
#include <grub/efi/pe32.h>

grub_err_t
grub_efi_check_nx_image_support (grub_addr_t kernel_addr,
				 grub_size_t kernel_size,
				 int *nx_supported)
{
  struct grub_dos_header *doshdr;
  grub_size_t sz = sizeof (*doshdr);

  struct grub_pe32_header_32 *pe32;
  struct grub_pe32_header_64 *pe64;

  int image_is_compatible = 0;
  int is_64_bit;

  if (kernel_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  doshdr = (void *)kernel_addr;

  if ((doshdr->magic & 0xffff) != GRUB_DOS_MAGIC)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel DOS magic is invalid"));

  sz = doshdr->lfanew + sizeof (*pe32);
  if (kernel_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  pe32 = (struct grub_pe32_header_32 *)(kernel_addr + doshdr->lfanew);
  pe64 = (struct grub_pe32_header_64 *)pe32;

  if (grub_memcmp (pe32->signature, GRUB_PE32_SIGNATURE,
		   GRUB_PE32_SIGNATURE_SIZE) != 0)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel PE magic is invalid"));

  switch (pe32->coff_header.machine)
    {
    case GRUB_PE32_MACHINE_ARMTHUMB_MIXED:
    case GRUB_PE32_MACHINE_I386:
    case GRUB_PE32_MACHINE_RISCV32:
      is_64_bit = 0;
      break;
    case GRUB_PE32_MACHINE_ARM64:
    case GRUB_PE32_MACHINE_IA64:
    case GRUB_PE32_MACHINE_RISCV64:
    case GRUB_PE32_MACHINE_X86_64:
      is_64_bit = 1;
      break;
    default:
      return grub_error (GRUB_ERR_BAD_OS, N_("PE machine type 0x%04hx unknown"),
			 pe32->coff_header.machine);
    }

  if (is_64_bit)
    {
      sz = doshdr->lfanew + sizeof (*pe64);
      if (kernel_size < sz)
	return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

      if (pe64->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }
  else
    {
      if (pe32->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }

  *nx_supported = image_is_compatible;
  return GRUB_ERR_NONE;
}

grub_err_t
grub_efi_check_nx_required (int *nx_required)
{
  grub_efi_status_t status;
  grub_efi_guid_t guid = GRUB_EFI_SHIM_LOCK_GUID;
  grub_size_t mok_policy_sz = 0;
  char *mok_policy = NULL;
  grub_uint32_t mok_policy_attrs = 0;

  status = grub_efi_get_variable_with_attributes ("MokPolicy", &guid,
						  &mok_policy_sz,
						  (void **)&mok_policy,
						  &mok_policy_attrs);
  if (status == GRUB_EFI_NOT_FOUND ||
      mok_policy_sz == 0 ||
      mok_policy == NULL)
    {
      *nx_required = 0;
      return GRUB_ERR_NONE;
    }

  *nx_required = 0;
  if (mok_policy_sz < 1 ||
      mok_policy_attrs != (GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
			   GRUB_EFI_VARIABLE_RUNTIME_ACCESS) ||
      (mok_policy[mok_policy_sz-1] & GRUB_MOK_POLICY_NX_REQUIRED))
    *nx_required = 1;

  return GRUB_ERR_NONE;
}
