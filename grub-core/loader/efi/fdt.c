/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013-2015  Free Software Foundation, Inc.
 *  Copyright (C) 2024       Canonical, Ltd.
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

#include <grub/fdt.h>
#include <grub/mm.h>
#include <grub/env.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/command.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/efi/efi.h>
#include <grub/efi/fdtload.h>
#include <grub/efi/memory.h>
#include <grub/cpu/efi/memory.h>

static void *loaded_fdt;
static void *fdt;

#define FDT_ADDR_CELLS_STRING "#address-cells"
#define FDT_SIZE_CELLS_STRING "#size-cells"
#define FDT_ADDR_SIZE_EXTRA ((2 * grub_fdt_prop_entry_size (sizeof(grub_uint32_t))) + \
                             sizeof (FDT_ADDR_CELLS_STRING) + \
                             sizeof (FDT_SIZE_CELLS_STRING))

static const struct grub_arg_option options_fdtdump[] = {
  {"prop",	'p', 0, N_("Get property."), N_("prop"), ARG_TYPE_STRING},
  {"set",       '\0', 0, N_("Store the value in the given variable name."),
                         N_("variable"), ARG_TYPE_STRING},
  {0, 0, 0, 0, 0, 0}
};

void *
grub_fdt_load (grub_size_t additional_size)
{
  void *raw_fdt;
  unsigned int size;

  if (fdt)
    {
      size = GRUB_EFI_BYTES_TO_PAGES (grub_fdt_get_totalsize (fdt));
      grub_efi_free_pages ((grub_addr_t) fdt, size);
    }

  if (loaded_fdt)
    raw_fdt = loaded_fdt;
  else
    raw_fdt = grub_efi_get_firmware_fdt();

  if (raw_fdt)
      size = grub_fdt_get_totalsize (raw_fdt);
  else
      size = GRUB_FDT_EMPTY_TREE_SZ + FDT_ADDR_SIZE_EXTRA;

  size += additional_size;

  grub_dprintf ("linux", "allocating %d bytes for fdt\n", size);
  fdt = grub_efi_allocate_pages_real (GRUB_EFI_MAX_USABLE_ADDRESS,
				      GRUB_EFI_BYTES_TO_PAGES (size),
				      GRUB_EFI_ALLOCATE_MAX_ADDRESS,
				      GRUB_EFI_ACPI_RECLAIM_MEMORY);
  if (!fdt)
    return NULL;

  if (raw_fdt)
    {
      grub_memmove (fdt, raw_fdt, size - additional_size);
      grub_fdt_set_totalsize (fdt, size);
    }
  else
    {
      grub_fdt_create_empty_tree (fdt, size);
      grub_fdt_set_prop32 (fdt, 0, FDT_ADDR_CELLS_STRING, 2);
      grub_fdt_set_prop32 (fdt, 0, FDT_SIZE_CELLS_STRING, 2);
    }
  return fdt;
}

grub_err_t
grub_fdt_install (void)
{
  grub_efi_boot_services_t *b;
  static grub_guid_t fdt_guid = GRUB_EFI_DEVICE_TREE_GUID;
  grub_efi_status_t status;

  if (fdt == NULL && loaded_fdt == NULL)
    return GRUB_ERR_NONE;

  b = grub_efi_system_table->boot_services;
  status = b->install_configuration_table (&fdt_guid, fdt ? fdt : loaded_fdt);
  if (status != GRUB_EFI_SUCCESS)
    return grub_error (GRUB_ERR_IO, "failed to install FDT");

  grub_dprintf ("fdt", "Installed/updated FDT configuration table @ %p\n",
		fdt ? fdt : loaded_fdt);
  return GRUB_ERR_NONE;
}

void
grub_fdt_unload (void) {
  if (!fdt) {
    return;
  }
  grub_efi_free_pages ((grub_addr_t) fdt,
		       GRUB_EFI_BYTES_TO_PAGES (grub_fdt_get_totalsize (fdt)));
  fdt = NULL;
}

static grub_err_t
grub_cmd_devicetree (grub_command_t cmd __attribute__ ((unused)),
		     int argc, char *argv[])
{
  grub_file_t dtb;
  void *blob = NULL;
  int size;

  if (loaded_fdt)
    grub_free (loaded_fdt);
  loaded_fdt = NULL;

  /* No arguments means "use firmware FDT".  */
  if (argc == 0)
    {
      return GRUB_ERR_NONE;
    }

  dtb = grub_file_open (argv[0], GRUB_FILE_TYPE_DEVICE_TREE_IMAGE);
  if (!dtb)
    goto out;

  size = grub_file_size (dtb);
  blob = grub_malloc (size);
  if (!blob)
    goto out;

  if (grub_file_read (dtb, blob, size) < size)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"), argv[0]);
      goto out;
    }

  if (grub_fdt_check_header (blob, size) != 0)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("invalid device tree"));
      goto out;
    }

out:
  if (dtb)
    grub_file_close (dtb);

  if (blob)
    {
      if (grub_errno == GRUB_ERR_NONE)
	loaded_fdt = blob;
      else
	grub_free (blob);
    }

  return grub_errno;
}

static grub_err_t
grub_cmd_fdtdump (grub_extcmd_context_t ctxt,
                 int argc __attribute__ ((unused)),
                 char **argv __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  const char *value = NULL;
  void *fw_fdt;

  fw_fdt = grub_efi_get_firmware_fdt ();
  if (fw_fdt == NULL)
      return grub_error (GRUB_ERR_IO,
                         N_("No device tree found"));

  if (state[0].set)
      value = grub_fdt_get_prop (fw_fdt, 0, state[0].arg, NULL);

  if (value == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       N_("failed to retrieve the prop field"));

  if (state[1].set)
    grub_env_set (state[1].arg, value);
  else
    grub_printf ("%s\n", value);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_devicetree;
static grub_extcmd_t cmd_fdtdump;

GRUB_MOD_INIT (fdt)
{
  cmd_fdtdump =
    grub_register_extcmd ("fdtdump", grub_cmd_fdtdump, 0,
                          N_("[-p] [--set variable]"),
                          N_("Retrieve device tree information."),
                          options_fdtdump);
  cmd_devicetree =
    grub_register_command_lockdown ("devicetree", grub_cmd_devicetree, 0,
				    N_("Load DTB file."));
}

GRUB_MOD_FINI (fdt)
{
  grub_unregister_command (cmd_devicetree);
  grub_unregister_extcmd (cmd_fdtdump);
}
