/* grub-image-verifier.c - make a bootable image */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <config.h>
#include <grub/types.h>
#include <grub/elf.h>
#include <grub/aout.h>
#include <grub/i18n.h>
#include <grub/kernel.h>
#include <grub/disk.h>
#include <grub/emu/misc.h>
#include <grub/util/misc.h>
#include <grub/util/resolve.h>
#include <grub/misc.h>
#include <grub/offsets.h>
#include <grub/crypto.h>
#include <grub/dl.h>
#include <time.h>
#include <multiboot.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <grub/efi/pe32.h>
#include <grub/uboot/image.h>
#include <grub/arm/reloc.h>
#include <grub/ia64/reloc.h>
#include <grub/osdep/hostfile.h>
#include <grub/util/install.h>
#include <grub/emu/config.h>
#include <grub/module_verifier.h>

#define _GNU_SOURCE	1

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include <argp.h>
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

#include "progname.h"

struct grub_module_verifier_arch archs[] = {
  { "i386", 4, 0, EM_386, GRUB_MODULE_VERIFY_SUPPORTS_REL, (int[]){
      R_386_32,
      R_386_PC32,
      -1
    } },
  { "x86_64", 8, 0, EM_X86_64, GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_X86_64_64,
      R_X86_64_PC64,
      /* R_X86_64_32, R_X86_64_32S are supported but shouldn't be used because of their limited range.  */
      -1
    }, (int[]){
      R_X86_64_PC32,
      R_X86_64_PLT32,
      -1
    }
  },
  { "powerpc", 4, 1, EM_PPC, GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      GRUB_ELF_R_PPC_ADDR16_LO,
      GRUB_ELF_R_PPC_REL24, /* It has limited range but GRUB adds trampolines when necessarry.  */
      GRUB_ELF_R_PPC_ADDR16_HA,
      GRUB_ELF_R_PPC_ADDR32,
      GRUB_ELF_R_PPC_REL32,
      GRUB_ELF_R_PPC_PLTREL24,
      -1
    } },
  { "sparc64", 8, 1, EM_SPARCV9, GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_SPARC_WDISP30, /* It has limited range but GRUB adds trampolines when necessarry. */
      R_SPARC_HH22,
      R_SPARC_HM10,
      R_SPARC_LM22,
      R_SPARC_LO10,
      R_SPARC_64,
      R_SPARC_OLO10,
      /* Following 2 relocations have limited range but unfortunately
	 clang generates them, as it doesn't implement mcmodel=large properly.
	 At least our heap and core are under 4G, so it's not a problem
	 usually. */
      R_SPARC_HI22,
      R_SPARC_32,
      -1
    } },
  { "ia64", 8, 0, EM_IA_64, GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_IA64_PCREL21B, /* We should verify that it's pointing either
			  to a function or to a section in the same module.
			  Checking that external symbol is a function is
			  non-trivial and I have never seen this relocation used
			  for anything else, so assume that it always points to a
			  function.
		       */
      R_IA64_SEGREL64LSB,
      R_IA64_FPTR64LSB,
      R_IA64_DIR64LSB,
      R_IA64_PCREL64LSB,
      R_IA64_LTOFF22X,
      R_IA64_LTOFF22,
      R_IA64_GPREL64I,
      R_IA64_LTOFF_FPTR22,
      R_IA64_LDXMOV,
      -1
    }, (int[]){
      R_IA64_GPREL22,
      -1
    } },
  { "mipsel", 4, 0, EM_MIPS, GRUB_MODULE_VERIFY_SUPPORTS_REL | GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_MIPS_HI16,
      R_MIPS_LO16,
      R_MIPS_32,
      R_MIPS_GPREL32,
      R_MIPS_26,
      R_MIPS_GOT16,
      R_MIPS_CALL16,
      R_MIPS_JALR,
      -1
    } },
  { "mips", 4, 1, EM_MIPS, GRUB_MODULE_VERIFY_SUPPORTS_REL | GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_MIPS_HI16,
      R_MIPS_LO16,
      R_MIPS_32,
      R_MIPS_GPREL32,
      R_MIPS_26,
      R_MIPS_GOT16,
      R_MIPS_CALL16,
      R_MIPS_JALR,
      -1
    } },
  { "arm", 4, 0, EM_ARM, GRUB_MODULE_VERIFY_SUPPORTS_REL, (int[]){
      /* Some relocations are range-limited but trampolines are added when necessarry. */
      R_ARM_ABS32,
      R_ARM_CALL,
      R_ARM_JUMP24,
      R_ARM_THM_CALL,
      R_ARM_THM_JUMP24,
      R_ARM_V4BX,
      R_ARM_THM_MOVW_ABS_NC,
      R_ARM_THM_MOVT_ABS,
      R_ARM_THM_JUMP19,
      -1
    } },
  { "arm64", 8, 0, EM_AARCH64, GRUB_MODULE_VERIFY_SUPPORTS_REL | GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_AARCH64_ABS64,
      R_AARCH64_CALL26,
      R_AARCH64_JUMP26,
      R_AARCH64_ADR_GOT_PAGE,
      R_AARCH64_LD64_GOT_LO12_NC,
      -1
    }, (int[]){
      R_AARCH64_ADR_PREL_PG_HI21,
      R_AARCH64_ADD_ABS_LO12_NC,
      R_AARCH64_LDST64_ABS_LO12_NC,
      R_AARCH64_PREL32,
      -1
    } },
  { "riscv32", 4, 0, EM_RISCV, GRUB_MODULE_VERIFY_SUPPORTS_REL | GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_RISCV_32,
      R_RISCV_64,
      R_RISCV_ADD8,
      R_RISCV_ADD16,
      R_RISCV_ADD32,
      R_RISCV_ADD64,
      R_RISCV_SUB8,
      R_RISCV_SUB16,
      R_RISCV_SUB32,
      R_RISCV_SUB64,
      R_RISCV_ALIGN,
      R_RISCV_BRANCH,
      R_RISCV_CALL,
      R_RISCV_CALL_PLT,
      R_RISCV_GOT_HI20,
      R_RISCV_HI20,
      R_RISCV_JAL,
      R_RISCV_LO12_I,
      R_RISCV_LO12_S,
      R_RISCV_PCREL_HI20,
      R_RISCV_PCREL_LO12_I,
      R_RISCV_PCREL_LO12_S,
      R_RISCV_RELAX,
      R_RISCV_RVC_BRANCH,
      R_RISCV_RVC_JUMP,
      -1
    } },
  { "riscv64", 8, 0, EM_RISCV, GRUB_MODULE_VERIFY_SUPPORTS_REL | GRUB_MODULE_VERIFY_SUPPORTS_RELA, (int[]){
      R_RISCV_32,
      R_RISCV_64,
      R_RISCV_ADD8,
      R_RISCV_ADD16,
      R_RISCV_ADD32,
      R_RISCV_ADD64,
      R_RISCV_SUB8,
      R_RISCV_SUB16,
      R_RISCV_SUB32,
      R_RISCV_SUB64,
      R_RISCV_ALIGN,
      R_RISCV_BRANCH,
      R_RISCV_CALL,
      R_RISCV_CALL_PLT,
      R_RISCV_GOT_HI20,
      R_RISCV_HI20,
      R_RISCV_JAL,
      R_RISCV_LO12_I,
      R_RISCV_LO12_S,
      R_RISCV_PCREL_HI20,
      R_RISCV_PCREL_LO12_I,
      R_RISCV_PCREL_LO12_S,
      R_RISCV_RELAX,
      R_RISCV_RVC_BRANCH,
      R_RISCV_RVC_JUMP,
      -1
    }
  },
};

struct platform_whitelist {
  const char *arch;
  const char *platform;
  const char **whitelist_empty;
};

static struct platform_whitelist whitelists[] = {
  {"i386", "xen", (const char *[]) {"all_video", 0}},
  {"i386", "xen_pvh", (const char *[]) {"all_video", 0}},
  {"x86_64", "xen", (const char *[]) {"all_video", 0}},
  {"sparc64", "ieee1275", (const char *[]) {"all_video", 0}},

  /* video is compiled-in on MIPS.  */
  {"mipsel", "loongson", (const char *[]) {"all_video", 0}},
  {"mipsel", "qemu_mips", (const char *[]) {"all_video", 0}},
  {"mipsel", "arc", (const char *[]) {"all_video", 0}},
  {"mips", "qemu_mips", (const char *[]) {"all_video", 0}},
  {"mips", "arc", (const char *[]) {"all_video", 0}},
};

static struct argp_option options[] = {
  { 0, 0, 0, 0, 0, 0 }
};

#pragma GCC diagnostic ignored "-Wformat-nonliteral"

static char *
help_filter (int key, const char *text, void *input __attribute__ ((unused)))
{
  switch (key)
    {
    default:
      return (char *) text;
    }
}

#pragma GCC diagnostic error "-Wformat-nonliteral"

struct arguments
{
  char *image;
  char *arch;
  char *platform;
};

static error_t
argp_parser (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case ARGP_KEY_ARG:
      if (!arguments->image)
	arguments->image = xstrdup (arg);
      else if (!arguments->arch)
	arguments->arch = xstrdup (arg);
      else if (!arguments->platform)
	arguments->platform = xstrdup (arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = {
  options, argp_parser, N_("[OPTION]... IMAGE ARCH PLATFORM"),
  N_("Validate a bootable image of GRUB."),
  NULL, help_filter, NULL
};

int
main (int argc, char *argv[])
{
  struct arguments arguments;
  unsigned arch, whitelist;
  const char **whitelist_empty = 0;
  void *img;
  size_t size;

  grub_util_host_init (&argc, &argv);

  memset (&arguments, 0, sizeof (struct arguments));

  if (argp_parse (&argp, argc, argv, 0, 0, &arguments) != 0)
    {
      fprintf (stderr, "%s", _("Error in parsing command line arguments\n"));
      exit(1);
    }

  if (!arguments.image || !arguments.arch || !arguments.platform)
    {
      fprintf (stderr, "%s", _("Error in parsing command line arguments\n"));
      exit(1);
    }

  for (arch = 0; arch < ARRAY_SIZE(archs); arch++)
    if (strcmp(archs[arch].name, argv[2]) == 0)
      break;
  if (arch == ARRAY_SIZE(archs))
    grub_util_error("%s: unknown arch: %s", argv[1], argv[2]);

  for (whitelist = 0; whitelist < ARRAY_SIZE(whitelists); whitelist++)
    if (strcmp(whitelists[whitelist].arch, argv[2]) == 0
	&& strcmp(whitelists[whitelist].platform, argv[3]) == 0)
      break;
  if (whitelist != ARRAY_SIZE(whitelists))
    whitelist_empty = whitelists[whitelist].whitelist_empty;

  size = grub_util_get_image_size (arguments.image);
  img = grub_util_read_image (arguments.image);
  if (archs[arch].voidp_sizeof == 8)
    grub_image_verify64(argv[1], img, size, &archs[arch], whitelist_empty);
  else
    grub_image_verify32(argv[1], img, size, &archs[arch], whitelist_empty);

  return 0;
}
