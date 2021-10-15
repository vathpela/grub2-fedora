/* module_verifier.h - prototypes for module validation */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2015,2018,2019,2021  Free Software Foundation, Inc.
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

#ifndef GRUB_MODULE_VERIFIER_HEADER
#define GRUB_MODULE_VERIFIER_HEADER 1

#include <stdint.h>
#include <stdlib.h>

#include <grub/types.h>

#define GRUB_MODULE_VERIFY_SUPPORTS_REL 1
#define GRUB_MODULE_VERIFY_SUPPORTS_RELA 2

struct grub_module_verifier_arch {
  const char *name;
  int voidp_sizeof;
  int bigendian;
  int machine;
  int flags;
  const int *supported_relocations;
  const int *short_relocations;
};

void grub_module_verify64(const char * const filename, void *module_img, size_t module_size, const struct grub_module_verifier_arch *arch, const char **whitelist_empty);
void grub_module_verify32(const char * const filename, void *module_img, size_t module_size, const struct grub_module_verifier_arch *arch, const char **whitelist_empty);

void grub_image_verify64(const char * const filename, void *img, size_t size, const struct grub_module_verifier_arch *arch, const char **whitelist_empty);
void grub_image_verify32(const char * const filename, void *img, size_t size, const struct grub_module_verifier_arch *arch, const char **whitelist_empty);

#if defined(MODULEVERIFIER_ELF32) || defined(IMAGEVERIFIER_ELF32)
# define SUFFIX(x)	x ## 32
# define ELFCLASSXX	ELFCLASS32
# define Elf_Ehdr	Elf32_Ehdr
# define Elf_Phdr	Elf32_Phdr
# define Elf_Nhdr	Elf32_Nhdr
# define Elf_Addr	Elf32_Addr
# define Elf_Sym	Elf32_Sym
# define Elf_Off	Elf32_Off
# define Elf_Shdr	Elf32_Shdr
# define Elf_Rela       Elf32_Rela
# define Elf_Rel        Elf32_Rel
# define Elf_Word       Elf32_Word
# define Elf_Half       Elf32_Half
# define Elf_Section    Elf32_Section
# define ELF_R_SYM(val)		ELF32_R_SYM(val)
# define ELF_R_TYPE(val)		ELF32_R_TYPE(val)
# define ELF_ST_TYPE(val)		ELF32_ST_TYPE(val)
#elif defined(MODULEVERIFIER_ELF64) || defined(IMAGEVERIFIER_ELF64)
# define SUFFIX(x)	x ## 64
# define ELFCLASSXX	ELFCLASS64
# define Elf_Ehdr	Elf64_Ehdr
# define Elf_Phdr	Elf64_Phdr
# define Elf_Nhdr	Elf64_Nhdr
# define Elf_Addr	Elf64_Addr
# define Elf_Sym	Elf64_Sym
# define Elf_Off	Elf64_Off
# define Elf_Shdr	Elf64_Shdr
# define Elf_Rela       Elf64_Rela
# define Elf_Rel        Elf64_Rel
# define Elf_Word       Elf64_Word
# define Elf_Half       Elf64_Half
# define Elf_Section    Elf64_Section
# define ELF_R_SYM(val)		ELF64_R_SYM(val)
# define ELF_R_TYPE(val)		ELF64_R_TYPE(val)
# define ELF_ST_TYPE(val)		ELF64_ST_TYPE(val)
#endif

#define grub_target_to_host32(x) (grub_target_to_host32_real (arch, (x)))
#define grub_host_to_target32(x) (grub_host_to_target32_real (arch, (x)))
#define grub_target_to_host64(x) (grub_target_to_host64_real (arch, (x)))
#define grub_host_to_target64(x) (grub_host_to_target64_real (arch, (x)))
#define grub_host_to_target_addr(x) (grub_host_to_target_addr_real (arch, (x)))
#define grub_target_to_host16(x) (grub_target_to_host16_real (arch, (x)))
#define grub_host_to_target16(x) (grub_host_to_target16_real (arch, (x)))
#define grub_target_to_host(val) grub_target_to_host_real(arch, (val))

static inline grub_uint32_t
grub_target_to_host32_real (const struct grub_module_verifier_arch *arch,
			    grub_uint32_t in)
{
  if (arch->bigendian)
    return grub_be_to_cpu32 (in);
  else
    return grub_le_to_cpu32 (in);
}

static inline grub_uint64_t
grub_target_to_host64_real (const struct grub_module_verifier_arch *arch,
			    grub_uint64_t in)
{
  if (arch->bigendian)
    return grub_be_to_cpu64 (in);
  else
    return grub_le_to_cpu64 (in);
}

static inline grub_uint64_t
grub_host_to_target64_real (const struct grub_module_verifier_arch *arch,
			    grub_uint64_t in)
{
  if (arch->bigendian)
    return grub_cpu_to_be64 (in);
  else
    return grub_cpu_to_le64 (in);
}

static inline grub_uint32_t
grub_host_to_target32_real (const struct grub_module_verifier_arch *arch,
			    grub_uint32_t in)
{
  if (arch->bigendian)
    return grub_cpu_to_be32 (in);
  else
    return grub_cpu_to_le32 (in);
}

static inline grub_uint16_t
grub_target_to_host16_real (const struct grub_module_verifier_arch *arch,
			    grub_uint16_t in)
{
  if (arch->bigendian)
    return grub_be_to_cpu16 (in);
  else
    return grub_le_to_cpu16 (in);
}

static inline grub_uint16_t
grub_host_to_target16_real (const struct grub_module_verifier_arch *arch,
			    grub_uint16_t in)
{
  if (arch->bigendian)
    return grub_cpu_to_be16 (in);
  else
    return grub_cpu_to_le16 (in);
}

static inline grub_uint64_t
grub_host_to_target_addr_real (const struct grub_module_verifier_arch *arch, grub_uint64_t in)
{
  if (arch->voidp_sizeof == 8)
    return grub_host_to_target64_real (arch, in);
  else
    return grub_host_to_target32_real (arch, in);
}

static inline grub_uint64_t
grub_target_to_host_real (const struct grub_module_verifier_arch *arch, grub_uint64_t in)
{
  if (arch->voidp_sizeof == 8)
    return grub_target_to_host64_real (arch, in);
  else
    return grub_target_to_host32_real (arch, in);
}

#endif /* ! GRUB_MODULE_VERIFIER_HEADER */
