#define GRUB_IMAGE_VERIFIERXX
#if !defined(IMAGEVERIFIER_ELF32) && !defined(IMAGEVERIFIER_ELF64)
#if __SIZEOF_POINTER__ == 8
#include "grub-image-verifier64.c"
#else
#include "grub-image-verifier32.c"
#endif
#endif

#include <string.h>
#include <grub/elf.h>
#include <grub/dl.h>
#include <grub/env.h>
#include <grub/module_verifier.h>
#include <grub/util/misc.h>

void
SUFFIX(grub_image_verify) (const char * const filename,
			    void *image, size_t size,
			    const struct grub_module_verifier_arch *arch,
			    const char **whitelist_empty)
{
  grub_dl_t dlt;

  grub_env_set ("debug", "all");
  dlt = grub_dl_load_core_noinit (image, size);

}
