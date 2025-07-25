#include <grub/gcrypt/g10lib.h>
#include <grub/gcrypt/gpg-error.h>
#include <grub/term.h>
#include <grub/crypto.h>
#include <grub/dl.h>
#include <grub/env.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

void *
gcry_malloc (size_t n)
{
  return grub_malloc (n);
}

void *
gcry_malloc_secure (size_t n)
{
  return grub_malloc (n);
}

void
gcry_free (void *a)
{
  grub_free (a);
}

int
gcry_is_secure (const void *a __attribute__ ((unused)))
{
  return 0;
}

/* FIXME: implement "exit".  */
void *
gcry_xcalloc (size_t n, size_t m)
{
  void *ret;
  size_t sz;
  if (grub_mul (n, m, &sz))
    grub_fatal ("gcry_xcalloc would overflow");
  ret = grub_zalloc (sz);
  if (!ret)
    grub_fatal ("gcry_xcalloc failed");
  return ret;
}

void *
_gcry_calloc (size_t n, size_t m)
{
  size_t sz;
  if (grub_mul (n, m, &sz))
    return NULL;
  return grub_zalloc (sz);
}

void *
gcry_xmalloc_secure (size_t n)
{
  void *ret;
  ret = grub_malloc (n);
  if (!ret)
    grub_fatal ("gcry_xmalloc failed");
  return ret;
}

void *
gcry_xcalloc_secure (size_t n, size_t m)
{
  void *ret;
  size_t sz;
  if (grub_mul (n, m, &sz))
    grub_fatal ("gcry_xcalloc would overflow");
  ret = grub_zalloc (sz);
  if (!ret)
    grub_fatal ("gcry_xcalloc failed");
  return ret;
}

void *
_gcry_calloc_secure (size_t n, size_t m)
{
  size_t sz;
  if (grub_mul (n, m, &sz))
    return NULL;
  return grub_zalloc (sz);
}

void *
gcry_xmalloc (size_t n)
{
  void *ret;
  ret = grub_malloc (n);
  if (!ret)
    grub_fatal ("gcry_xmalloc failed");
  return ret;
}

void *
gcry_xrealloc (void *a, size_t n)
{
  void *ret;
  ret = grub_realloc (a, n);
  if (!ret)
    grub_fatal ("gcry_xrealloc failed");
  return ret;
}

void *
_gcry_realloc (void *a, size_t n)
{
  return grub_realloc (a, n);
}

void _gcry_log_printf (const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, "gcrypt"))
    {
      grub_printf ("gcrypt: ");
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

void _gcry_log_debug (const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, "gcrypt"))
    {
      grub_printf ("gcrypt: ");
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

void _gcry_log_bug (const char *fmt, ...)
{
  va_list args;

  grub_printf ("gcrypt bug: ");
  va_start (args, fmt);
  grub_vprintf (fmt, args);
  va_end (args);
  grub_refresh ();
  grub_fatal ("gcrypt bug");
}

gcry_err_code_t
gpg_err_code_from_errno (int err)
{
  switch (err)
    {
    case GRUB_ERR_NONE:
      return GPG_ERR_NO_ERROR;
    case GRUB_ERR_OUT_OF_MEMORY:
      return GPG_ERR_OUT_OF_MEMORY;
    default:
      return GPG_ERR_GENERAL;
    }
}

gcry_err_code_t
gpg_error_from_syserror (void)
{
  return gpg_err_code_from_errno(grub_errno);
}

gcry_err_code_t
gpg_err_code_from_syserror (void)
{
  return gpg_error_from_syserror ();
}

void _gcry_fatal_error(int rc, const char *text )
{
  grub_fatal("gcry fatal %d: %s", rc, text);
}


void _gcry_randomize (void *buffer __attribute__((unused)), size_t length __attribute__((unused)),
                      enum gcry_random_level level __attribute__((unused)))
{
  grub_fatal("Attempt to get secure random numbers");
}


void *_gcry_random_bytes_secure (size_t nbytes __attribute__((unused)), enum gcry_random_level level __attribute__((unused)))
{
  grub_fatal("Attempt to get secure random numbers");
}

const char *gpg_strerror (gpg_error_t err)
{
  static char buf[256];
  grub_snprintf(buf, sizeof(buf) - 5, "gpg error %d\n", err);
  return buf;
}
