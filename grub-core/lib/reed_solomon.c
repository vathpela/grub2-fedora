/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#ifdef TEST
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define xmalloc malloc
#define grub_memset memset
#define grub_memcpy memcpy
#endif

#ifndef STANDALONE
#include <assert.h>
#endif

#ifndef STANDALONE
#ifdef TEST
typedef unsigned int grub_size_t;
typedef unsigned char grub_uint8_t;
#else
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/gf256.h>
#include <grub/reed_solomon.h>
#include <grub/util/misc.h>
#endif
#endif

#define SECTOR_SIZE 512
#define MAX_BLOCK_SIZE (200 * SECTOR_SIZE)

#ifdef STANDALONE
#ifdef TEST
typedef unsigned int grub_size_t;
typedef unsigned char grub_uint8_t;
#else
#include <grub/types.h>
#include <grub/misc.h>
#endif
#ifdef __i386__
#define REED_SOLOMON_ATTRIBUTE  __attribute__ ((regparm(3)))
#else
#define REED_SOLOMON_ATTRIBUTE
#endif
void
grub_reed_solomon_recover (void *ptr_, grub_size_t s, grub_size_t rs)
  REED_SOLOMON_ATTRIBUTE;
#else
#define REED_SOLOMON_ATTRIBUTE
#endif

#if defined (STANDALONE) && !defined (TEST)

#ifdef __APPLE__
#define ATTRIBUTE_TEXT __attribute__ ((section("_text,_text")))
#else
#define ATTRIBUTE_TEXT __attribute__ ((section(".text")))
#endif

static grub_gf256_single_t *const sigma ATTRIBUTE_TEXT = (void *) 0x100700;
static grub_gf256_single_t *const errpot ATTRIBUTE_TEXT = (void *) 0x100800;
static int *const errpos ATTRIBUTE_TEXT = (void *) 0x100900;
static grub_gf256_single_t *const sy ATTRIBUTE_TEXT = (void *) 0x100d00;
static grub_gf256_single_t *const mstat ATTRIBUTE_TEXT = (void *) 0x100e00;
static grub_gf256_single_t *const errvals ATTRIBUTE_TEXT = (void *) 0x100f00;
static grub_gf256_single_t *const eqstat ATTRIBUTE_TEXT = (void *) 0x101000;
/* Next available address: (void *) 0x112000.  */
#else

static grub_gf256_single_t sigma[256];
static grub_gf256_single_t errpot[256];
static int errpos[256];
static grub_gf256_single_t sy[256];
static grub_gf256_single_t mstat[256];
static grub_gf256_single_t errvals[256];
static grub_gf256_single_t eqstat[65536 + 256];
#endif

#if !defined (STANDALONE)
static void
rs_encode (grub_gf256_single_t *data, grub_size_t s, grub_size_t rs)
{
  grub_gf256_single_t *rs_polynomial;
  unsigned int i, j;
  grub_gf256_single_t *m;
  m = xmalloc ((s + rs) * sizeof (grub_gf256_single_t));
  grub_memcpy (m, data, s * sizeof (grub_gf256_single_t));
  grub_memset (m + s, 0, rs * sizeof (grub_gf256_single_t));
  rs_polynomial = xmalloc ((rs + 1) * sizeof (grub_gf256_single_t));
  grub_memset (rs_polynomial, 0, (rs + 1) * sizeof (grub_gf256_single_t));
  rs_polynomial[rs] = 1;
  /* Multiply with X - a^r */
  for (j = 0; j < rs; j++)
    {
      for (i = 0; i < rs; i++)
	if (rs_polynomial[i])
	  rs_polynomial[i] = (rs_polynomial[i + 1]
			      ^ grub_gf256_mulx (j, rs_polynomial[i]));
	else
	  rs_polynomial[i] = rs_polynomial[i + 1];
      if (rs_polynomial[rs])
	rs_polynomial[rs] = grub_gf256_mulx (j, rs_polynomial[rs]);
    }
  for (j = 0; j < s; j++)
    if (m[j])
      {
	grub_gf256_single_t f = m[j];
	for (i = 0; i <= rs; i++)
	  m[i+j] ^= grub_gf256_mul (rs_polynomial[i], f);
      }
  free (rs_polynomial);
  grub_memcpy (data + s, m + s, rs * sizeof (grub_gf256_single_t));
  free (m);
}
#endif

static void
rs_recover (grub_gf256_single_t *mm, grub_size_t s, grub_size_t rs)
{
  grub_size_t rs2 = rs / 2;
  int errnum = 0;
  int i, j;

  for (i = 0; i < (int) rs; i++)
    sy[i] = grub_gf256_pol_evaluate (mm, s + rs - 1, i);

  for (i = 0; i < (int) rs; i++)
    if (sy[i] != 0)
      break;

  /* No error detected.  */
  if (i == (int) rs)
    return;

  {

    for (i = 0; i < (int) rs2; i++)
      for (j = 0; j < (int) rs2 + 1; j++)
	eqstat[i * (rs2 + 1) + j] = sy[i+j];

    for (i = 0; i < (int) rs2; i++)
      sigma[i] = 0;

    grub_gf256_gauss_solve (eqstat, rs2, rs2, sigma);
  }

  for (i = 0; i < (int) (rs + s); i++)
    if (grub_gf256_pol_evaluate (sigma, rs2 - 1, 255 - i) == grub_gf256_powx[i])
      {
	errpot[errnum] = grub_gf256_powx[i];
	errpos[errnum++] = s + rs - i - 1;
      }
  {
    for (j = 0; j < errnum; j++)
      eqstat[j] = 1;
    eqstat[errnum] = sy[0];
    for (i = 1; i < (int) rs; i++)
      {
	for (j = 0; j < (int) errnum; j++)
	  eqstat[(errnum + 1) * i + j] = grub_gf256_mul (errpot[j],
						 eqstat[(errnum + 1) * (i - 1)
							+ j]);
	eqstat[(errnum + 1) * i + errnum] = sy[i];
      }

    grub_gf256_gauss_solve (eqstat, rs, errnum, errvals);

    for (i = 0; i < (int) errnum; i++)
      mm[errpos[i]] ^= errvals[i];
  }
}

static void
decode_block (grub_gf256_single_t *ptr, grub_size_t s,
	      grub_gf256_single_t *rptr, grub_size_t rs)
{
  int i, j;
  for (i = 0; i < SECTOR_SIZE; i++)
    {
      grub_size_t ds = (s + SECTOR_SIZE - 1 - i) / SECTOR_SIZE;
      grub_size_t rr = (rs + SECTOR_SIZE - 1 - i) / SECTOR_SIZE;

      /* Nothing to do.  */
      if (!ds || !rr)
	continue;

      for (j = 0; j < (int) ds; j++)
	mstat[j] = ptr[SECTOR_SIZE * j + i];
      for (j = 0; j < (int) rr; j++)
	mstat[j + ds] = rptr[SECTOR_SIZE * j + i];

      rs_recover (mstat, ds, rr);

      for (j = 0; j < (int) ds; j++)
	ptr[SECTOR_SIZE * j + i] = mstat[j];
    }
}

#if !defined (STANDALONE)
static void
encode_block (grub_gf256_single_t *ptr, grub_size_t s,
	      grub_gf256_single_t *rptr, grub_size_t rs)
{
  unsigned int i, j;
  for (i = 0; i < SECTOR_SIZE; i++)
    {
      grub_size_t ds = (s + SECTOR_SIZE - 1 - i) / SECTOR_SIZE;
      grub_size_t rr = (rs + SECTOR_SIZE - 1 - i) / SECTOR_SIZE;
      grub_gf256_single_t *m;

      if (!ds || !rr)
	continue;

      m = xmalloc (ds + rr);
      for (j = 0; j < ds; j++)
	m[j] = ptr[SECTOR_SIZE * j + i];
      rs_encode (m, ds, rr);
      for (j = 0; j < rr; j++)      
	rptr[SECTOR_SIZE * j + i] = m[j + ds];
      free (m);
    }
}
#endif

#if !defined (STANDALONE)
void
grub_reed_solomon_add_redundancy (void *buffer, grub_size_t data_size,
				  grub_size_t redundancy)
{
  grub_size_t s = data_size;
  grub_size_t rs = redundancy;
  grub_gf256_single_t *ptr = buffer;
  grub_gf256_single_t *rptr = ptr + s;
  void *tmp;

  tmp = xmalloc (data_size);
  grub_memcpy (tmp, buffer, data_size);

  /* Nothing to do.  */
  if (!rs)
    goto exit;

  while (s > 0)
    {
      grub_size_t tt;
      grub_size_t cs, crs;
      cs = s;
      crs = rs;
      tt = cs + crs;
      if (tt > MAX_BLOCK_SIZE)
	{
	  cs = ((cs * (MAX_BLOCK_SIZE / 512)) / tt) * 512;
	  crs = ((crs * (MAX_BLOCK_SIZE / 512)) / tt) * 512;
	}
      encode_block (ptr, cs, rptr, crs);
      ptr += cs;
      rptr += crs;
      s -= cs;
      rs -= crs;
    }

#ifndef TEST
  assert (grub_memcmp (tmp, buffer, data_size) == 0);
#endif
exit:
  free (tmp);
}
#endif

void REED_SOLOMON_ATTRIBUTE
grub_reed_solomon_recover (void *ptr_, grub_size_t s, grub_size_t rs)
{
  grub_gf256_single_t *ptr = ptr_;
  grub_gf256_single_t *rptr = ptr + s;
  grub_uint8_t *cptr;

  /* Nothing to do.  */
  if (!rs)
    return;

  for (cptr = rptr + rs - 1; cptr >= rptr; cptr--)
    if (*cptr)
      break;
  if (rptr + rs - 1 - cptr > (grub_ssize_t) rs / 2)
    return;

  while (s > 0)
    {
      grub_size_t tt;
      grub_size_t cs, crs;
      cs = s;
      crs = rs;
      tt = cs + crs;
      if (tt > MAX_BLOCK_SIZE)
	{
	  cs = ((cs * (MAX_BLOCK_SIZE / 512)) / tt) * 512;
	  crs = ((crs * (MAX_BLOCK_SIZE / 512)) / tt) * 512;
	}
      decode_block (ptr, cs, rptr, crs);
      ptr += cs;
      rptr += crs;
      s -= cs;
      rs -= crs;
    }
}

#ifdef TEST
int
main (int argc, char **argv)
{
  FILE *in, *out;
  grub_size_t s, rs;
  char *buf;

  grub_memset (grub_gf256_powx, 0xee, sizeof (gf_powx));
  grub_memset (grub_gf256_powx_inv, 0xdd, sizeof (gf_powx_inv));

#ifndef STANDALONE
  in = grub_util_fopen ("tst.bin", "rb");
  if (!in)
    return 1;
  fseek (in, 0, SEEK_END);
  s = ftell (in);
  fseek (in, 0, SEEK_SET);
  rs = 0x7007;
  buf = xmalloc (s + rs + SECTOR_SIZE);
  fread (buf, 1, s, in);
  fclose (in);

  grub_reed_solomon_add_redundancy (buf, s, rs);

  out = grub_util_fopen ("tst_rs.bin", "wb");
  fwrite (buf, 1, s + rs, out);
  fclose (out);
#else
  out = grub_util_fopen ("tst_rs.bin", "rb");
  fseek (out, 0, SEEK_END);
  s = ftell (out);
  fseek (out, 0, SEEK_SET);
  rs = 0x7007;
  s -= rs;

  buf = xmalloc (s + rs + SECTOR_SIZE);
  fread (buf, 1, s + rs, out);
  fclose (out);  
#endif
#if 1
  grub_memset (buf + 512 * 15, 0, 512);
#endif

  out = grub_util_fopen ("tst_dam.bin", "wb");
  fwrite (buf, 1, s + rs, out);
  fclose (out);
  grub_reed_solomon_recover (buf, s, rs);

  out = grub_util_fopen ("tst_rec.bin", "wb");
  fwrite (buf, 1, s, out);
  fclose (out);

  return 0;
}
#endif
