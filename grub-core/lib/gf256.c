/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright 2011-2019 Free Software Foundation, Inc.
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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/gf256.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GF_SIZE 8
#define GF_POLYNOMIAL 0x1d
#define GF_INVERT2 0x8e

#ifdef __APPLE__
#define ATTRIBUTE_TEXT __attribute__ ((section("_text,_text")))
#else
#define ATTRIBUTE_TEXT __attribute__ ((section(".text")))
#endif

#if defined (STANDALONE) && !defined (TEST)
grub_gf256_single_t * const grub_gf256_powx ATTRIBUTE_TEXT = (void *) 0x100000;
grub_gf256_single_t * const grub_gf256_powx_inv ATTRIBUTE_TEXT = (void *) 0x100200;
static int * const chosenstat ATTRIBUTE_TEXT = (void *) 0x100300;
/* Next available address: (void *) 0x112000.  */
#else
grub_gf256_single_t grub_gf256_powx[255 * 2];
grub_gf256_single_t grub_gf256_powx_inv[256];
static int chosenstat[256];
#endif

grub_gf256_single_t
grub_gf256_pol_evaluate (grub_gf256_single_t *pol, grub_size_t degree, int log_x)
{
  int i;
  grub_gf256_single_t s = 0;
  int log_xn = 0;

  for (i = degree; i >= 0; i--)
    {
      if (pol[i])
	s ^= grub_gf256_mulx (log_xn, pol[i]);
      log_xn += log_x;
      if (log_xn >= ((1 << GF_SIZE) - 1))
	log_xn -= ((1 << GF_SIZE) - 1);
    }
  return s;
}

void
grub_gf256_gauss_eliminate (grub_gf256_single_t *eq, int n, int m, int *chosen)
{
  int i, j;

  for (i = 0 ; i < n; i++)
    {
      int nzidx;
      int k;
      grub_gf256_single_t r;
      for (nzidx = 0; nzidx < m && (eq[i * (m + 1) + nzidx] == 0);
	   nzidx++);
      if (nzidx == m)
	continue;
      chosen[i] = nzidx;
      r = grub_gf256_invert (eq[i * (m + 1) + nzidx]);
      for (j = 0; j < m + 1; j++)
	eq[i * (m + 1) + j] = grub_gf256_mul (eq[i * (m + 1) + j], r);
      for (j = i + 1; j < n; j++)
	{
	  grub_gf256_single_t rr = eq[j * (m + 1) + nzidx];
	  for (k = 0; k < m + 1; k++)
	    eq[j * (m + 1) + k] ^= grub_gf256_mul (eq[i * (m + 1) + k], rr);
	}
    }
}

void
grub_gf256_gauss_solve (grub_gf256_single_t *eq, int n, int m, grub_gf256_single_t *sol)
{
  int i, j;

  for (i = 0; i < n; i++)
    chosenstat[i] = -1;
  for (i = 0; i < m; i++)
    sol[i] = 0;
  grub_gf256_gauss_eliminate (eq, n, m, chosenstat);
  for (i = n - 1; i >= 0; i--)
    {
      grub_gf256_single_t s = 0;
      if (chosenstat[i] == -1)
	continue;
      for (j = 0; j < m; j++)
	s ^= grub_gf256_mul (eq[i * (m + 1) + j], sol[j]);
      s ^= eq[i * (m + 1) + m];
      sol[chosenstat[i]] = s;
    }
}

GRUB_MOD_INIT(gf256)
{
  int i;
  grub_uint8_t cur = 1;

  grub_gf256_powx_inv[0] = 0;
  for (i = 0; i < 255; i++)
    {
      grub_gf256_powx[i] = cur;
      grub_gf256_powx[i + 255] = cur;
      grub_gf256_powx_inv[cur] = i;
      if (cur & (1ULL << (GF_SIZE - 1)))
	cur = (cur << 1) ^ GF_POLYNOMIAL;
      else
	cur <<= 1;
    }
}

GRUB_MOD_FINI(gf256)
{
}
