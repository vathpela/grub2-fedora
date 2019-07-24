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

#ifndef GRUB_GF256_HEADER
#define GRUB_GF256_HEADER 1

typedef grub_uint8_t grub_gf256_single_t;

#if defined (STANDALONE) && !defined (TEST)
extern grub_gf256_single_t * const grub_gf256_powx;
extern grub_gf256_single_t * const grub_gf256_powx_inv;
#else
extern grub_gf256_single_t EXPORT_VAR(grub_gf256_powx)[255 * 2];
extern grub_gf256_single_t EXPORT_VAR(grub_gf256_powx_inv)[256];
#endif

grub_gf256_single_t EXPORT_FUNC(grub_gf256_pol_evaluate) (grub_gf256_single_t *pol, grub_size_t degree, int log_x);
void EXPORT_FUNC(grub_gf256_gauss_eliminate) (grub_gf256_single_t *eq, int n, int m, int *chosen);
void EXPORT_FUNC(grub_gf256_gauss_solve) (grub_gf256_single_t *eq, int n, int m, grub_gf256_single_t *sol);

static inline grub_gf256_single_t
grub_gf256_mul (grub_gf256_single_t a, grub_gf256_single_t b)
{
  if (a == 0 || b == 0)
    return 0;
  return grub_gf256_powx[(int) grub_gf256_powx_inv[a] + (int) grub_gf256_powx_inv[b]];
}

static inline grub_gf256_single_t
grub_gf256_mulx (unsigned int a, grub_gf256_single_t b)
{
  if (a == 0 || b == 0)
    return 0;
  return grub_gf256_powx[a + (int) grub_gf256_powx_inv[b]];
}

static inline grub_gf256_single_t
grub_gf256_invert (grub_gf256_single_t a)
{
  return grub_gf256_powx[255 - (int) grub_gf256_powx_inv[a]];
}

#endif /* !GRUB_GF256_HEADER */
