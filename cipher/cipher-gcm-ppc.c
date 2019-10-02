/* cipher-gcm-gcm.c  -  Power 8 vpmsum accelerated Galois Counter Mode
 *                               implementation
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

#ifdef GCM_USE_PPC_VPMSUM

#include <altivec.h>

#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR        NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE ASM_FUNC_ATTR ALWAYS_INLINE

typedef vector unsigned char vector16x_u8;
typedef vector unsigned long long vector2x_u64;
typedef vector unsigned __int128 vector1x_u128;
typedef vector unsigned __int128 block;

static ASM_FUNC_ATTR_INLINE vector2x_u64
asm_vpmsumd(vector2x_u64 a, vector2x_u64 b)
{
  vector2x_u64 r;
  __asm__("vpmsumd %0, %1, %2"
	  : "=v" (r)
	  : "v" (a), "v" (b));
  return r;
}

#define ALIGNED_LOAD(in_ptr) \
  (vec_aligned_ld (0, (const unsigned char *)(in_ptr)))

static ASM_FUNC_ATTR_INLINE block
vec_aligned_ld(unsigned long offset, const unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  __asm__ ("lvx %0,%1,%2\n\t"
	   : "=v" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
  return vec;
#else
  return vec_vsx_ld (offset, ptr);
#endif
}

#define STORE_TABLE(slot, vec) \
  (vec_aligned_st (((block)vec), slot * 16, (unsigned char *)(gcm_table)))


static ASM_FUNC_ATTR_INLINE void
vec_aligned_st(block vec, unsigned long offset, unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  __asm__ ("stvx %0,%1,%2\n\t"
	   :
	   : "v" (vec), "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
#else
  vec_vsx_st (vec, offset, ptr);
#endif
}


#define VEC_LOAD_BE(in_ptr, bswap_const) \
  (vec_load_be (0, (const unsigned char *)(in_ptr), bswap_const))

static ASM_FUNC_ATTR_INLINE block
vec_load_be(unsigned long offset, const unsigned char *ptr,
	    vector unsigned char be_bswap_const)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  /* GCC vec_vsx_ld is generating two instructions on little-endian. Use
   * lxvw4x directly instead. */
  __asm__ ("lxvw4x %x0,%1,%2\n\t"
	   : "=wa" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
  __asm__ ("vperm %0,%1,%1,%2\n\t"
	   : "=v" (vec)
	   : "v" (vec), "v" (be_bswap_const));
  return vec;
#else
  (void)be_bswap_const;
  return vec_vsx_ld (offset, ptr);
#endif
}

/*
 Power ghash based on papers:
  "The Galois/Counter Mode of Operation (GCM)"; David A. McGrew, John Viega
  "Intel® Carry-Less Multiplication Instruction and its Usage for Computing the
   GCM Mode - Rev 2.01"; Shay Gueron, Michael E. Kounavis.
 */
void ASM_FUNC_ATTR 
__attribute__((optimize(0)))
_gcry_ghash_setup_ppc_vpmsum (uint64_t *gcm_table, void *gcm_key)
{
  volatile vector2x_u64 zero8 = {0, 0};
  volatile vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 3, 4, 5, 6, 0, 1, 2, 3 };
  volatile vector1x_u128 H = VEC_LOAD_BE(gcm_key, bswap_const);

  volatile vector16x_u8 c2, t0, t1, t2, most_sig_of_H, t4, t5, t6;
  volatile vector2x_u64 in, in1;
  volatile vector2x_u64 H_lo = zero8, H_hi = zero8;
  volatile vector2x_u64 lo, mid, hi;
  volatile vector2x_u64 H2_lo = zero8, H2, H2_hi = zero8;

  // This in a long sequence to create the following constant
  // { U64_C(0x0000000000000001), U64_C(0xc200000000000000) };
  c2 = vec_splat_u8(-16); // 0xf0, because gcc is buggy
  t0 = vec_splat_u8(1);
  c2 = c2 + c2; // 0xe0
  c2 = c2 | t0; // 0xe1
  c2 = (vector16x_u8)((vector1x_u128)(c2) << (15 * 8));
  t1 = (vector16x_u8)((vector1x_u128)(t0) >> (15 * 8));
  c2 = c2 + c2; // 0xc2
  c2 = c2 | t1; // 0xc2......01 finially

  // rotate H
  t2 = vec_splat_u8(7);
  most_sig_of_H = vec_splat((vector16x_u8)H, 15);
  H = H << (vector1x_u128)t1;
  most_sig_of_H = most_sig_of_H >> t2;
  most_sig_of_H = most_sig_of_H & c2;
  in = (vector2x_u64)(H ^ (vector1x_u128)most_sig_of_H);

  c2 = (vector16x_u8)((vector1x_u128)c2 >> 64); // change mask to 00000000c2000000

  H = (((vector1x_u128)in << 64) | ((vector1x_u128)in >> 64));
  H_lo[0] = ((vector2x_u64)H)[1];
  H_hi[0] = ((vector2x_u64)H)[0];

  STORE_TABLE(1, c2);
  STORE_TABLE(2, H_lo);
  STORE_TABLE(3, H);
  STORE_TABLE(4, H_hi);

  lo = asm_vpmsumd(H_lo, in); // do not need to mask in because 0 * anything -> 0
  mid = asm_vpmsumd((vector2x_u64)H, in);
  hi = asm_vpmsumd(H_hi, in);

  // reduce 1
  t2 = asm_vpmsumd(lo, (vector2x_u64)c2);

  t0 = mid << 64;
  t1 = mid >> 64;
  lo ^= t0;
  hi ^= t1;
  lo = (vector1x_u128)lo << 64 | (vector1x_u128)lo >> 64;
  lo ^= t2;

  // reduce 2
  t1 = (vector1x_u128)lo << 64 | (vector1x_u128)lo >> 64;
  low = asm_vpmsumd(lo, t2);
  t1 ^= hi;
  in1 = lo ^ t1;

  H2 = ((vector1x_u128)in1 << 64) | ((vector1x_u128)in1 >> 64);
  H2_lo[0] = ((vector2x_u64)H2)[1];
  H2_hi[0] = ((vector2x_u64)H2)[0];

  STORE_TABLE(5, H2_lo);
  STORE_TABLE(6, H2);
  STORE_TABLE(7, H2_hi);

  abort();
}

unsigned int ASM_FUNC_ATTR
_gcry_ghash_ppc_vpmsum (gcry_cipher_hd_t c, byte *result, const byte *buf,
                          size_t nblocks)
{
  return 0;
}

#endif /* GCM_USE_PPC_VPMSUM */
