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
	   : "memory", "r0");
  return vec;
#else
  return vec_vsx_ld (offset, ptr);
#endif
}

#include <stdio.h>

void hexDump (const char *desc, const void *addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char *pc = (const unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

#define STORE_TABLE(gcm_table, slot, vec) \
  vec_aligned_st (((block)vec), slot * 16, (unsigned char *)(gcm_table)); \
  hexDump("", &vec, 16);


static ASM_FUNC_ATTR_INLINE void
vec_aligned_st(block vec, unsigned long offset, unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  __asm__ ("stvx %0,%1,%2\n\t"
	   :
	   : "v" (vec), "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory", "r0");
#else
  vec_vsx_st ((vector16x_u8)vec, offset, ptr);
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
	   : "memory", "r0");
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

  After saving the magic c2 constant and pre-formatted version of the key,
  we pre-process the key for parallel hashing. This takes advantage of the identity
  of addition over a glois field being identital to XOR, and thus cumulative. (S 2.2, page 3)
  We multiply and add (glois field versions) the key over multiple iterations and save the result.
  This can later be glois added (XORed) with parallel processed input.

  The ghash "key" is a salt.
 */
void ASM_FUNC_ATTR 
_gcry_ghash_setup_ppc_vpmsum (uint64_t *gcm_table, void *gcm_key)
{
  vector2x_u64 zero8 = {0, 0};
  vector16x_u8 bswap64_const = { 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 };
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector1x_u128 H = VEC_LOAD_BE(gcm_key, bswap_const);

  vector16x_u8 t0, t1, t2, most_sig_of_H, t4, t5, t6;
  vector2x_u64 d0, d1, d2;
  vector2x_u64 in, in2;
  vector2x_u64 H_lo = zero8, H_hi = zero8;
  vector2x_u64 lo, mid, hi;
  vector2x_u64 H2_lo = zero8, H2, H2_hi = zero8;
  vector2x_u64 X_lo, X2_lo, X_mid, X2_mid, X_hi, X2_hi,
    reduce, reduce2;

  // This in a long sequence to create the following constant
  // { U64_C(0x0000000000000001), U64_C(0xc200000000000000) };
  //c2 = vec_splat_u8(-16); // 0xf0, because gcc is buggy
  //t0 = vec_splat_u8(1);
  //c2 = c2 + c2; // 0xe0
  //c2 = c2 | t0; // 0xe1
  //c2 = (vector16x_u8)((vector1x_u128)(c2) << (15 * 8));
  //t1 = (vector16x_u8)((vector1x_u128)(t0) >> (15 * 8));
  //c2 = c2 + c2; // 0xc2
  //c2 = c2 | t1; // 0xc2......01 finially
  vector2x_u64 c2orig = { 0x0000000000000001ULL, 0xc200000000000000ULL };
  vector16x_u8 c2 = (vector16x_u8)c2orig;

  // rotate H
  t2 = vec_splat_u8(7);
  most_sig_of_H = vec_splat((vector16x_u8)H, 15);
  vector1x_u128 one = {1};
  H = H << one; // vsl is a strange instruction, and I don't think it is modeled, but it can reuse t0 above
  most_sig_of_H = most_sig_of_H >> t2;
  most_sig_of_H = most_sig_of_H & c2;
  in = (vector2x_u64)(H ^ (vector1x_u128)most_sig_of_H);

  c2 = (vector16x_u8)((vector1x_u128)c2 >> 64); // change mask to 00000000c2000000

  H = (((vector1x_u128)in << 64) | ((vector1x_u128)in >> 64));
  H_lo[0] = ((vector2x_u64)H)[1];
  H_hi[1] = ((vector2x_u64)H)[0];

  STORE_TABLE(gcm_table, 0, c2);
  STORE_TABLE(gcm_table, 1, H_lo);
  STORE_TABLE(gcm_table, 2, H);
  STORE_TABLE(gcm_table, 3, H_hi);

  lo = asm_vpmsumd(H_lo, in); // do not need to mask in because 0 * anything -> 0
  mid = asm_vpmsumd((vector2x_u64)H, in);
  hi = asm_vpmsumd(H_hi, in);

  // reduce 1
  d2 = asm_vpmsumd(lo, (vector2x_u64)c2);

  d0 = (vector2x_u64)((vector1x_u128)mid << 64);
  d1 = (vector2x_u64)((vector1x_u128)mid >> 64);
  lo ^= d0;
  hi ^= d1;
  lo = (vector2x_u64)((vector1x_u128)lo << 64 | (vector1x_u128)lo >> 64);
  lo ^= d2;

  // reduce 2
  d1 = (vector2x_u64)((vector1x_u128)lo << 64 | (vector1x_u128)lo >> 64);
  lo = asm_vpmsumd(lo, (vector2x_u64)c2);
  d1 ^= hi;
  in2 = lo ^ d1;

  H2 = (vector2x_u64)(((vector1x_u128)in2 << 64) | ((vector1x_u128)in2 >> 64));
  H2_lo[0] = ((vector2x_u64)H2)[1];
  H2_hi[1] = ((vector2x_u64)H2)[0];

  STORE_TABLE(gcm_table, 4, H2_lo);
  STORE_TABLE(gcm_table, 5, H2);
  STORE_TABLE(gcm_table, 6, H2_hi);

  X_lo = asm_vpmsumd(H2_lo, in);
  X2_lo = asm_vpmsumd(H2_lo, in2);
  X_mid = asm_vpmsumd(H2, in);
  X2_mid = asm_vpmsumd(H2, in2);
  X_hi = asm_vpmsumd(H2_hi, in);
  X2_hi = asm_vpmsumd(H2_hi, in2);

  reduce = asm_vpmsumd(X_lo, (vector2x_u64)c2);
  reduce2 = asm_vpmsumd(X2_lo, (vector2x_u64)c2);

  X_lo ^= (vector2x_u64)((vector1x_u128)X_mid << 64);
  X_hi ^= (vector2x_u64)((vector1x_u128)X_mid >> 64);
  X2_lo ^= (vector2x_u64)((vector1x_u128)X2_mid << 64);
  X2_hi ^= (vector2x_u64)((vector1x_u128)X2_mid >> 64);

  H = ((vector1x_u128)X_lo << 64 | (vector1x_u128)X_lo >> 64);
  H2[0] = ((vector2x_u64)X2_lo)[1];
  H2[1] = ((vector2x_u64)X2_lo)[0];

  H ^=  (vector1x_u128)reduce;
  H2 ^= reduce2;

  // We could have also b64 switched reduce and reduce2, however as we are
  // using the unrotated H and H2 above to vpmsum, this is marginally better.
  reduce[0] = ((vector2x_u64)H)[1];
  reduce[1] = ((vector2x_u64)H)[0];
  reduce2[0] = ((vector2x_u64)H2)[1];
  reduce2[1] = ((vector2x_u64)H2)[0];

  H =  (vector1x_u128)asm_vpmsumd((vector2x_u64)H, (vector2x_u64)c2);
  H2 = asm_vpmsumd(H2, (vector2x_u64)c2);

  reduce ^= X_hi;
  reduce2 ^= X2_hi;
  H ^= (vector1x_u128)reduce;
  H2 ^= reduce2;

  H_lo = (vector2x_u64)((vector1x_u128)H << 64);
  H_hi = (vector2x_u64)((vector1x_u128)H >> 64);
  H2_lo = (vector2x_u64)((vector1x_u128)H2 << 64);
  H2_hi = (vector2x_u64)((vector1x_u128)H2 >> 64);

  STORE_TABLE(gcm_table, 7, H_lo);
  STORE_TABLE(gcm_table, 8, H);
  STORE_TABLE(gcm_table, 9, H_hi);
  STORE_TABLE(gcm_table, 10, H2_lo);
  STORE_TABLE(gcm_table, 11, H2);
  STORE_TABLE(gcm_table, 12, H2_hi);
}

unsigned int ASM_FUNC_ATTR
__attribute__((optimize(0)))
_gcry_ghash_ppc_vpmsum (volatile byte *result, void *gcm_table, volatile const byte *buf,
                          volatile size_t nblocks)
{
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 bswap_8_const = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  volatile block c2, Hl, Hm, Hh, in, Hm_right, Hl_rotate, cur;

  volatile block t0;

  cur = vec_aligned_ld(0, result);

for (int i=0;i!=nblocks;i++) {
  in = vec_load_be(16 * i, (vector16x_u8*)buf, bswap_const);
  cur ^= in;
  c2 = vec_aligned_ld(0, gcm_table);
  Hl = vec_aligned_ld(16, gcm_table);
  Hm = vec_aligned_ld(32, gcm_table);
  Hh = vec_aligned_ld(48, gcm_table);

  Hl = (block)asm_vpmsumd((vector2x_u64)cur, (vector2x_u64)Hl);
  Hm = (block)asm_vpmsumd((vector2x_u64)cur, (vector2x_u64)Hm);
  Hh = (block)asm_vpmsumd((vector2x_u64)cur, (vector2x_u64)Hh);

  t0 = (block)asm_vpmsumd((vector2x_u64)Hl, (vector2x_u64)c2);

  Hl ^= Hm << 64;

  Hm_right = Hm >> 64;
  Hh ^= Hm_right;
  Hl_rotate = Hl << 64 | Hl >> 64;
  Hl_rotate ^= t0;
  Hl = Hl_rotate << 64 | Hl_rotate >> 64;
  Hl_rotate = (block)asm_vpmsumd((vector2x_u64)Hl_rotate, (vector2x_u64)c2);
  Hl ^= Hh;
  Hl ^= Hl_rotate;

  cur = Hl;
}

  cur = (block)vec_perm((vector16x_u8)cur, (vector16x_u8)cur, bswap_8_const);
  STORE_TABLE(result, 0, cur);
}

#endif /* GCM_USE_PPC_VPMSUM */
