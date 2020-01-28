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
typedef vector signed char vector16x_s8;
typedef vector unsigned long long vector2x_u64;
typedef vector unsigned __int128 vector1x_u128;
typedef vector unsigned __int128 block;

/* While this would makse sense to use vector2x_u64 given that
 * it works on the first 64 bits and second 64 bits seperately,
 * I find it easier to work with this way, and it makes swapping
 * the two halves much easier as a single vector1x_u128 with can
 * be manipulated with bit shifts.
 */
static ASM_FUNC_ATTR_INLINE block
asm_vpmsumd(block a, block b)
{
  block r;
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

void hexDump (const char *desc, volatile const void *volatile addr, const int len) {
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
__attribute__((optimize(0)))
_gcry_ghash_setup_ppc_vpmsum (uint64_t *gcm_table, void *gcm_key)
{
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  volatile vector16x_u8 c2 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0b11000010};
  volatile vector1x_u128 T0, T1, T2;
  volatile vector1x_u128 C2, H, H1, H1l, H1h, H2, H2l, H2h;
  volatile vector16x_s8 most_sig_of_H, t7, carry;
  vector1x_u128 one = {1};

  H = VEC_LOAD_BE(gcm_key, bswap_const);
  most_sig_of_H = vec_splat((vector16x_s8)H, 15);
  t7 = vec_splat_s8(7);
  carry = most_sig_of_H >> t7;
  carry &= c2; // only interested in certain carries.
  H1 = H << one;
  H1 ^= (vector1x_u128)carry; // complete the <<< 1

  T1 = H1 << 64 | H1 >> 64;
  H1l = T1 >> 64;
  H1h = T1 << 64;
  C2 = (vector1x_u128)c2 >> 64;

  STORE_TABLE(gcm_table, 0, C2);
  STORE_TABLE(gcm_table, 1, H1l);
  STORE_TABLE(gcm_table, 2, T1);
  STORE_TABLE(gcm_table, 3, H1h);

  H2l = asm_vpmsumd(H1l, H1); // do not need to mask in because 0 * anything -> 0
  H2 = asm_vpmsumd(T1, H1);
  H2h = asm_vpmsumd(H1h, H1);

  // reduce 1
  T0 = asm_vpmsumd(H2l, C2);

  H2l ^= H2 << 64;
  H2h ^= H2 >> 64;
  H2l = H2l << 64 | H2l >> 64;
  H2l ^= T0;
  // reduce 2
  T0 = H2l << 64 | H2l >> 64;
  H2l = asm_vpmsumd(H2l, C2);
  H2 = H2l ^ H2h ^ T0;

  T2 = H2 << 64 | H2 >> 64;
  H2l = T2 >> 64;
  H2h = T2 << 64;

  STORE_TABLE(gcm_table, 4, H2l);
  STORE_TABLE(gcm_table, 5, T2);
  STORE_TABLE(gcm_table, 6, H2h);
  
  volatile vector1x_u128 H3l, H3, H3h, H4l, H4, H4h, T3, T4;
  volatile vector2x_u64 X_lo, X2_lo, X_mid, X2_mid, X_hi, X2_hi, reduce, reduce2, H22, H_lo, H_hi, H2_lo, H2_hi;
  
  X_lo = (vector2x_u64)asm_vpmsumd(H2l, H1);
  X2_lo = (vector2x_u64)asm_vpmsumd(H2l, H2);
  X_mid = (vector2x_u64)asm_vpmsumd(T2, H1);
  X2_mid = (vector2x_u64)asm_vpmsumd(T2, H2);
  X_hi = (vector2x_u64)asm_vpmsumd(H2h, H1);
  X2_hi = (vector2x_u64)asm_vpmsumd(H2h, H2);

  T3 = asm_vpmsumd((block)X_lo, C2);
  T4 = asm_vpmsumd((block)X2_lo, C2);

  X_lo ^= (vector2x_u64)((vector1x_u128)X_mid << 64);
  X_hi ^= (vector2x_u64)((vector1x_u128)X_mid >> 64);
  X2_lo ^= (vector2x_u64)((vector1x_u128)X2_mid << 64);
  X2_hi ^= (vector2x_u64)((vector1x_u128)X2_mid >> 64);

  H3 = ((vector1x_u128)X_lo << 64 | (vector1x_u128)X_lo >> 64);
  H4 = (vector1x_u128)X2_lo >> 64 | (vector1x_u128)X2_lo << 64;

  H3 ^= T3;
  H4 ^= T4;

  // We could have also b64 switched reduce and reduce2, however as we are
  // using the unrotated H and H2 above to vpmsum, this is marginally better.
  T3 = H3 << 64 | H3 >> 64;
  T4 = H4 << 64 | H4 >> 64;

  H3 = asm_vpmsumd(H3, C2);
  H4 = asm_vpmsumd(H4, C2);

  T3 ^= (vector1x_u128)X_hi;
  T4 ^= (vector1x_u128)X2_hi;
  H3 ^= T3;
  H4 ^= T4;
  H3 = H3 << 64 | H3 >> 64;
  H4 = H4 << 64 | H4 >> 64;
  
  H3l = H3 >> 64;
  H3h = H3 << 64;
  H4l = H4 >> 64;
  H4h = H4 << 64;

  STORE_TABLE(gcm_table, 7, H3l);
  STORE_TABLE(gcm_table, 8, H3);
  STORE_TABLE(gcm_table, 9, H3h);
  STORE_TABLE(gcm_table, 10, H4l);
  STORE_TABLE(gcm_table, 11, H4);
  STORE_TABLE(gcm_table, 12, H4h);
}

#include <assert.h>
void ASM_FUNC_ATTR
_gcry_ghash_ppc_vpmsum (byte *result, void *gcm_table, const byte *buf,
                          volatile size_t nblocks)
{
  // This const is strange, it is reversing the bytes, and also reversing the u32s that get switched by lxvw4
  // and it also addresses bytes big-endian, and is here due to lack of proper peep-hole optimization.
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 bswap_8_const = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  block c2, H0l, H0m, H0h, Hl, Hm, Hh, in, Hm_right, Hl_rotate, cur;

  block t0;

  //cur = vec_aligned_ld(0, result);
  //cur = (block)vec_perm((vector16x_u8)cur, (vector16x_u8)cur, bswap_8_const);

  cur = vec_load_be(0, (vector16x_u8*)result, bswap_const);

  hexDump("in Xi", result, 16);

  hexDump("table", gcm_table, 64);
  
  c2 = vec_aligned_ld(0, gcm_table);
  H0l = vec_aligned_ld(16, gcm_table);
  H0m = vec_aligned_ld(32, gcm_table);
  H0h = vec_aligned_ld(48, gcm_table);

  hexDump("in", buf, 16 * nblocks);
  
for (size_t off = 0; off != (nblocks * 16); off += 16) {
  in = vec_load_be(off, (vector16x_u8*)buf, bswap_const);
  cur ^= in;

  Hl = asm_vpmsumd(cur, H0l);
  Hm = asm_vpmsumd(cur, H0m);
  Hh = asm_vpmsumd(cur, H0h);

  t0 = asm_vpmsumd(Hl, c2);

  Hl ^= Hm << 64;

  Hm_right = Hm >> 64;
  Hh ^= Hm_right;
  Hl_rotate = Hl << 64 | Hl >> 64;
  Hl_rotate ^= t0;
  Hl = Hl_rotate << 64 | Hl_rotate >> 64;
  Hl_rotate = asm_vpmsumd(Hl_rotate, c2);
  Hl ^= Hh;
  Hl ^= Hl_rotate;

  cur = Hl;
}

  cur = (block)vec_perm((vector16x_u8)cur, (vector16x_u8)cur, bswap_8_const);
  STORE_TABLE(result, 0, cur);
  hexDump("out Xi", result, 16);
}

#endif /* GCM_USE_PPC_VPMSUM */
