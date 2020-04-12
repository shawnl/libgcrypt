/* cipher-gcm-gcm.c  -  Power 8 vpmsum accelerated Galois Counter Mode
 *                               implementation
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>
 *
 * This file is part of Libgcrypt.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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

#define STORE_TABLE(gcm_table, slot, vec) \
  vec_aligned_st (((block)vec), slot * 16, (unsigned char *)(gcm_table));


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
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 c2 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0b11000010};
  vector1x_u128 T0, T1, T2;
  vector1x_u128 C2, H, H1, H1l, H1h, H2, H2l, H2h;
  vector1x_u128 H3l, H3, H3h, H4l, H4, H4h, T3, T4;
  vector16x_s8 most_sig_of_H, t7, carry;
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
  
  H3l = asm_vpmsumd(H2l, H1);
  H4l = asm_vpmsumd(H2l, H2);
  H3 = asm_vpmsumd(T2, H1);
  H4 = asm_vpmsumd(T2, H2);
  H3h = asm_vpmsumd(H2h, H1);
  H4h = asm_vpmsumd(H2h, H2);

  T3 = asm_vpmsumd(H3l, C2);
  T4 = asm_vpmsumd(H4l, C2);

  H3l ^= H3 << 64;
  H3h ^= H3 >> 64;
  H4l ^= H4 << 64;
  H4h ^= H4 >> 64;

  H3 = H3l << 64 | H3l >> 64;
  H4 = H4l << 64 | H4l >> 64;

  H3 ^= T3;
  H4 ^= T4;

  // We could have also b64 switched reduce and reduce2, however as we are
  // using the unrotated H and H2 above to vpmsum, this is marginally better.
  T3 = H3 << 64 | H3 >> 64;
  T4 = H4 << 64 | H4 >> 64;

  H3 = asm_vpmsumd(H3, C2);
  H4 = asm_vpmsumd(H4, C2);

  T3 ^= H3h;
  T4 ^= H4h;
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


block vec_perm2(block l, block r, vector16x_u8 perm) {
  block ret;
  __asm__ ("vperm %0,%1,%2,%3\n\t"
	   : "=v" (ret)
	   : "v" (l), "v" (r), "v" (perm));
  return ret;
}

#include <assert.h>
void ASM_FUNC_ATTR
_gcry_ghash_ppc_vpmsum (const byte *result, const void *const gcm_table, const byte *const buf,
                          const size_t nblocks)
{
  // This const is strange, it is reversing the bytes, and also reversing the u32s that get switched by lxvw4
  // and it also addresses bytes big-endian, and is here due to lack of proper peep-hole optimization.
  vector16x_u8 bswap_const = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 bswap_8_const = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  block c2, H0l, H0m, H0h, H4l, H4m, H4h, H2l, H2m, H2h, H3l, H3m, H3h, Hl, Hm, Hh, in, in0, in1, in2, in3, Hm_right, Hl_rotate, cur;
  size_t blocks_remaining = nblocks, off = 0;

  block t0;

  cur = vec_load_be(0, (vector16x_u8*)result, bswap_const);
  
  c2 = vec_aligned_ld(0, gcm_table);
  H0l = vec_aligned_ld(16, gcm_table);
  H0m = vec_aligned_ld(32, gcm_table);
  H0h = vec_aligned_ld(48, gcm_table);

for (size_t not_multiple_of_four = nblocks % 4; not_multiple_of_four; not_multiple_of_four--) {
  in = vec_load_be(off, (vector16x_u8*)buf, bswap_const);
  off += 16;
  blocks_remaining--;
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

  if (blocks_remaining > 0) {
    vector16x_u8 hiperm = {0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0},
      loperm = {0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8};
    block Xl, Xm, Xh, Xl1, Xm1, Xh1, Xl2, Xm2, Xh2, Xl3, Xm3, Xh3, Xl_rotate;
    block H21l, H21h, merge_l, merge_h;

    H2l = vec_aligned_ld(48 + 16, gcm_table);
    H2m = vec_aligned_ld(48 + 32, gcm_table);
    H2h = vec_aligned_ld(48 + 48, gcm_table);
    H3l = vec_aligned_ld(48 * 2 + 16, gcm_table);
    H3m = vec_aligned_ld(48 * 2 + 32, gcm_table);
    H3h = vec_aligned_ld(48 * 2 + 48, gcm_table);
    H4l = vec_aligned_ld(48 * 3 + 16, gcm_table);
    H4m = vec_aligned_ld(48 * 3 + 32, gcm_table);
    H4h = vec_aligned_ld(48 * 3 + 48, gcm_table);

    in0 = vec_load_be(off, (vector16x_u8*)buf, bswap_const);
    in1 = vec_load_be(off + 16, (vector16x_u8*)buf, bswap_const);
    in2 = vec_load_be(off + 32, (vector16x_u8*)buf, bswap_const);
    in3 = vec_load_be(off + 48, (vector16x_u8*)buf, bswap_const);
    blocks_remaining -= 4;
    off += 64;

    Xh = in0 ^ cur;

    Xl1 = asm_vpmsumd(in1, H3l);
    Xm1 = asm_vpmsumd(in1, H3m);
    Xh1 = asm_vpmsumd(in1, H3h);

    H21l = vec_perm2(H2m, H0m, hiperm);
    H21h = vec_perm2(H2m, H0m, loperm);
    merge_l = vec_perm2(in2, in3, loperm);
    merge_h = vec_perm2(in2, in3, hiperm);

    Xm2 = asm_vpmsumd(in2, H2m);
    Xl3 = asm_vpmsumd(merge_l, H21l);
    Xm3 = asm_vpmsumd(in3, H0m);
    Xh3 = asm_vpmsumd(merge_h, H21h);

    Xm2 ^= Xm1;
    Xl3 ^= Xl1;
    Xm3 ^= Xm2;
    Xh3 ^= Xh1;

    for (;blocks_remaining > 0; blocks_remaining -= 4, off += 64) {
      in0 = vec_load_be(off, (vector16x_u8*)buf, bswap_const);
      in1 = vec_load_be(off + 16, (vector16x_u8*)buf, bswap_const);
      in2 = vec_load_be(off + 32, (vector16x_u8*)buf, bswap_const);
      in3 = vec_load_be(off + 48, (vector16x_u8*)buf, bswap_const);

      Xl = asm_vpmsumd(Xh, H4l);
      Xm = asm_vpmsumd(Xh, H4m);
      Xh = asm_vpmsumd(Xh, H4h);
      Xl1 = asm_vpmsumd(in1, H3l);
      Xm1 = asm_vpmsumd(in1, H3m);
      Xh1 = asm_vpmsumd(in1, H3h);

      Xl ^= Xl3;
      Xm ^= Xm3;
      Xh ^= Xh3;
      merge_l = vec_perm2(in2, in3, loperm);
      merge_h = vec_perm2(in2, in3, hiperm);

      t0 = asm_vpmsumd(Xl, c2);
      Xl3 = asm_vpmsumd(merge_l, H21l);
      Xh3 = asm_vpmsumd(merge_h, H21h);

      Xl ^= Xm << 64;
      Xh ^= Xm >> 64;

      Xl = Xl << 64 | Xl >> 64;
      Xl ^= t0;

      Xl_rotate = Xl << 64 | Xl >> 64;
      Xm2 = asm_vpmsumd(in2, H2m);
      Xm3 = asm_vpmsumd(in3, H0m);
      Xl = asm_vpmsumd(Xl, c2);

      Xl3 ^= Xl1;
      Xh3 ^= Xh1;
      Xh ^= in0;
      Xm2 ^= Xm1;
      Xh ^= Xl_rotate;
      Xm3 ^= Xm2;
      Xh ^= Xl;
    }

    Xl = asm_vpmsumd(Xh, H4l);
    Xm = asm_vpmsumd(Xh, H4m);
    Xh = asm_vpmsumd(Xh, H4h);

    Xl ^= Xl3;
    Xm ^= Xm3;

    t0 = asm_vpmsumd(Xl, c2);

    Xh ^= Xh3;
    Xl ^= Xm << 64;
    Xh ^= Xm >> 64;
    
    Xl = Xl << 64 | Xl >> 64;
    Xl ^= t0;

    Xl_rotate = Xl << 64 | Xl >> 64;
    Xl = asm_vpmsumd(Xl, c2);
    Xl_rotate ^= Xh;
    Xl ^= Xl_rotate;

    cur = Xl;
  }
  cur = (block)vec_perm((vector16x_u8)cur, (vector16x_u8)cur, bswap_8_const);
  STORE_TABLE(result, 0, cur);
}

#endif /* GCM_USE_PPC_VPMSUM */
