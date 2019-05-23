/* SHA2 for GnuPG
 * Copyright (C) 2000, 2001, 2002, 2003, 2007,
 *               2008, 2011, 2012 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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

#ifndef G10_SHA2_COMMON_H
#define G10_SHA2_COMMON_H

/* USE_ARM_NEON_ASM indicates whether to enable ARM NEON assembly code. */
#undef USE_ARM_NEON_ASM
#ifdef ENABLE_NEON_SUPPORT
# if defined(HAVE_ARM_ARCH_V6) && defined(__ARMEL__) \
     && defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS) \
     && defined(HAVE_GCC_INLINE_ASM_NEON)
#  define USE_ARM_NEON_ASM 1
# endif
#endif /*ENABLE_NEON_SUPPORT*/


/* USE_ARM_ASM indicates whether to enable ARM assembly code. */
#undef USE_ARM_ASM
#if defined(__ARMEL__) && defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS)
# define USE_ARM_ASM 1
#endif


/* USE_SSSE3 indicates whether to compile with Intel SSSE3 code. */
#undef USE_SSSE3
#if defined(__x86_64__) && defined(HAVE_GCC_INLINE_ASM_SSSE3) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
     defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
# define USE_SSSE3 1
#endif


/* USE_AVX indicates whether to compile with Intel AVX code. */
#undef USE_AVX
#if defined(__x86_64__) && defined(HAVE_GCC_INLINE_ASM_AVX) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
     defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
# define USE_AVX 1
#endif


/* USE_AVX2 indicates whether to compile with Intel AVX2/rorx code. */
#undef USE_AVX2
#if defined(__x86_64__) && defined(HAVE_GCC_INLINE_ASM_AVX2) && \
    defined(HAVE_GCC_INLINE_ASM_BMI2) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
     defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
# define USE_AVX2 1
#endif

/* USE_PPC_ASM indicates whether to compile with PowerISA 2.07 crypto support */
#undef USE_PPC_ASM
#ifdef ENABLE_PPC_CRYPTO_SUPPORT
# if defined(__powerpc64__) || defined(__powerpc__)
#   define USE_PPC_ASM 1
# endif
#endif

/* Assembly implementations use SystemV ABI, ABI conversion and additional
 * stack to store XMM6-XMM15 needed on Win64. */
#undef ASM_FUNC_ABI
#undef ASM_EXTRA_STACK
#if defined(USE_SSSE3) || defined(USE_AVX) || defined(USE_AVX2) || \
    defined(USE_SHAEXT)
# ifdef HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS
#  define ASM_FUNC_ABI __attribute__((sysv_abi))
#  define ASM_EXTRA_STACK (10 * 16 + sizeof(void *) * 4)
# else
#  define ASM_FUNC_ABI
#  define ASM_EXTRA_STACK 0
# endif
#endif
#endif