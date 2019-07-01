/* Rijndael (AES) for GnuPG - PowerPC ISA 2.07 (POWER 8)
 * Copyright (C) 2019 Shawn Landden
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
 *
 * Alternatively, this code may be used in OpenSSL from The OpenSSL Project,
 * and Cryptogams by Andy Polyakov, and if made part of a release of either
 * or both projects, is thereafter dual-licensed under the license said project
 * is released under.
 */

#include <config.h>
#include "rijndael-internal.h"
#include "./cipher-internal.h"

size_t _gcry_aes_ppc8_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
                                 const void *inbuf_arg, size_t nblocks,
                                 int encrypt);
unsigned int _gcry_aes_ppc8_encrypt (const RIJNDAEL_context *ctx,
                                     unsigned char *b,
                                     const unsigned char *a);
unsigned int _gcry_aes_ppc8_decrypt (const RIJNDAEL_context *ctx,
                                     unsigned char *b,
                                     const unsigned char *a);

