/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};


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

#include <gcrypt.h>

void aes_gcm_encrypt(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));
//    ctx = EVP_CIPHER_CTX_new();


    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
abort();    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        abort();
    }

    gcry_cipher_hd_t aes_hd;

(void)gcry_cipher_open(&aes_hd, GCRY_CIPHER_AES256,
                               GCRY_CIPHER_MODE_GCM, 0);

    err = gcry_cipher_setkey(aes_hd,gcm_key, sizeof(gcm_key));
    if (err) {
abort();    }
hexDump("key", aes_hd, sizeof(aes_hd));
    err = gcry_cipher_setiv(aes_hd, gcm_iv, sizeof(gcm_iv));
    if (err) {
abort();    }
    /* Zero or more calls to specify any AAD */
          err = gcry_cipher_authenticate(aes_hd, gcm_aad, sizeof(gcm_aad));
if (err) abort();
          err = gcry_cipher_encrypt (aes_hd, outbuf, sizeof(outbuf),
                                       gcm_pt, sizeof(gcm_pt));
if (err) abort();
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, sizeof(gcm_pt) + 16);
    /* Finalise: note get no output for GCM */
//    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
      err = gcry_cipher_final (aes_hd);
if (err) abort();
    /* Get tag */
//    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
      err = gcry_cipher_gettag (aes_hd, &outbuf[sizeof(gcm_pt)], 16);
if (err) abort();
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, &outbuf[16], 16);
}

void aes_gcm_decrypt(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag),
                        (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char **argv)
{
    aes_gcm_encrypt();
    aes_gcm_decrypt();
}
