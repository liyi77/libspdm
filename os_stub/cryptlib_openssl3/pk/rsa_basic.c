/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) libspdm_rsa_new
 * 2) libspdm_rsa_free
 * 3) libspdm_rsa_set_key
 * 4) rsa_pkcs1_verify
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 *
 **/
void *libspdm_rsa_new(void)
{

    /* Allocates & Initializes RSA context by OpenSSL RSA_new()*/

    return (void *)EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void libspdm_rsa_free(void *rsa_context)
{

    /* Free OpenSSL RSA context*/

    EVP_PKEY_CTX_free((EVP_PKEY_CTX *)rsa_context);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  true   RSA key component was set successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, uintn bn_size)
{
    /**
     * @RSA PARAM TABLE
     * P:    OSSL_PKEY_PARAM_RSA_FACTOR1
     * Q:    OSSL_PKEY_PARAM_RSA_FACTOR2
     * DP:   OSSL_PKEY_PARAM_RSA_EXPONENT1
     * DQ:   OSSL_PKEY_PARAM_RSA_EXPONENT2
     * QINV: OSSL_PKEY_PARAM_RSA_COEFFICIENT1
     */

    EVP_PKEY *rsa_key;
    bool status;
    BIGNUM *bn;


    /* Check input parameters.*/

    if (rsa_context == NULL || bn_size > INT_MAX) {
        return false;
    }

    bn = NULL;
    if (BN_bin2bn(big_number, (uint32_t)bn_size, bn) == NULL) {
        return false;
    }

    /* Retrieve the components from RSA object.*/

    rsa_key = EVP_PKEY_CTX_get0_pkey((EVP_PKEY_CTX *)rsa_context);

    /* Set RSA key Components by converting octet string to OpenSSL BN representation.
     * NOTE: For RSA public key (used in signature verification), only public components
     *       (N, e) are needed.*/

    switch (key_tag) {

    /* RSA public Modulus (N), public Exponent (e) and Private Exponent (d)*/

    case LIBSPDM_RSA_KEY_N:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_N, bn);
        break;
    case LIBSPDM_RSA_KEY_E:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_E, bn);
        break;
    case LIBSPDM_RSA_KEY_D:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_D, bn);
        break;


    /* RSA Secret prime Factor of Modulus (p and q)*/

    case LIBSPDM_RSA_KEY_P:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_FACTOR1, bn);
        break;
    case LIBSPDM_RSA_KEY_Q:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_FACTOR2, bn);
        break;


    /* p's CRT Exponent (== d mod (p - 1)),  q's CRT Exponent (== d mod (q - 1)),
     * and CRT Coefficient (== 1/q mod p)*/

    case LIBSPDM_RSA_KEY_DP:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_EXPONENT1, bn);
        break;
    case LIBSPDM_RSA_KEY_DQ:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_EXPONENT2, bn);
        break;
    case LIBSPDM_RSA_KEY_Q_INV:
        EVP_PKEY_set_bn_param(rsa_key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn);
        break;

    default:
        status = false;
        goto err;
    }

    status = true;

err:
    BN_free(bn);

    return status;
}

/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in PKCS1-v1_5.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, uintn hash_nid,
                                       const uint8_t *message_hash,
                                       uintn hash_size, const uint8_t *signature,
                                       uintn sig_size)
{
    int32_t digest_type;
    uint8_t *sig_buf;
    EVP_PKEY *rsa_key;
    EVP_MD *md;


    /* Check input parameters.*/

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        digest_type = NID_sha256;
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        digest_type = NID_sha384;
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        digest_type = NID_sha512;
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        digest_type = NID_sha3_256;
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        digest_type = NID_sha3_384;
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        digest_type = NID_sha3_512;
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    rsa_key = (EVP_PKEY *)rsa_context;
    sig_buf = (uint8_t *)signature;

    /* Initialize context for verification and set options. */
    if (EVP_PKEY_verify_init(rsa_key) == 0) {
        return false;
    }

    /* Verify signature. */
    return (bool)EVP_PKEY_verify(rsa_key, sig_buf, (uint32_t)sig_size,
                        message_hash, (uint32_t)hash_size);

}

/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify(void *rsa_context, uintn hash_nid,
                            const uint8_t *message_hash, uintn hash_size,
                            const uint8_t *signature, uintn sig_size)
{
    const EVP_MD *evp_md;
    uint8_t *sig_buf;
    EVP_PKEY *rsa_key;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    rsa = rsa_context;
    size = RSA_size(rsa);
    if (sig_size != (uintn)size) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        evp_md = EVP_sha256();
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        evp_md = EVP_sha384();
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        evp_md = EVP_sha512();
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        evp_md = EVP_sha3_256();
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        evp_md = EVP_sha3_384();
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        evp_md = EVP_sha3_512();
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    /* Initialize context for verification and set options. */
    if (EVP_PKEY_verify_init(rsa_key) == 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set_signature_md(rsa_key, evp_md) == 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(rsa_key, RSA_PKCS1_PSS_PADDING) == 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(rsa_key, RSA_PKCS1_PSS_PADDING) == 0) {
        return false;
    }

    /* Verify signature. */
    return (bool)EVP_PKEY_verify(rsa_key, sig_buf, (uint32_t)sig_size,
                        message_hash, (uint32_t)hash_size);




    return result;
}
