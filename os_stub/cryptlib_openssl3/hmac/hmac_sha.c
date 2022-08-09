/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SHA256/384/512 Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <openssl/core_names.h>

/**
 * Allocates and initializes one EVP_MAC_CTX context for subsequent HMAC-MD use.
 *
 * @return  Pointer to the EVP_MAC_CTX context that has been initialized.
 *         If the allocations fails, hmac_md_new() returns NULL.
 *
 **/
void *hmac_md_new(void)
{
    EVP_MAC *mac;
    EVP_MAC_CTX *mctx; 

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac != NULL) {
        mctx = EVP_MAC_CTX_new(mac);
    }

    EVP_MAC_free(mac);
    return (void *)mctx;
}

/**
 * Release the specified EVP_MAC_CTX context.
 *
 * @param[in]  hmac_md_ctx  Pointer to the EVP_MAC_CTX context to be released.
 *
 **/
void hmac_md_free(const void *hmac_md_ctx)
{

    /* Free OpenSSL EVP_MAC_CTX context*/

    EVP_MAC_CTX_free((EVP_MAC_CTX *)hmac_md_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to hmac_md_update().
 *
 * If hmac_md_ctx is NULL, then return false.
 *
 * @param[in]   digest_name        digest_name.
 * @param[out]  hmac_md_ctx      Pointer to HMAC-MD context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
bool hmac_md_set_key(const uint8_t digest_name[], void *hmac_md_ctx,
                     const uint8_t *key, uintn key_size)
{
    OSSL_PARAM params[2];

    /* Check input parameters.*/
    if (digest_name == NULL || hmac_md_ctx == NULL || key_size > INT_MAX) {
        return false;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
                                                 sizeof(digest_name));
    params[1] = OSSL_PARAM_construct_end();

    /* Initialise the HMAC operation */
    if (EVP_MAC_init(hmac_md_ctx, key, key_size, params) != 1) {
        return false;
    }

    return true;
}

// struct evp_mac_ctx_st {
//     EVP_MAC *meth;
//     void *algctx;
// } /* EVP_MAC_CTX */;

/**
 * Makes a copy of an existing HMAC-MD context.
 *
 * If hmac_md_ctx is NULL, then return false.
 * If new_hmac_md_ctx is NULL, then return false.
 *
 * @param[in]  hmac_md_ctx     Pointer to HMAC-MD context being copied.
 * @param[out] new_hmac_md_ctx  Pointer to new HMAC-MD context.
 *
 * @retval true   HMAC-MD context copy succeeded.
 * @retval false  HMAC-MD context copy failed.
 *
 **/
bool hmac_md_duplicate(const void *hmac_md_ctx, void *new_hmac_md_ctx)
{
    // EVP_MAC_CTX *new_ctx;

    // /* Check input parameters.*/

    // if (hmac_md_ctx == NULL || new_hmac_md_ctx == NULL) {
    //     return false;
    // }

    // /* Free ctx new by hmac_md_new(). Backward compatible with openssl1.0 */
    // EVP_MAC_CTX_free((EVP_MAC_CTX *)new_hmac_md_ctx);

    // new_ctx = EVP_MAC_CTX_dup((EVP_MAC_CTX *)hmac_md_ctx);
    // if (new_ctx == NULL) {
    //     return false;
    // }

    // *((EVP_MAC_CTX *)new_hmac_md_ctx) = *new_ctx;
    // free_pool(new_ctx);

    //Blocked here, EVP_MAC_CTX have not a 'copy' function.
    return false;
}

/**
 * Digests the input data and updates HMAC-MD context.
 *
 * This function performs HMAC-MD digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC-MD context should be initialized by hmac_md_new(), and should not be finalized
 * by hmac_md_final(). Behavior with invalid context is undefined.
 *
 * If hmac_md_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_md_ctx     Pointer to the HMAC-MD context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC-MD data digest succeeded.
 * @retval false  HMAC-MD data digest failed.
 *
 **/
bool hmac_md_update(void *hmac_md_ctx, const void *data,
                    uintn data_size)
{

    /* Check input parameters.*/

    if (hmac_md_ctx == NULL) {
        return false;
    }


    /* Check invalid parameters, in case that only DataLength was checked in OpenSSL*/

    if (data == NULL && data_size != 0) {
        return false;
    }


    /* OpenSSL HMAC-MD digest update*/

    if (EVP_MAC_update((EVP_MAC_CTX *)hmac_md_ctx, data, data_size) != 1) {
        return false;
    }

    return true;
}

/**
 * Completes computation of the HMAC-MD digest value.
 *
 * This function completes HMAC-MD hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC-MD context cannot
 * be used again.
 * HMAC-MD context should be initialized by hmac_md_new(), and should not be finalized
 * by hmac_md_final(). Behavior with invalid HMAC-MD context is undefined.
 *
 * If hmac_md_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_md_ctx      Pointer to the HMAC-MD context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-MD digest
 *                                    value.
 *
 * @retval true   HMAC-MD digest computation succeeded.
 * @retval false  HMAC-MD digest computation failed.
 *
 **/
bool hmac_md_final(void *hmac_md_ctx, uint8_t *hmac_value)
{
    size_t length;


    /* Check input parameters.*/

    if (hmac_md_ctx == NULL || hmac_value == NULL) {
        return false;
    }


    /* OpenSSL HMAC-MD digest finalization*/

    if (EVP_MAC_final((EVP_MAC_CTX *)hmac_md_ctx, NULL, &length, 0) != 1) {
        return false;
    }
    if (EVP_MAC_final((EVP_MAC_CTX *)hmac_md_ctx, hmac_value, &length, length) != 1) {
        return false;
    }

    return true;
}

/**
 * Computes the HMAC-MD digest of a input data buffer.
 *
 * This function performs the HMAC-MD digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   digest_name  digest_name.
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-MD digest
 *                         value.
 *
 * @retval true   HMAC-MD digest computation succeeded.
 * @retval false  HMAC-MD digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool hmac_md_all(const uint8_t digest_name[], const void *data,
                 uintn data_size, const uint8_t *key, uintn key_size,
                 uint8_t *hmac_value)
{
    size_t length;
    OSSL_PARAM params[2];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    bool ret_val;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return false;
    }

    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL) {
        EVP_MAC_free(mac);
        return false;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
                                            sizeof(digest_name));
    params[1] = OSSL_PARAM_construct_end();

    /* Initialise the HMAC operation */
    ret_val = (bool)EVP_MAC_init(mctx, key, key_size, params);
    if (!ret_val) {
        goto done;
    }

    ret_val = (bool)EVP_MAC_update(mctx, data, data_size);
    if (!ret_val) {
        goto done;
    }

    ret_val = (bool)EVP_MAC_final(mctx, NULL, &length, 0);
    if (!ret_val) {
        goto done;
    }

    ret_val = (bool)EVP_MAC_final(mctx, hmac_value, &length, length);
    if (!ret_val) {
        goto done;
    }

done:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return ret_val;
}

/**
 * Allocates and initializes one EVP_MAC_CTX context for subsequent HMAC-SHA256 use.
 *
 * @return  Pointer to the EVP_MAC_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hmac_sha256_new() returns NULL.
 *
 **/
void *libspdm_hmac_sha256_new(void)
{
    return hmac_md_new();
}

/**
 * Release the specified EVP_MAC_CTX context.
 *
 * @param[in]  hmac_sha256_ctx  Pointer to the EVP_MAC_CTX context to be released.
 *
 **/
void libspdm_hmac_sha256_free(void *hmac_sha256_ctx)
{
    hmac_md_free(hmac_sha256_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to libspdm_hmac_sha256_update().
 *
 * If hmac_sha256_ctx is NULL, then return false.
 *
 * @param[out]  hmac_sha256_ctx  Pointer to HMAC-SHA256 context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
bool libspdm_hmac_sha256_set_key(void *hmac_sha256_ctx, const uint8_t *key,
                                 uintn key_size)
{
    return hmac_md_set_key("SHA-256", hmac_sha256_ctx, key, key_size);
}

/**
 * Makes a copy of an existing HMAC-SHA256 context.
 *
 * If hmac_sha256_ctx is NULL, then return false.
 * If new_hmac_sha256_ctx is NULL, then return false.
 *
 * @param[in]  hmac_sha256_ctx     Pointer to HMAC-SHA256 context being copied.
 * @param[out] new_hmac_sha256_ctx  Pointer to new HMAC-SHA256 context.
 *
 * @retval true   HMAC-SHA256 context copy succeeded.
 * @retval false  HMAC-SHA256 context copy failed.
 *
 **/
bool libspdm_hmac_sha256_duplicate(const void *hmac_sha256_ctx,
                                   void *new_hmac_sha256_ctx)
{
    return hmac_md_duplicate(hmac_sha256_ctx, new_hmac_sha256_ctx);
}

/**
 * Digests the input data and updates HMAC-SHA256 context.
 *
 * This function performs HMAC-SHA256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC-SHA256 context should be initialized by libspdm_hmac_sha256_new(), and should not be finalized
 * by libspdm_hmac_sha256_final(). Behavior with invalid context is undefined.
 *
 * If hmac_sha256_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_sha256_ctx Pointer to the HMAC-SHA256 context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC-SHA256 data digest succeeded.
 * @retval false  HMAC-SHA256 data digest failed.
 *
 **/
bool libspdm_hmac_sha256_update(void *hmac_sha256_ctx, const void *data,
                                uintn data_size)
{
    return hmac_md_update(hmac_sha256_ctx, data, data_size);
}

/**
 * Completes computation of the HMAC-SHA256 digest value.
 *
 * This function completes HMAC-SHA256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC-SHA256 context cannot
 * be used again.
 * HMAC-SHA256 context should be initialized by libspdm_hmac_sha256_new(), and should not be finalized
 * by libspdm_hmac_sha256_final(). Behavior with invalid HMAC-SHA256 context is undefined.
 *
 * If hmac_sha256_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_sha256_ctx  Pointer to the HMAC-SHA256 context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA256 digest
 *                                    value (32 bytes).
 *
 * @retval true   HMAC-SHA256 digest computation succeeded.
 * @retval false  HMAC-SHA256 digest computation failed.
 *
 **/
bool libspdm_hmac_sha256_final(void *hmac_sha256_ctx, uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha256_ctx, hmac_value);
}

/**
 * Computes the HMAC-SHA256 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA256 digest
 *                         value (32 bytes).
 *
 * @retval true   HMAC-SHA256 digest computation succeeded.
 * @retval false  HMAC-SHA256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha256_all(const void *data, uintn data_size,
                             const uint8_t *key, uintn key_size,
                             uint8_t *hmac_value)
{
    return hmac_md_all("SHA-256", data, data_size, key, key_size,
                       hmac_value);
}

/**
 * Allocates and initializes one EVP_MAC_CTX context for subsequent HMAC-SHA384 use.
 *
 * @return  Pointer to the EVP_MAC_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hmac_sha384_new() returns NULL.
 *
 **/
void *libspdm_hmac_sha384_new(void)
{
    return hmac_md_new();
}

/**
 * Release the specified EVP_MAC_CTX context.
 *
 * @param[in]  hmac_sha384_ctx  Pointer to the EVP_MAC_CTX context to be released.
 *
 **/
void libspdm_hmac_sha384_free(void *hmac_sha384_ctx)
{
    hmac_md_free(hmac_sha384_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to libspdm_hmac_sha384_update().
 *
 * If hmac_sha384_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[out]  hmac_sha384_ctx  Pointer to HMAC-SHA384 context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_set_key(void *hmac_sha384_ctx, const uint8_t *key,
                                 uintn key_size)
{
    return hmac_md_set_key("SHA-384", hmac_sha384_ctx, key, key_size);
}

/**
 * Makes a copy of an existing HMAC-SHA384 context.
 *
 * If hmac_sha384_ctx is NULL, then return false.
 * If new_hmac_sha384_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  hmac_sha384_ctx     Pointer to HMAC-SHA384 context being copied.
 * @param[out] new_hmac_sha384_ctx  Pointer to new HMAC-SHA384 context.
 *
 * @retval true   HMAC-SHA384 context copy succeeded.
 * @retval false  HMAC-SHA384 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_duplicate(const void *hmac_sha384_ctx,
                                   void *new_hmac_sha384_ctx)
{
    return hmac_md_duplicate(hmac_sha384_ctx, new_hmac_sha384_ctx);
}

/**
 * Digests the input data and updates HMAC-SHA384 context.
 *
 * This function performs HMAC-SHA384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC-SHA384 context should be initialized by libspdm_hmac_sha384_new(), and should not be finalized
 * by libspdm_hmac_sha384_final(). Behavior with invalid context is undefined.
 *
 * If hmac_sha384_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  hmac_sha384_ctx Pointer to the HMAC-SHA384 context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC-SHA384 data digest succeeded.
 * @retval false  HMAC-SHA384 data digest failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_update(void *hmac_sha384_ctx, const void *data,
                                uintn data_size)
{
    return hmac_md_update(hmac_sha384_ctx, data, data_size);
}

/**
 * Completes computation of the HMAC-SHA384 digest value.
 *
 * This function completes HMAC-SHA384 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC-SHA384 context cannot
 * be used again.
 * HMAC-SHA384 context should be initialized by libspdm_hmac_sha384_new(), and should not be finalized
 * by libspdm_hmac_sha384_final(). Behavior with invalid HMAC-SHA384 context is undefined.
 *
 * If hmac_sha384_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  hmac_sha384_ctx  Pointer to the HMAC-SHA384 context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA384 digest
 *                                    value (48 bytes).
 *
 * @retval true   HMAC-SHA384 digest computation succeeded.
 * @retval false  HMAC-SHA384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_final(void *hmac_sha384_ctx, uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha384_ctx, hmac_value);
}

/**
 * Computes the HMAC-SHA384 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA384 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA384 digest
 *                         value (48 bytes).
 *
 * @retval true   HMAC-SHA384 digest computation succeeded.
 * @retval false  HMAC-SHA384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_all(const void *data, uintn data_size,
                             const uint8_t *key, uintn key_size,
                             uint8_t *hmac_value)
{
    return hmac_md_all("SHA-384", data, data_size, key, key_size,
                       hmac_value);
}

/**
 * Allocates and initializes one EVP_MAC_CTX context for subsequent HMAC-SHA512 use.
 *
 * @return  Pointer to the EVP_MAC_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hmac_sha512_new() returns NULL.
 *
 **/
void *libspdm_hmac_sha512_new(void)
{
    return hmac_md_new();
}

/**
 * Release the specified EVP_MAC_CTX context.
 *
 * @param[in]  hmac_sha512_ctx  Pointer to the EVP_MAC_CTX context to be released.
 *
 **/
void libspdm_hmac_sha512_free(void *hmac_sha512_ctx)
{
    hmac_md_free(hmac_sha512_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to libspdm_hmac_sha512_update().
 *
 * If hmac_sha512_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[out]  hmac_sha512_ctx  Pointer to HMAC-SHA512 context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_set_key(void *hmac_sha512_ctx, const uint8_t *key,
                                 uintn key_size)
{
    return hmac_md_set_key("SHA-512", hmac_sha512_ctx, key, key_size);
}

/**
 * Makes a copy of an existing HMAC-SHA512 context.
 *
 * If hmac_sha512_ctx is NULL, then return false.
 * If new_hmac_sha512_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  hmac_sha512_ctx     Pointer to HMAC-SHA512 context being copied.
 * @param[out] new_hmac_sha512_ctx  Pointer to new HMAC-SHA512 context.
 *
 * @retval true   HMAC-SHA512 context copy succeeded.
 * @retval false  HMAC-SHA512 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_duplicate(const void *hmac_sha512_ctx,
                                   void *new_hmac_sha512_ctx)
{
    return hmac_md_duplicate(hmac_sha512_ctx, new_hmac_sha512_ctx);
}

/**
 * Digests the input data and updates HMAC-SHA512 context.
 *
 * This function performs HMAC-SHA512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC-SHA512 context should be initialized by libspdm_hmac_sha512_new(), and should not be finalized
 * by libspdm_hmac_sha512_final(). Behavior with invalid context is undefined.
 *
 * If hmac_sha512_ctx is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  hmac_sha512_ctx Pointer to the HMAC-SHA512 context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC-SHA512 data digest succeeded.
 * @retval false  HMAC-SHA512 data digest failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_update(void *hmac_sha512_ctx, const void *data,
                                uintn data_size)
{
    return hmac_md_update(hmac_sha512_ctx, data, data_size);
}

/**
 * Completes computation of the HMAC-SHA512 digest value.
 *
 * This function completes HMAC-SHA512 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC-SHA512 context cannot
 * be used again.
 * HMAC-SHA512 context should be initialized by libspdm_hmac_sha512_new(), and should not be finalized
 * by libspdm_hmac_sha512_final(). Behavior with invalid HMAC-SHA512 context is undefined.
 *
 * If hmac_sha512_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  hmac_sha512_ctx  Pointer to the HMAC-SHA512 context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA512 digest
 *                                    value (64 bytes).
 *
 * @retval true   HMAC-SHA512 digest computation succeeded.
 * @retval false  HMAC-SHA512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_final(void *hmac_sha512_ctx, uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sha512_ctx, hmac_value);
}

/**
 * Computes the HMAC-SHA512 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA512 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA512 digest
 *                         value (64 bytes).
 *
 * @retval true   HMAC-SHA512 digest computation succeeded.
 * @retval false  HMAC-SHA512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_all(const void *data, uintn data_size,
                             const uint8_t *key, uintn key_size,
                             uint8_t *hmac_value)
{
    return hmac_md_all("SHA-512", data, data_size, key, key_size,
                       hmac_value);
}
