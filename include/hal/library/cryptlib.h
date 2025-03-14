/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Defines base cryptographic library APIs.
 * The Base Cryptographic Library provides implementations of basic cryptography
 * primitives (hash Serials, HMAC, AES, RSA, Diffie-Hellman, Elliptic Curve, etc) for security
 * functionality enabling.
 **/

#ifndef CRYPTLIB_H
#define CRYPTLIB_H

#define LIBSPDM_CRYPTO_NID_NULL 0x0000

/* Hash */
#define LIBSPDM_CRYPTO_NID_SHA256 0x0001
#define LIBSPDM_CRYPTO_NID_SHA384 0x0002
#define LIBSPDM_CRYPTO_NID_SHA512 0x0003
#define LIBSPDM_CRYPTO_NID_SHA3_256 0x0004
#define LIBSPDM_CRYPTO_NID_SHA3_384 0x0005
#define LIBSPDM_CRYPTO_NID_SHA3_512 0x0006
#define LIBSPDM_CRYPTO_NID_SM3_256 0x0007

/* Signing */
#define LIBSPDM_CRYPTO_NID_RSASSA2048 0x0101
#define LIBSPDM_CRYPTO_NID_RSASSA3072 0x0102
#define LIBSPDM_CRYPTO_NID_RSASSA4096 0x0103
#define LIBSPDM_CRYPTO_NID_RSAPSS2048 0x0104
#define LIBSPDM_CRYPTO_NID_RSAPSS3072 0x0105
#define LIBSPDM_CRYPTO_NID_RSAPSS4096 0x0106
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256 0x0107
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384 0x0108
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521 0x0109
#define LIBSPDM_CRYPTO_NID_SM2_DSA_P256 0x010A
#define LIBSPDM_CRYPTO_NID_EDDSA_ED25519 0x010B
#define LIBSPDM_CRYPTO_NID_EDDSA_ED448 0x010C

/* Key Exchange */
#define LIBSPDM_CRYPTO_NID_FFDHE2048 0x0201
#define LIBSPDM_CRYPTO_NID_FFDHE3072 0x0202
#define LIBSPDM_CRYPTO_NID_FFDHE4096 0x0203
#define LIBSPDM_CRYPTO_NID_SECP256R1 0x0204
#define LIBSPDM_CRYPTO_NID_SECP384R1 0x0205
#define LIBSPDM_CRYPTO_NID_SECP521R1 0x0206
#define LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256 0x0207
#define LIBSPDM_CRYPTO_NID_CURVE_X25519 0x0208
#define LIBSPDM_CRYPTO_NID_CURVE_X448 0x0209

/* AEAD */
#define LIBSPDM_CRYPTO_NID_AES_128_GCM 0x0301
#define LIBSPDM_CRYPTO_NID_AES_256_GCM 0x0302
#define LIBSPDM_CRYPTO_NID_CHACHA20_POLY1305 0x0303
#define LIBSPDM_CRYPTO_NID_SM4_128_GCM 0x0304

/* X.509 v3 key usage extension flags. */
#define LIBSPDM_CRYPTO_X509_KU_DIGITAL_SIGNATURE 0x80 /* bit 0 */
#define LIBSPDM_CRYPTO_X509_KU_NON_REPUDIATION 0x40 /* bit 1 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_ENCIPHERMENT 0x20 /* bit 2 */
#define LIBSPDM_CRYPTO_X509_KU_DATA_ENCIPHERMENT 0x10 /* bit 3 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_AGREEMENT 0x08 /* bit 4 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_CERT_SIGN 0x04 /* bit 5 */
#define LIBSPDM_CRYPTO_X509_KU_CRL_SIGN 0x02 /* bit 6 */
#define LIBSPDM_CRYPTO_X509_KU_ENCIPHER_ONLY 0x01 /* bit 7 */
#define LIBSPDM_CRYPTO_X509_KU_DECIPHER_ONLY 0x8000 /* bit 8 */

/* These constants comply with the DER encoded ASN.1 type tags. */
#define LIBSPDM_CRYPTO_ASN1_BOOLEAN 0x01
#define LIBSPDM_CRYPTO_ASN1_INTEGER 0x02
#define LIBSPDM_CRYPTO_ASN1_BIT_STRING 0x03
#define LIBSPDM_CRYPTO_ASN1_OCTET_STRING 0x04
#define LIBSPDM_CRYPTO_ASN1_NULL 0x05
#define LIBSPDM_CRYPTO_ASN1_OID 0x06
#define LIBSPDM_CRYPTO_ASN1_UTF8_STRING 0x0C
#define LIBSPDM_CRYPTO_ASN1_SEQUENCE 0x10
#define LIBSPDM_CRYPTO_ASN1_SET 0x11
#define LIBSPDM_CRYPTO_ASN1_PRINTABLE_STRING 0x13
#define LIBSPDM_CRYPTO_ASN1_T61_STRING 0x14
#define LIBSPDM_CRYPTO_ASN1_IA5_STRING 0x16
#define LIBSPDM_CRYPTO_ASN1_UTC_TIME 0x17
#define LIBSPDM_CRYPTO_ASN1_GENERALIZED_TIME 0x18
#define LIBSPDM_CRYPTO_ASN1_UNIVERSAL_STRING 0x1C
#define LIBSPDM_CRYPTO_ASN1_BMP_STRING 0x1E
#define LIBSPDM_CRYPTO_ASN1_PRIMITIVE 0x00
#define LIBSPDM_CRYPTO_ASN1_CONSTRUCTED 0x20
#define LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC 0x80

#define LIBSPDM_CRYPTO_ASN1_TAG_CLASS_MASK 0xC0
#define LIBSPDM_CRYPTO_ASN1_TAG_PC_MASK 0x20
#define LIBSPDM_CRYPTO_ASN1_TAG_VALUE_MASK 0x1F

/* RSA key Tags Definition used in libspdm_rsa_set_key() function for key component identification.*/
typedef enum {
    LIBSPDM_RSA_KEY_N, /*< RSA public Modulus (N)*/
    LIBSPDM_RSA_KEY_E, /*< RSA public exponent (e)*/
    LIBSPDM_RSA_KEY_D, /*< RSA Private exponent (d)*/
    LIBSPDM_RSA_KEY_P, /*< RSA secret prime factor of Modulus (p)*/
    LIBSPDM_RSA_KEY_Q, /*< RSA secret prime factor of Modules (q)*/
    LIBSPDM_RSA_KEY_DP, /*< p's CRT exponent (== d mod (p - 1))*/
    LIBSPDM_RSA_KEY_DQ, /*< q's CRT exponent (== d mod (q - 1))*/
    LIBSPDM_RSA_KEY_Q_INV /*< The CRT coefficient (== 1/q mod p)*/
} libspdm_rsa_key_tag_t;

#include "hal/library/cryptlib_hash.h"
#include "hal/library/cryptlib_mac.h"
#include "hal/library/cryptlib_aead.h"

/*=====================================================================================
 *    Asymmetric Cryptography Primitive
 *=====================================================================================*/

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 *
 **/
void *libspdm_rsa_new(void);

/**
 * Release the specified RSA context.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void libspdm_rsa_free(void *rsa_context);

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
                         const uint8_t *big_number, size_t bn_size);

/**
 * Gets the tag-designated RSA key component from the established RSA context.
 *
 * This function retrieves the tag-designated RSA key component from the
 * established RSA context as a non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If specified key component has not been set or has been cleared, then returned
 * bn_size is set to 0.
 * If the big_number buffer is too small to hold the contents of the key, false
 * is returned and bn_size is set to the required buffer size to obtain the key.
 *
 * If rsa_context is NULL, then return false.
 * If bn_size is NULL, then return false.
 * If bn_size is large enough but big_number is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[out]      big_number   Pointer to octet integer buffer.
 * @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
 *                             On output, the size of data returned in big number buffer in bytes.
 *
 * @retval  true   RSA key component was retrieved successfully.
 * @retval  false  Invalid RSA key component tag.
 * @retval  false  bn_size is too small.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_get_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         uint8_t *big_number, size_t *bn_size);

/**
 * Generates RSA key components.
 *
 * This function generates RSA key components. It takes RSA public exponent E and
 * length in bits of RSA modulus N as input, and generates all key components.
 * If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.
 *
 * Before this function can be invoked, pseudorandom number generator must be correctly
 * initialized by libspdm_random_seed().
 *
 * If rsa_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  rsa_context           Pointer to RSA context being set.
 * @param[in]       modulus_length        length of RSA modulus N in bits.
 * @param[in]       public_exponent       Pointer to RSA public exponent.
 * @param[in]       public_exponent_size   size of RSA public exponent buffer in bytes.
 *
 * @retval  true   RSA key component was generated successfully.
 * @retval  false  Invalid RSA key component tag.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_generate_key(void *rsa_context, size_t modulus_length,
                              const uint8_t *public_exponent,
                              size_t public_exponent_size);

/**
 * Validates key components of RSA context.
 * NOTE: This function performs integrity checks on all the RSA key material, so
 *      the RSA key structure must contain all the private key data.
 *
 * This function validates key components of RSA context in following aspects:
 * - Whether p is a prime
 * - Whether q is a prime
 * - Whether n = p * q
 * - Whether d*e = 1  mod lcm(p-1,q-1)
 *
 * If rsa_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  rsa_context  Pointer to RSA context to check.
 *
 * @retval  true   RSA key components are valid.
 * @retval  false  RSA key components are not valid.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_check_key(void *rsa_context);

/**
 * Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      rsa_context   Pointer to RSA context for signature generation.
 * @param[in]      hash_nid      hash NID
 * @param[in]      message_hash  Pointer to octet message hash to be signed.
 * @param[in]      hash_size     size of the message hash in bytes.
 * @param[out]     signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                             On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in PKCS1-v1_5.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_pkcs1_sign_with_nid(void *rsa_context, size_t hash_nid,
                                     const uint8_t *message_hash,
                                     size_t hash_size, uint8_t *signature,
                                     size_t *sig_size);

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
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, size_t hash_nid,
                                       const uint8_t *message_hash,
                                       size_t hash_size, const uint8_t *signature,
                                       size_t sig_size);

/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_rsa_pss_sign(void *rsa_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          uint8_t *signature, size_t *sig_size);

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
bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size);

/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
 *                         RSA private key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **rsa_context);

/**
 * Retrieve the RSA public key from one DER-encoded X509 certificate.
 *
 * If cert is NULL, then return false.
 * If rsa_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
 *                         RSA public key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * @retval  true   RSA public key was retrieved successfully.
 * @retval  false  Fail to retrieve RSA public key from X509 certificate.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **rsa_context);

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
 *                         EC private key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ec_get_private_key_from_pem(const uint8_t *pem_data, size_t pem_size,
                                         const char *password,
                                         void **ec_context);

/**
 * Retrieve the EC public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC public key was retrieved successfully.
 * @retval  false  Fail to retrieve EC public key from X509 certificate.
 *
 **/
bool libspdm_ec_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                         void **ec_context);

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
 *                         Ed private key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ecd_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **ecd_context);

/**
 * Retrieve the Ed public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
 *                         Ed public key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed public key was retrieved successfully.
 * @retval  false  Fail to retrieve Ed public key from X509 certificate.
 *
 **/
bool libspdm_ecd_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **ecd_context);

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
 *                         sm2 private key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_sm2_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **sm2_context);

/**
 * Retrieve the sm2 public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
 *                         sm2 public key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 public key was retrieved successfully.
 * @retval  false  Fail to retrieve sm2 public key from X509 certificate.
 *
 **/
bool libspdm_sm2_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **sm2_context);

/**
 * Retrieve the tag and length of the tag.
 *
 * @param ptr      The position in the ASN.1 data
 * @param end      end of data
 * @param length   The variable that will receive the length
 * @param tag      The expected tag
 *
 * @retval      true   Get tag successful
 * @retval      FALSe  Failed to get tag or tag not match
 **/
bool libspdm_asn1_get_tag(uint8_t **ptr, const uint8_t *end, size_t *length,
                          uint32_t tag);

/**
 * Retrieve the subject bytes from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If subject_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
 *                             and the size of buffer returned cert_subject on output.
 *
 * @retval  true   The certificate subject retrieved successfully.
 * @retval  false  Invalid certificate, or the subject_size is too small for the result.
 *                The subject_size will be updated with the required size.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_x509_get_subject_name(const uint8_t *cert, size_t cert_size,
                                   uint8_t *cert_subject,
                                   size_t *subject_size);

/**
 * Retrieve the common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string (UTF8). At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_common_name(const uint8_t *cert, size_t cert_size,
                                  char *common_name,
                                  size_t *common_name_size);

/**
 * Retrieve the organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_organization_name(const uint8_t *cert, size_t cert_size,
                                   char *name_buffer,
                                   size_t *name_buffer_size);

/**
 * Retrieve the version from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     version      Pointer to the retrieved version integer.
 *
 * @retval RETURN_SUCCESS           The certificate version retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If  cert is NULL or cert_size is Zero.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_version(const uint8_t *cert, size_t cert_size,
                              size_t *version);

/**
 * Retrieve the serialNumber from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     serial_number  Pointer to the retrieved certificate serial_number bytes.
 * @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
 *                             and the size of buffer returned serial_number on output.
 *
 * @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL or cert_size is Zero.
 *                                 If serial_number_size is NULL.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no serial_number exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the serial_number is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 serial_number_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_serial_number(const uint8_t *cert, size_t cert_size,
                                    uint8_t *serial_number,
                                    size_t *serial_number_size);

/**
 * Retrieve the issuer bytes from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If issuer_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_issuer  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] issuer_size  The size in bytes of the cert_issuer buffer on input,
 *                             and the size of buffer returned cert_issuer on output.
 *
 * @retval  true   The certificate issuer retrieved successfully.
 * @retval  false  Invalid certificate, or the issuer_size is too small for the result.
 *                The issuer_size will be updated with the required size.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_x509_get_issuer_name(const uint8_t *cert, size_t cert_size,
                                  uint8_t *cert_issuer,
                                  size_t *issuer_size);

/**
 * Retrieve the issuer common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate issuer common
 *                                 name string. At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Issuer common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_common_name(const uint8_t *cert, size_t cert_size,
                                    char *common_name,
                                    size_t *common_name_size);

/**
 * Retrieve the issuer organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate issuer organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate issuer Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_orgnization_name(const uint8_t *cert, size_t cert_size,
                                         char *name_buffer,
                                         size_t *name_buffer_size);

/**
 * Retrieve the signature algorithm from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     oid              signature algorithm Object identifier buffer
 * @param[in,out]  oid_size          signature algorithm Object identifier buffer size
 *
 * @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If oid_size is NULL.
 *                                 If oid is not NULL and *oid_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no SignatureType.
 * @retval RETURN_BUFFER_TOO_SMALL  If the oid is NULL. The required buffer size
 *                                 is returned in the oid_size.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_signature_algorithm(const uint8_t *cert,
                                          size_t cert_size, uint8_t *oid,
                                          size_t *oid_size);

/**
 * Retrieve Extension data from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[in]      oid              Object identifier buffer
 * @param[in]      oid_size          Object identifier buffer size
 * @param[out]     extension_data    Extension bytes.
 * @param[in, out] extension_data_size Extension bytes size.
 *
 * @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If extension_data_size is NULL.
 *                                 If extension_data is not NULL and *extension_data_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Extension entry match oid.
 * @retval RETURN_BUFFER_TOO_SMALL  If the extension_data is NULL. The required buffer size
 *                                 is returned in the extension_data_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_extension_data(const uint8_t *cert, size_t cert_size,
                                     const uint8_t *oid, size_t oid_size,
                                     uint8_t *extension_data,
                                     size_t *extension_data_size);

/**
 * Retrieve the Validity from one X.509 certificate
 *
 * If cert is NULL, then return false.
 * If CertIssuerSize is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     from         notBefore Pointer to date_time object.
 * @param[in,out]  from_size     notBefore date_time object size.
 * @param[out]     to           notAfter Pointer to date_time object.
 * @param[in,out]  to_size       notAfter date_time object size.
 *
 * Note: libspdm_x509_compare_date_time to compare date_time oject
 *      x509SetDateTime to get a date_time object from a date_time_str
 *
 * @retval  true   The certificate Validity retrieved successfully.
 * @retval  false  Invalid certificate, or Validity retrieve failed.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_x509_get_validity(const uint8_t *cert, size_t cert_size,
                               uint8_t *from, size_t *from_size, uint8_t *to,
                               size_t *to_size);

/**
 * format a date_time object into DataTime buffer
 *
 * If date_time_str is NULL, then return false.
 * If date_time_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
 *                                 Ref: https://www.w3.org/TR/NOTE-datetime
 *                                 Z stand for UTC time
 * @param[out]     date_time         Pointer to a date_time object.
 * @param[in,out]  date_time_size     date_time object buffer size.
 *
 * @retval RETURN_SUCCESS           The date_time object create successfully.
 * @retval RETURN_INVALID_PARAMETER If date_time_str is NULL.
 *                                 If date_time_size is NULL.
 *                                 If date_time is not NULL and *date_time_size is 0.
 *                                 If year month day hour minute second combination is invalid datetime.
 * @retval RETURN_BUFFER_TOO_SMALL  If the date_time is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 date_time_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_set_date_time(char *date_time_str, void *date_time,
                                size_t *date_time_size);

/**
 * Compare date_time1 object and date_time2 object.
 *
 * If date_time1 is NULL, then return -2.
 * If date_time2 is NULL, then return -2.
 * If date_time1 == date_time2, then return 0
 * If date_time1 > date_time2, then return 1
 * If date_time1 < date_time2, then return -1
 *
 * @param[in]      date_time1         Pointer to a date_time Ojbect
 * @param[in]      date_time2         Pointer to a date_time Object
 *
 * @retval  0      If date_time1 == date_time2
 * @retval  1      If date_time1 > date_time2
 * @retval  -1     If date_time1 < date_time2
 **/
int32_t libspdm_x509_compare_date_time(const void *date_time1, const void *date_time2);

/**
 * Retrieve the key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage (LIBSPDM_CRYPTO_X509_KU_*)
 *
 * @retval  true   The certificate key usage retrieved successfully.
 * @retval  false  Invalid certificate, or usage is NULL
 * @retval  false  This interface is not supported.
 **/
bool libspdm_x509_get_key_usage(const uint8_t *cert, size_t cert_size,
                                size_t *usage);

/**
 * Retrieve the Extended key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage bytes.
 * @param[in, out] usage_size        key usage buffer sizs in bytes.
 *
 * @retval RETURN_SUCCESS           The usage bytes retrieve successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If cert_size is NULL.
 *                                 If usage is not NULL and *usage_size is 0.
 *                                 If cert is invalid.
 * @retval RETURN_BUFFER_TOO_SMALL  If the usage is NULL. The required buffer size
 *                                 is returned in the usage_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_extended_key_usage(const uint8_t *cert,
                                         size_t cert_size, uint8_t *usage,
                                         size_t *usage_size);

/**
 * Retrieve the basic constraints from one X.509 certificate.
 *
 * @param[in]      cert                     Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size                size of the X509 certificate in bytes.
 * @param[out]     basic_constraints        basic constraints bytes.
 * @param[in, out] basic_constraints_size   basic constraints buffer sizs in bytes.
 *
 * @retval RETURN_SUCCESS           The basic constraints retrieve successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                  If cert_size is NULL.
 *                                  If basic_constraints is not NULL and *basic_constraints_size is 0.
 *                                  If cert is invalid.
 * @retval RETURN_BUFFER_TOO_SMALL  The required buffer size is small.
 *                                  The return buffer size is basic_constraints_size parameter.
 * @retval RETURN_NOT_FOUND         If no Extension entry match oid.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_extended_basic_constraints(const uint8_t *cert,
                                                 size_t cert_size,
                                                 uint8_t *basic_constraints,
                                                 size_t *basic_constraints_size);

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * If cert is NULL, then return false.
 * If ca_cert is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate to be verified.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
 * @param[in]      ca_cert_size   size of the CA Certificate in bytes.
 *
 * @retval  true   The certificate was issued by the trusted CA.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_x509_verify_cert(const uint8_t *cert, size_t cert_size,
                              const uint8_t *ca_cert, size_t ca_cert_size);

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Cerificate itself. and
 *                                  subsequent cerificate is signed by the preceding
 *                                  cerificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      root_cert          Trusted Root Certificate buffer
 *
 * @param[in]      root_cert_length    Trusted Root Certificate buffer length
 *
 * @retval  true   All cerificates was issued by the first certificate in X509Certchain.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 **/
bool libspdm_x509_verify_cert_chain(const uint8_t *root_cert, size_t root_cert_length,
                                    const uint8_t *cert_chain,
                                    size_t cert_chain_length);

/**
 * Get one X509 certificate from cert_chain.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Cerificate itself. and
 *                                  subsequent cerificate is signed by the preceding
 *                                  cerificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      cert_index         index of certificate. If index is -1 indecate the
 *                                  last certificate in cert_chain.
 *
 * @param[out]     cert              The certificate at the index of cert_chain.
 * @param[out]     cert_length        The length certificate at the index of cert_chain.
 *
 * @retval  true   Success.
 * @retval  false  Failed to get certificate from certificate chain.
 **/
bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                           size_t cert_chain_length,
                                           const int32_t cert_index, const uint8_t **cert,
                                           size_t *cert_length);

/**
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If cert is NULL, then return false.
 * If single_x509_cert is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 * @param[out] single_x509_cert  The generated X509 object.
 *
 * @retval     true            The X509 object generation succeeded.
 * @retval     false           The operation failed.
 * @retval     false           This interface is not supported.
 *
 **/
bool libspdm_x509_construct_certificate(const uint8_t *cert, size_t cert_size,
                                        uint8_t **single_x509_cert);

/**
 * Construct a X509 stack object from a list of DER-encoded certificate data.
 *
 * If x509_stack is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
 *                            On output, pointer to the X509 stack object with new
 *                            inserted X509 certificate.
 * @param           ...        A list of DER-encoded single certificate data followed
 *                            by certificate size. A NULL terminates the list. The
 *                            pairs are the arguments to libspdm_x509_construct_certificate().
 *
 * @retval     true            The X509 stack construction succeeded.
 * @retval     false           The construction operation failed.
 * @retval     false           This interface is not supported.
 *
 **/
bool libspdm_x509_construct_certificate_stack(uint8_t **x509_stack, ...);

/**
 * Release the specified X509 object.
 *
 * If the interface is not supported, then ASSERT().
 *
 * @param[in]  x509_cert  Pointer to the X509 object to be released.
 *
 **/
void libspdm_x509_free(void *x509_cert);

/**
 * Release the specified X509 stack object.
 *
 * If the interface is not supported, then ASSERT().
 *
 * @param[in]  x509_stack  Pointer to the X509 stack object to be released.
 *
 **/
void libspdm_x509_stack_free(void *x509_stack);

/**
 * Retrieve the TBSCertificate from one given X.509 certificate.
 *
 * @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
 * @param[out]     tbs_cert_size  size of the TBS certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If tbs_cert is NULL, then return false.
 * If tbs_cert_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @retval  true   The TBSCertificate was retrieved successfully.
 * @retval  false  Invalid X.509 certificate.
 *
 **/
bool libspdm_x509_get_tbs_cert(const uint8_t *cert, size_t cert_size,
                               uint8_t **tbs_cert, size_t *tbs_cert_size);

/*=====================================================================================
 *    DH key Exchange Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Diffie-Hellman context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 *         If the allocations fails, libspdm_dh_new_by_nid() returns NULL.
 *         If the interface is not supported, libspdm_dh_new_by_nid() returns NULL.
 *
 **/
void *libspdm_dh_new_by_nid(size_t nid);

/**
 * Release the specified DH context.
 *
 * If the interface is not supported, then ASSERT().
 *
 * @param[in]  dh_context  Pointer to the DH context to be released.
 *
 **/
void libspdm_dh_free(void *dh_context);

/**
 * Generates DH parameter.
 *
 * Given generator g, and length of prime number p in bits, this function generates p,
 * and sets DH context according to value of g and p.
 *
 * Before this function can be invoked, pseudorandom number generator must be correctly
 * initialized by libspdm_random_seed().
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[out]      prime        Pointer to the buffer to receive the generated prime number.
 *
 * @retval true   DH parameter generation succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  PRNG fails to generate random prime number with prime_length.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_dh_generate_parameter(void *dh_context, size_t generator,
                                   size_t prime_length, uint8_t *prime);

/**
 * Sets generator and prime parameters for DH.
 *
 * Given generator g, and prime number p, this function and sets DH
 * context accordingly.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[in]       prime        Pointer to the prime number.
 *
 * @retval true   DH parameter setting succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  value of generator is not suitable for the prime.
 * @retval false  value of prime is not a prime number.
 * @retval false  value of prime is not a safe prime number.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_dh_set_parameter(void *dh_context, size_t generator,
                              size_t prime_length, const uint8_t *prime);

/**
 * Generates DH public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * If dh_context is NULL, then return false.
 * If public_key_size is NULL, then return false.
 * If public_key_size is large enough but public_key is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * For FFDHE2048, the public_size is 256.
 * For FFDHE3072, the public_size is 384.
 * For FFDHE4096, the public_size is 512.
 *
 * @param[in, out]  dh_context      Pointer to the DH context.
 * @param[out]      public_key      Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
 *                               On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DH public key generation succeeded.
 * @retval false  DH public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_dh_generate_key(void *dh_context, uint8_t *public_key,
                             size_t *public_key_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * If dh_context is NULL, then return false.
 * If peer_public_key is NULL, then return false.
 * If key_size is NULL, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 * If this interface is not supported, then return false.
 *
 * For FFDHE2048, the peer_public_size and key_size is 256.
 * For FFDHE3072, the peer_public_size and key_size is 384.
 * For FFDHE4096, the peer_public_size and key_size is 512.
 *
 * @param[in, out]  dh_context          Pointer to the DH context.
 * @param[in]       peer_public_key      Pointer to the peer's public key.
 * @param[in]       peer_public_key_size  size of peer's public key in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                   On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DH exchanged key generation succeeded.
 * @retval false  DH exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_dh_compute_key(void *dh_context, const uint8_t *peer_public_key,
                            size_t peer_public_key_size, uint8_t *key,
                            size_t *key_size);

/*=====================================================================================
 *    Elliptic Curve Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Elliptic Curve context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Elliptic Curve context that has been initialized.
 *         If the allocations fails, libspdm_ec_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ec_new_by_nid(size_t nid);

/**
 * Release the specified EC context.
 *
 * @param[in]  ec_context  Pointer to the EC context to be released.
 *
 **/
void libspdm_ec_free(void *ec_context);

/**
 * Sets the public key component into the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   EC public key component was set successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ec_set_pub_key(void *ec_context, const uint8_t *public_key,
                            size_t public_key_size);

/**
 * Gets the public key component from the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   EC key component was retrieved successfully.
 * @retval  false  Invalid EC key component.
 *
 **/
bool libspdm_ec_get_pub_key(void *ec_context, uint8_t *public_key,
                            size_t *public_key_size);

/**
 * Validates key components of EC context.
 * NOTE: This function performs integrity checks on all the EC key material, so
 *      the EC key structure must contain all the private key data.
 *
 * If ec_context is NULL, then return false.
 *
 * @param[in]  ec_context  Pointer to EC context to check.
 *
 * @retval  true   EC key components are valid.
 * @retval  false  EC key components are not valid.
 *
 **/
bool libspdm_ec_check_key(const void *ec_context);

/**
 * Generates EC key and returns EC public key (X, Y).
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * EC context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * If ec_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ec_context      Pointer to the EC context.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   EC public X,Y generation succeeded.
 * @retval false  EC public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ec_generate_key(void *ec_context, uint8_t *public_key,
                             size_t *public_key_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If ec_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * For P-256, the peer_public_size is 64. first 32-byte is X, second 32-byte is Y. The key_size is 32.
 * For P-384, the peer_public_size is 96. first 48-byte is X, second 48-byte is Y. The key_size is 48.
 * For P-521, the peer_public_size is 132. first 66-byte is X, second 66-byte is Y. The key_size is 66.
 *
 * @param[in, out]  ec_context          Pointer to the EC context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size     size of peer's public X,Y in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   EC exchanged key generation succeeded.
 * @retval false  EC exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_ec_compute_key(void *ec_context, const uint8_t *peer_public,
                            size_t peer_public_size, uint8_t *key,
                            size_t *key_size);

/**
 * Carries out the EC-DSA signature.
 *
 * This function carries out the EC-DSA signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If ec_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
 * For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.
 *
 * @param[in]       ec_context    Pointer to EC context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive EC-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in EC-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_ecdsa_sign(void *ec_context, size_t hash_nid,
                        const uint8_t *message_hash, size_t hash_size,
                        uint8_t *signature, size_t *sig_size);

/**
 * Verifies the EC-DSA signature.
 *
 * If ec_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
 * For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.
 *
 * @param[in]  ec_context    Pointer to EC context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to EC-DSA signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in EC-DSA.
 * @retval  false  Invalid signature or invalid EC context.
 *
 **/
bool libspdm_ecdsa_verify(void *ec_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          const uint8_t *signature, size_t sig_size);

/*=====================================================================================
 *    Edwards-Curve Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Edwards-Curve context for subsequent use
 * with the NID.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Edwards-Curve context that has been initialized.
 *         If the allocations fails, libspdm_ecd_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ecd_new_by_nid(size_t nid);

/**
 * Release the specified Ed context.
 *
 * @param[in]  ecd_context  Pointer to the Ed context to be released.
 *
 **/
void libspdm_ecd_free(void *ecd_context);

/**
 * Sets the public key component into the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   Ed public key component was set successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ecd_set_pub_key(void *ecd_context, const uint8_t *public_key,
                             size_t public_key_size);

/**
 * Gets the public key component from the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   Ed key component was retrieved successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ecd_get_pub_key(void *ecd_context, uint8_t *public_key,
                             size_t *public_key_size);

/**
 * Validates key components of Ed context.
 * NOTE: This function performs integrity checks on all the Ed key material, so
 *      the Ed key structure must contain all the private key data.
 *
 * If ecd_context is NULL, then return false.
 *
 * @param[in]  ecd_context  Pointer to Ed context to check.
 *
 * @retval  true   Ed key components are valid.
 * @retval  false  Ed key components are not valid.
 *
 **/
bool libspdm_ecd_check_key(const void *ecd_context);

/**
 * Generates Ed key and returns Ed public key.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * If ecd_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ecd_context      Pointer to the Ed context.
 * @param[out]      public         Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   Ed public key generation succeeded.
 * @retval false  Ed public key generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ecd_generate_key(void *ecd_context, uint8_t *public_key,
                              size_t *public_key_size);

/**
 * Carries out the Ed-DSA signature.
 *
 * This function carries out the Ed-DSA signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If ecd_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be NULL.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * For ed25519, context must be NULL and context_size must be 0.
 * For ed448, context must be maximum of 255 octets.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]       ecd_context    Pointer to Ed context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       context      the EDDSA signing context.
 * @param[in]       context_size size of EDDSA signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive Ed-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in Ed-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_eddsa_sign(const void *ecd_context, size_t hash_nid,
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t size, uint8_t *signature,
                        size_t *sig_size);

/**
 * Verifies the Ed-DSA signature.
 *
 * If ecd_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be NULL.
 *
 * For ed25519, context must be NULL and context_size must be 0.
 * For ed448, context must be maximum of 255 octets.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]  ecd_context    Pointer to Ed context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  context      the EDDSA signing context.
 * @param[in]  context_size size of EDDSA signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to Ed-DSA signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in Ed-DSA.
 * @retval  false  Invalid signature or invalid Ed context.
 *
 **/
bool libspdm_eddsa_verify(const void *ecd_context, size_t hash_nid,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t size,
                          const uint8_t *signature, size_t sig_size);

/*=====================================================================================
 *    Montgomery-Curve Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Montgomery-Curve Context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Montgomery-Curve Context that has been initialized.
 *         If the allocations fails, libspdm_ecx_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ecx_new_by_nid(size_t nid);

/**
 * Release the specified Ecx context.
 *
 * @param[in]  ecx_context  Pointer to the Ecx context to be released.
 *
 **/
void libspdm_ecx_free(const void *ecx_context);

/**
 * Generates Ecx key and returns Ecx public key.
 *
 * This function generates random secret, and computes the public key, which is
 * returned via parameter public, public_size.
 * Ecx context is updated accordingly.
 * If the public buffer is too small to hold the public key, false is returned and
 * public_size is set to the required buffer size to obtain the public key.
 *
 * For X25519, the public_size is 32.
 * For X448, the public_size is 56.
 *
 * If ecx_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ecx_context      Pointer to the Ecx context.
 * @param[out]      public         Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   Ecx public key generation succeeded.
 * @retval false  Ecx public key generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ecx_generate_key(void *ecx_context, uint8_t *public,
                              size_t *public_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 *
 * If ecx_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * For X25519, the public_size is 32.
 * For X448, the public_size is 56.
 *
 * @param[in, out]  ecx_context          Pointer to the Ecx context.
 * @param[in]       peer_public         Pointer to the peer's public key.
 * @param[in]       peer_public_size     Size of peer's public key in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   Ecx exchanged key generation succeeded.
 * @retval false  Ecx exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_ecx_compute_key(void *ecx_context, const uint8_t *peer_public,
                             size_t peer_public_size, uint8_t *key,
                             size_t *key_size);

/*=====================================================================================
 *    Shang-Mi2 Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_dsa_new_by_nid(size_t nid);

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_dsa_free(void *sm2_context);

/**
 * Sets the public key component into the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to sm2 context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   sm2 public key component was set successfully.
 * @retval  false  Invalid sm2 public key component.
 *
 **/
bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                 size_t public_key_size);

/**
 * Gets the public key component from the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  sm2_context     Pointer to sm2 context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   sm2 key component was retrieved successfully.
 * @retval  false  Invalid sm2 key component.
 *
 **/
bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                 size_t *public_key_size);

/**
 * Validates key components of sm2 context.
 * NOTE: This function performs integrity checks on all the sm2 key material, so
 *      the sm2 key structure must contain all the private key data.
 *
 * If sm2_context is NULL, then return false.
 *
 * @param[in]  sm2_context  Pointer to sm2 context to check.
 *
 * @retval  true   sm2 key components are valid.
 * @retval  false  sm2 key components are not valid.
 *
 **/
bool libspdm_sm2_dsa_check_key(const void *sm2_context);

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_dsa_generate_key(void *sm2_context, uint8_t *public,
                                  size_t *public_size);

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_key_exchange_new_by_nid(size_t nid);

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_key_exchange_free(void *sm2_context);

/**
 * Initialize the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 * @param[in]  hash_nid            hash NID, only SM3 is valid.
 * @param[in]  id_a                the ID-A of the key exchange context.
 * @param[in]  id_a_size           size of ID-A key exchange context.
 * @param[in]  id_b                the ID-B of the key exchange context.
 * @param[in]  id_b_size           size of ID-B key exchange context.
 * @param[in]  is_initiator        if the caller is initiator.
 *                                true: initiator
 *                                false: not an initiator
 *
 * @retval true   sm2 context is initialized.
 * @retval false  sm2 context is not initialized.
 **/
bool libspdm_sm2_key_exchange_init(const void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator);

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public,
                                           size_t *public_size);

/**
 * Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If sm2_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 *
 * The id_a_size and id_b_size must be smaller than 2^16-1.
 * The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
 * The key_size must be smaller than 2^32-1, limited by KDF function.
 *
 * @param[in, out]  sm2_context         Pointer to the sm2 context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size     size of peer's public X,Y in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in]       key_size            On input, the size of key buffer in bytes.
 *
 * @retval true   sm2 exchanged key generation succeeded.
 * @retval false  sm2 exchanged key generation failed.
 *
 **/
bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size);

/**
 * Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * This function carries out the SM2 signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be SM3_256.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]       sm2_context   Pointer to sm2 context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       id_a          the ID-A of the signing context.
 * @param[in]       id_a_size     size of ID-A signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive SM2 signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in SM2.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                          const uint8_t *id_a, size_t id_a_size,
                          const uint8_t *message, size_t size,
                          uint8_t *signature, size_t *sig_size);

/**
 * Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be SM3_256.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]  sm2_context   Pointer to SM2 context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  id_a          the ID-A of the signing context.
 * @param[in]  id_a_size     size of ID-A signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to SM2 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in SM2.
 * @retval  false  Invalid signature or invalid sm2 context.
 *
 **/
bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                            const uint8_t *id_a, size_t id_a_size,
                            const uint8_t *message, size_t size,
                            const uint8_t *signature, size_t sig_size);

/*=====================================================================================
 *    Pseudo-Random Generation Primitive
 *=====================================================================================*/

/**
 * Sets up the seed value for the pseudorandom number generator.
 *
 * This function sets up the seed value for the pseudorandom number generator.
 * If seed is not NULL, then the seed passed in is used.
 * If seed is NULL, then default seed is used.
 * If this interface is not supported, then return false.
 *
 * @param[in]  seed      Pointer to seed value.
 *                      If NULL, default seed is used.
 * @param[in]  seed_size  size of seed value.
 *                      If seed is NULL, this parameter is ignored.
 *
 * @retval true   Pseudorandom number generator has enough entropy for random generation.
 * @retval false  Pseudorandom number generator does not have enough entropy for random generation.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_random_seed(const uint8_t *seed, size_t seed_size);

/**
 * Generates a pseudorandom byte stream of the specified size.
 *
 * If output is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[out]  output  Pointer to buffer to receive random value.
 * @param[in]   size    size of random bytes to generate.
 *
 * @retval true   Pseudorandom byte stream generated successfully.
 * @retval false  Pseudorandom number generator fails to generate due to lack of entropy.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_random_bytes(uint8_t *output, size_t size);

/*=====================================================================================
 *    key Derivation Function Primitive
 *=====================================================================================*/

/**
 * Derive key data using HMAC-SHA256 based KDF.
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size);

/**
 * Derive SHA256 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA256 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size);

/**
 * Derive key data using HMAC-SHA384 based KDF.
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size);

/**
 * Derive SHA384 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA384 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size);

/**
 * Derive key data using HMAC-SHA512 based KDF.
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size);

/**
 * Derive SHA512 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA512 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size);

/**
 * Derive SHA3_256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size);

/**
 * Derive SHA3_256 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA3_256 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size);

/**
 * Derive SHA3_384 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size);

/**
 * Derive SHA3_384 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA3_384 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size);

/**
 * Derive SHA3_512 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size);

/**
 * Derive SHA3_512 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SHA3_512 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size);

/**
 * Derive SM3_256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sm3_256_extract_and_expand(const uint8_t *key, size_t key_size,
                                             const uint8_t *salt, size_t salt_size,
                                             const uint8_t *info, size_t info_size,
                                             uint8_t *out, size_t out_size);

/**
 * Derive SM3_256 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sm3_256_extract(const uint8_t *key, size_t key_size,
                                  const uint8_t *salt, size_t salt_size,
                                  uint8_t *prk_out, size_t prk_out_size);

/**
 * Derive SM3_256 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sm3_256_expand(const uint8_t *prk, size_t prk_size,
                                 const uint8_t *info, size_t info_size,
                                 uint8_t *out, size_t out_size);

/**
 * Gen CSR
 *
 * @param[in]      hash_nid              hash algo for sign
 * @param[in]      asym_nid              asym algo for sign
 *
 * @param[in]      requester_info        requester info to gen CSR
 * @param[in]      requester_info_length The len of requester info
 *
 * @param[in]      context               Pointer to asymmetric context
 * @param[in]      subject_name          Subject name: should be break with ',' in the middle
 *                                       example: "C=AA,CN=BB"
 * Subject names should contain a comma-separated list of OID types and values:
 * The valid OID type name is in:
 * {"CN", "commonName", "C", "countryName", "O", "organizationName","L",
 * "OU", "organizationalUnitName", "ST", "stateOrProvinceName", "emailAddress",
 * "serialNumber", "postalAddress", "postalCode", "dnQualifier", "title",
 * "SN","givenName","GN", "initials", "pseudonym", "generationQualifier", "domainComponent", "DC"}.
 * Note: The object of C and countryName should be CSR Supported Country Codes
 *
 * @param[in]      csr_len               For input，csr_len is the size of store CSR buffer.
 *                                       For output，csr_len is CSR len for DER format
 * @param[in]      csr_pointer           For input, csr_pointer is buffer address to store CSR.
 *                                       For output, csr_pointer is address for stored CSR.
 *                                       The csr_pointer address will be changed.
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/
bool libspdm_gen_x509_csr(size_t hash_nid, size_t asym_nid,
                          uint8_t *requester_info, size_t requester_info_length,
                          void *context, char *subject_name,
                          size_t *csr_len, uint8_t **csr_pointer);

#endif /* CRYPTLIB_H */
