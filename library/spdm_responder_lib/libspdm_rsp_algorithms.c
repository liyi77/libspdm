/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"


/* current version libspdm does not support any ext algo.
 * the responder will ignore the ext algo in request.
 * the responder will not build ext algo in response.*/


#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t other_params_support;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint8_t reserved2[12];
    uint8_t ext_asym_sel_count;
    uint8_t ext_hash_sel_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_algorithms_response_mine_t;
#pragma pack()

/**
 * Select the preferred supproted algorithm according to the priority_table.
 *
 * @param  priority_table                The priority table.
 * @param  priority_table_count           The count of the priroty table entry.
 * @param  local_algo                    Local supported algorithm.
 * @param  peer_algo                     Peer supported algorithm.
 *
 * @return final preferred supported algorithm
 **/
static uint32_t libspdm_prioritize_algorithm(const uint32_t *priority_table,
                                             size_t priority_table_count,
                                             uint32_t local_algo, uint32_t peer_algo)
{
    uint32_t common_algo;
    size_t index;

    common_algo = (local_algo & peer_algo);
    for (index = 0; index < priority_table_count; index++) {
        if ((common_algo & priority_table[index]) != 0) {
            return priority_table[index];
        }
    }

    return 0;
}

/**
 * Process the SPDM NEGOTIATE_ALGORITHMS request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_response_algorithms(void *context,
                                                 size_t request_size,
                                                 const void *request,
                                                 size_t *response_size,
                                                 void *response)
{
    const spdm_negotiate_algorithms_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_algorithms_response_mine_t *spdm_response;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    size_t index;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;
    uint32_t algo_size;
    uint8_t fixed_alg_size;
    uint8_t ext_alg_count;
    uint16_t ext_alg_total_count;

    uint32_t hash_priority_table[] = {
    #if LIBSPDM_SHA512_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
    #endif
    #if LIBSPDM_SHA384_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
    #endif
    #if LIBSPDM_SHA256_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    #endif
    #if LIBSPDM_SHA3_512_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512,
    #endif
    #if LIBSPDM_SHA3_384_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384,
    #endif
    #if LIBSPDM_SHA3_256_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256,
    #endif
    #if LIBSPDM_SM3_256_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256,
    #endif
        0,
    };

    uint32_t asym_priority_table[] = {
    #if LIBSPDM_ECDSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
    #endif
    #if LIBSPDM_RSA_PSS_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
    #endif
    #if LIBSPDM_RSA_SSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
    #endif
    #if LIBSPDM_EDDSA_ED448_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448,
    #endif
    #if LIBSPDM_EDDSA_ED25519_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519,
    #endif
    #if LIBSPDM_SM2_DSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256,
    #endif
    };

    uint32_t req_asym_priority_table[] = {
    #if LIBSPDM_ECDSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
    #endif
    #if LIBSPDM_RSA_PSS_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
    #endif
    #if LIBSPDM_RSA_SSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
    #endif
    #if LIBSPDM_EDDSA_ED448_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448,
    #endif
    #if LIBSPDM_EDDSA_ED25519_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519,
    #endif
    #if LIBSPDM_SM2_DSA_SUPPORT == 1
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256,
    #endif
    };

    uint32_t dhe_priority_table[] = {
    #if LIBSPDM_ECDHE_SUPPORT == 1
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
    #endif
    #if LIBSPDM_FFDHE_SUPPORT == 1
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
    #endif
    #if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256,
    #endif
    };

    uint32_t aead_priority_table[] = {
    #if LIBSPDM_AEAD_GCM_SUPPORT == 1
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
    #endif
    #if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
    #endif
    #if LIBSPDM_AEAD_SM4_SUPPORT == 1
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM,
    #endif
        0,
    };

    uint32_t key_schedule_priority_table[] = {
        SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
    };

    uint32_t measurement_hash_priority_table[] = {
    #if LIBSPDM_SHA512_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
    #endif
    #if LIBSPDM_SHA384_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
    #endif
    #if LIBSPDM_SHA256_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
    #endif
    #if LIBSPDM_SHA3_512_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,
    #endif
    #if LIBSPDM_SHA3_384_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,
    #endif
    #if LIBSPDM_SHA3_256_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,
    #endif
    #if LIBSPDM_SM3_256_SUPPORT == 1
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256,
    #endif
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
    };

    uint32_t measurement_spec_priority_table[] = {
        SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
    };

    uint32_t other_params_support_priority_table[] = {
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
    };

    spdm_context = context;
    spdm_request = request;

    ext_alg_total_count = 0;

    LIBSPDM_ASSERT(!(((spdm_context->local_context.capability.flags &
                       SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) ^
                     (spdm_context->local_context.algorithm.measurement_spec == 0)));

    LIBSPDM_ASSERT(!(((spdm_context->local_context.capability.flags &
                       SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) ^
                     (spdm_context->local_context.algorithm.measurement_hash_algo == 0)));

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (request_size < sizeof(spdm_negotiate_algorithms_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (request_size <
        sizeof(spdm_negotiate_algorithms_request_t) +
        sizeof(uint32_t) * spdm_request->ext_asym_count +
        sizeof(uint32_t) * spdm_request->ext_hash_count +
        sizeof(spdm_negotiate_algorithms_common_struct_table_t) *
        spdm_request->header.param1) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    struct_table = (void *)((size_t)spdm_request +
                            sizeof(spdm_negotiate_algorithms_request_t) +
                            sizeof(uint32_t) * spdm_request->ext_asym_count +
                            sizeof(uint32_t) * spdm_request->ext_hash_count);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        for (index = 0; index < spdm_request->header.param1; index++) {
            if ((size_t)spdm_request + request_size <
                (size_t)struct_table) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            if ((size_t)spdm_request + request_size -
                (size_t)struct_table <
                sizeof(spdm_negotiate_algorithms_common_struct_table_t)) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
            ext_alg_count = struct_table->alg_count & 0xF;
            ext_alg_total_count += ext_alg_count;
            if (fixed_alg_size != 2) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            if ((size_t)spdm_request + request_size -
                (size_t)struct_table -
                sizeof(spdm_negotiate_algorithms_common_struct_table_t) <
                sizeof(uint32_t) * ext_alg_count) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }
    ext_alg_total_count += (spdm_request->ext_asym_count + spdm_request->ext_hash_count);
    /* Algorithm count check and message size check*/
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (ext_alg_total_count > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_EXT_ALG_COUNT_VERSION_11) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
        if (spdm_request->length > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_LENGTH_VERSION_11) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
    } else {
        if (ext_alg_total_count > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_EXT_ALG_COUNT_VERSION_10) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
        if (spdm_request->length > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_LENGTH_VERSION_10) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
    }
    request_size = (size_t)struct_table - (size_t)spdm_request;
    if (request_size != spdm_request->length) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }
    spdm_request_size = request_size;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size >= sizeof(libspdm_algorithms_response_mine_t));
    *response_size = sizeof(libspdm_algorithms_response_mine_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_response->header.param1 =
            4; /* Number of Algorithms Structure Tables*/
    } else {
        spdm_response->header.param1 = 0;
        *response_size =
            sizeof(libspdm_algorithms_response_mine_t) -
            sizeof(spdm_negotiate_algorithms_common_struct_table_t) *
            4;
    }
    spdm_response->header.request_response_code = SPDM_ALGORITHMS;
    spdm_response->header.param2 = 0;
    spdm_response->length = (uint16_t)*response_size;

    spdm_context->connection_info.algorithm.measurement_spec =
        spdm_request->measurement_specification;
    if (spdm_request->measurement_specification != 0) {
        spdm_context->connection_info.algorithm.measurement_hash_algo =
            spdm_context->local_context.algorithm.measurement_hash_algo;
    } else {
        spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
    }
    spdm_context->connection_info.algorithm.base_asym_algo =
        spdm_request->base_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        spdm_request->base_hash_algo;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        struct_table =
            (void *)((size_t)spdm_request +
                     sizeof(spdm_negotiate_algorithms_request_t) +
                     sizeof(uint32_t) * spdm_request->ext_asym_count +
                     sizeof(uint32_t) * spdm_request->ext_hash_count);
        for (index = 0; index < spdm_request->header.param1; index++) {
            switch (struct_table->alg_type) {
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                spdm_context->connection_info.algorithm
                .dhe_named_group =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                spdm_context->connection_info.algorithm
                .aead_cipher_suite =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                spdm_context->connection_info.algorithm
                .req_base_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                spdm_context->connection_info.algorithm
                .key_schedule =
                    struct_table->alg_supported;
                break;
            default:
                /* Unknown algorithm types do not need to be processed */
                break;
            }
            ext_alg_count = struct_table->alg_count & 0xF;
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.algorithm.other_params_support =
            spdm_request->other_params_support;
    }

    spdm_response->measurement_specification_sel =
        (uint8_t)libspdm_prioritize_algorithm(
            measurement_spec_priority_table,
            LIBSPDM_ARRAY_SIZE(measurement_spec_priority_table),
            spdm_context->local_context.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm
            .measurement_spec);
    spdm_response->measurement_hash_algo = libspdm_prioritize_algorithm(
        measurement_hash_priority_table,
        LIBSPDM_ARRAY_SIZE(measurement_hash_priority_table),
        spdm_context->local_context.algorithm.measurement_hash_algo,
        spdm_context->connection_info.algorithm.measurement_hash_algo);
    spdm_response->base_asym_sel = libspdm_prioritize_algorithm(
        asym_priority_table, LIBSPDM_ARRAY_SIZE(asym_priority_table),
        spdm_context->local_context.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_asym_algo);
    spdm_response->base_hash_sel = libspdm_prioritize_algorithm(
        hash_priority_table, LIBSPDM_ARRAY_SIZE(hash_priority_table),
        spdm_context->local_context.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_hash_algo);
    spdm_response->struct_table[0].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_response->struct_table[0].alg_count = 0x20;
    spdm_response->struct_table[0].alg_supported =
        (uint16_t)libspdm_prioritize_algorithm(
            dhe_priority_table, LIBSPDM_ARRAY_SIZE(dhe_priority_table),
            spdm_context->local_context.algorithm.dhe_named_group,
            spdm_context->connection_info.algorithm.dhe_named_group);
    spdm_response->struct_table[1].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_response->struct_table[1].alg_count = 0x20;
    spdm_response->struct_table[1]
    .alg_supported = (uint16_t)libspdm_prioritize_algorithm(
        aead_priority_table, LIBSPDM_ARRAY_SIZE(aead_priority_table),
        spdm_context->local_context.algorithm.aead_cipher_suite,
        spdm_context->connection_info.algorithm.aead_cipher_suite);
    spdm_response->struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_response->struct_table[2].alg_count = 0x20;
    spdm_response->struct_table[2]
    .alg_supported = (uint16_t)libspdm_prioritize_algorithm(
        req_asym_priority_table,
        LIBSPDM_ARRAY_SIZE(req_asym_priority_table),
        spdm_context->local_context.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    spdm_response->struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_response->struct_table[3].alg_count = 0x20;
    spdm_response->struct_table[3].alg_supported =
        (uint16_t)libspdm_prioritize_algorithm(
            key_schedule_priority_table,
            LIBSPDM_ARRAY_SIZE(key_schedule_priority_table),
            spdm_context->local_context.algorithm.key_schedule,
            spdm_context->connection_info.algorithm.key_schedule);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response->other_params_support =
            (uint8_t)libspdm_prioritize_algorithm(
                other_params_support_priority_table,
                LIBSPDM_ARRAY_SIZE(other_params_support_priority_table),
                spdm_context->local_context.algorithm.other_params_support,
                spdm_context->connection_info.algorithm.other_params_support);
    }

    spdm_context->connection_info.algorithm.measurement_spec =
        spdm_response->measurement_specification_sel;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        spdm_response->measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        spdm_response->base_asym_sel;
    spdm_context->connection_info.algorithm.base_hash_algo =
        spdm_response->base_hash_sel;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) &&
        (spdm_request->measurement_specification != 0)) {
        if (spdm_context->connection_info.algorithm.measurement_spec !=
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        algo_size = libspdm_get_measurement_hash_size(
            spdm_context->connection_info.algorithm
            .measurement_hash_algo);
        if (algo_size == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }
    algo_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (algo_size == 0) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        algo_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
        if (algo_size == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_context->connection_info.algorithm.dhe_named_group =
            spdm_response->struct_table[0].alg_supported;
        spdm_context->connection_info.algorithm.aead_cipher_suite =
            spdm_response->struct_table[1].alg_supported;
        spdm_context->connection_info.algorithm.req_base_asym_alg =
            spdm_response->struct_table[2].alg_supported;
        spdm_context->connection_info.algorithm.key_schedule =
            spdm_response->struct_table[3].alg_supported;
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
            spdm_context->connection_info.algorithm.other_params_support =
                spdm_response->other_params_support;
        } else {
            spdm_context->connection_info.algorithm.other_params_support = 0;
        }

        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
            algo_size = libspdm_get_dhe_pub_key_size(
                spdm_context->connection_info.algorithm
                .dhe_named_group);
            if (algo_size == 0) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
            algo_size = libspdm_get_aead_key_size(
                spdm_context->connection_info.algorithm
                .aead_cipher_suite);
            if (algo_size == 0) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            algo_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm
                .req_base_asym_alg);
            if (algo_size == 0) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
            if (spdm_context->connection_info.algorithm
                .key_schedule !=
                SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                if ((spdm_context->connection_info.algorithm.other_params_support &
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) !=
                    SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1) {
                    return libspdm_generate_error_response(
                        spdm_context,
                        SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                        response_size, response);
                }
            }
        }
    } else {
        spdm_context->connection_info.algorithm.dhe_named_group = 0;
        spdm_context->connection_info.algorithm.aead_cipher_suite = 0;
        spdm_context->connection_info.algorithm.req_base_asym_alg = 0;
        spdm_context->connection_info.algorithm.key_schedule = 0;
        spdm_context->connection_info.algorithm.other_params_support = 0;
    }
    status = libspdm_append_message_a(spdm_context, spdm_request,
                                      spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_a(spdm_context, spdm_response,
                                      *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    libspdm_set_connection_state(spdm_context,
                                 LIBSPDM_CONNECTION_STATE_NEGOTIATED);

    return LIBSPDM_STATUS_SUCCESS;
}
