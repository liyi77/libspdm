/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

/**
 * Process the SPDM encapsulated CHALLENGE request and return the response.
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
libspdm_return_t libspdm_get_encap_response_challenge_auth(
    void *context, size_t request_size, void *request,
    size_t *response_size, void *response)
{
    spdm_challenge_request_t *spdm_request;
    spdm_challenge_auth_response_t *spdm_response;
    bool result;
    size_t signature_size;
    uint8_t slot_id;
    uint32_t hash_size;
    uint32_t measurement_summary_hash_size;
    uint8_t *ptr;
    size_t total_size;
    libspdm_context_t *spdm_context;
    uint8_t auth_attribute;
    libspdm_return_t status;
    size_t response_capacity;
    uint8_t slot_mask;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_VERSION_MISMATCH,
            SPDM_CHALLENGE, response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_CHALLENGE, response_size, response);
    }

    if (request_size != sizeof(spdm_challenge_request_t)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    slot_id = spdm_request->header.param1;

    if ((slot_id != 0xFF) &&
        (slot_id >= SPDM_MAX_SLOT_COUNT)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    signature_size = libspdm_get_req_asym_signature_size(
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    measurement_summary_hash_size = 0;

    total_size =
        sizeof(spdm_challenge_auth_response_t) + hash_size +
        SPDM_NONCE_SIZE + measurement_summary_hash_size +
        sizeof(uint16_t) +
        spdm_context->local_context.opaque_challenge_auth_rsp_size +
        signature_size;

    LIBSPDM_ASSERT(*response_size >= total_size);
    response_capacity = *response_size;
    *response_size = total_size;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    auth_attribute = (uint8_t)(slot_id & 0xF);
    spdm_response->header.param1 = auth_attribute;

    if (slot_id == 0xFF) {
        spdm_response->header.param2 = 0;

        slot_id = spdm_context->local_context.provisioned_slot_id;
    } else {
        slot_mask = libspdm_get_cert_slot_mask(spdm_context);
        if (slot_mask != 0) {
            spdm_response->header.param2 = slot_mask;
        } else {
            return libspdm_generate_encap_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    ptr = (void *)(spdm_response + 1);
    result = libspdm_generate_cert_chain_hash(spdm_context, slot_id, ptr);
    if (!result) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }
    ptr += hash_size;

    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, ptr)) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    ptr += SPDM_NONCE_SIZE;

    ptr += measurement_summary_hash_size;

    *(uint16_t *)ptr = (uint16_t)spdm_context->local_context
                       .opaque_challenge_auth_rsp_size;
    ptr += sizeof(uint16_t);
    if (spdm_context->local_context.opaque_challenge_auth_rsp != NULL) {
        libspdm_copy_mem(ptr,
                         response_capacity - (ptr - (uint8_t*)response),
                         spdm_context->local_context.opaque_challenge_auth_rsp,
                         spdm_context->local_context.opaque_challenge_auth_rsp_size);
        ptr += spdm_context->local_context.opaque_challenge_auth_rsp_size;
    }

    /* Calc Sign*/

    status = libspdm_append_message_mut_c(spdm_context, spdm_request,
                                          request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    status = libspdm_append_message_mut_c(spdm_context, spdm_response,
                                          (size_t)ptr - (size_t)spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_mut_c(spdm_context);
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }
    result =
        libspdm_generate_challenge_auth_signature(spdm_context, true, ptr);
    if (!result) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }
    ptr += signature_size;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
