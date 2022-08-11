cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/x509_parser_openssl
                    ${LIBSPDM_DIR}/os_stub/openssllib/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl/crypto/include
                    ${LIBSPDM_DIR}/os_stub/openssllib/openssl
)

SET(src_x509_parser_openssl
    x509.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(x509_parser_openssl STATIC ${src_x509_parser_openssl})
TARGET_COMPILE_OPTIONS(x509_parser_openssl PRIVATE ${OPENSSL_FLAGS})
