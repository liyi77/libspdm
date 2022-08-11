cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/x509_parser_mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

SET(src_x509_parser_mbedtls
    x509.c
    sys_call/mem_allocation.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(x509_parser_mbedtls STATIC ${src_x509_parser_mbedtls})
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        TARGET_COMPILE_OPTIONS(x509_parser_mbedtls PRIVATE /wd4090)
    endif()
endif()