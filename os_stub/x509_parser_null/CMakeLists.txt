cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub/x509_parser_null
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include                   
)

SET(src_x509_parser_null
    x509.c
)

ADD_LIBRARY(x509_parser_null STATIC ${src_x509_parser_null})