#=======================================
#SEAL SQ 2024
#INeS SDK
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

# Nous voulons un cmake "récent" pour utiliser les dernières fonctionnalités
cmake_minimum_required(VERSION 3.6)

#Project name
project(ines_SDK_lib VERSION 1.0.0)


if(INES_SDK_DEBUG)
    add_compile_definitions(VAULTIC_LOGS_LEVEL VERBOSE)
endif()

LINK_DIRECTORIES(lib)

#source files directory
set(SRCS 
    "src/wisekey_Http_Request_Manager.c"
    "src/wisekey_Crypto_Tools.c"
    "src/wisekey_Tools.c"
    "src/wisekey_Ines_API.c"
    )

set(HEADERS
    "include/wisekey_ZTP_settings.h"
    "include/wisekey_Http_Request_Manager.h"
    "include/wisekey_Crypto_Tools.h"
    "include/wisekey_Tools.h"
    "include/wisekey_Ines_API.h"
    )

INCLUDE_DIRECTORIES(include)

#VAULTIC LIB
if("${VAULTIC_PRODUCT}" STREQUAL "408")
    message("VIC 408 Compilation")
    add_compile_definitions(TARGETCHIP_VAULTIC_408)
    set(USE_SEALSQ_VAULT_IC ON )
    add_compile_definitions(USE_SPI)
    set(VAULTIC_BUILD_CRYPTO_EXT ON)
    add_subdirectory(lib/libVaultIC/408/vaultic_tls-4xx/src)
elseif("${VAULTIC_PRODUCT}" STREQUAL "292")
    message("VIC 292 Compilation")
    add_compile_definitions(TARGETCHIP_VAULTIC_292)
    set(USE_SEALSQ_VAULT_IC ON)
    set(VAULTIC_BUILD_CRYPTO_EXT ON)
    add_subdirectory(lib/libVaultIC/292/vaultic_tls-2xx/src)
else()
    message("No Secure Element compilation")
    remove_definitions(-DTARGETCHIP_VAULTIC_292 -DTARGETCHIP_VAULTIC_408)
endif()

# On inclut notre bibliothèque dans le processus de CMake
add_subdirectory(extlibs/ini)
add_subdirectory(extlibs/json)
add_subdirectory(extlibs/libwolfssl/wolfssl)

set(ALL_FILES ${Source_Files})
add_library(ines_SDK_lib STATIC ${SRCS} ${HEADERS})

if(USE_SEALSQ_VAULT_IC)
    message("Linking for Secure Element VIC ${VAULTIC_PRODUCT}")
    target_link_libraries(ines_SDK_lib  PUBLIC ini json wolfssl vaultic_tls_${VAULTIC_PRODUCT} vaultic_tls_crypto m)
else()
    message("Linking for WITHOUT-SE version")
    target_link_libraries(ines_SDK_lib ini json wolfssl m)
endif()
