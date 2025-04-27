#
# CMakeLists.txt file for generating vaultic_tls library
#

cmake_minimum_required(VERSION 3.5)

project(vaultic_tls)
include(functions.cmake)

add_option("VAULTIC_PRODUCT"
     "Select VaultIC product"
     "none" "292;none")
     
add_option("VAULTIC_PLATFORM"
     "Select Platform"
     "RASPBERRY" "RASPBERRY")
       
add_option("VAULTIC_LOGS_LEVEL"
    "Configure the level of debug logs"
    "ERRORS" "SILENT;ERRORS;DEBUG;VERBOSE")
    
# Translate CMAKE options in compiler definitions for VaultIC-Elib
if("${VAULTIC_PRODUCT}" STREQUAL "none")
    message(FATAL_ERROR "No VaultIC product selected")
endif()

set(VAULTIC_LOG_LEVEL 3)

if("${VAULTIC_LOGS_LEVEL}" STREQUAL "SILENT")
    set(VAULTIC_LOG_LEVEL 0)
elseif("${VAULTIC_LOGS_LEVEL}" STREQUAL "ERRORS")
    set(VAULTIC_LOG_LEVEL 1)
elseif("${VAULTIC_LOGS_LEVEL}" STREQUAL "DEBUG")
    set(VAULTIC_LOG_LEVEL 2)
elseif("${VAULTIC_LOGS_LEVEL}" STREQUAL "VERBOSE")
    set(VAULTIC_LOG_LEVEL 3)
else() 
    message (FATAL_ERROR "Invalid LOG_LEVEL value: expecting SILENT, ERRORS, DEBUG or VERBOSE") 
endif()

if(${VAULTIC_PLATFORM} STREQUAL "RASPBERRY")
		set(TARGET_NAME embedded/raspberry/pi3)
        list (APPEND CFLAGS "RASPBERRY_PI")
else()
        message(FATAL_ERROR "Not implemented yet")
endif()

list (APPEND CFLAGS "VCC_CTRL_BY_GPIO   ")
list (APPEND CFLAGS "RESET_BLOCKPROTOCOL_AT_STARTUP")
list (APPEND CFLAGS "RPI_PRINT_ERRORS")
list (APPEND CFLAGS "TWI_TRACE_ERRORS")

# Declare files of the vaultic_tls library
set(VAULTIC_TLS_INC_DIR ./)
set(VAULTIC_TLS_SRCS    vaultic_tls.c)


# Declare files from VaultIC API which are required for TLS
set(VAULTIC_API_SRC_DIR ../../vaultic_elib_${VAULTIC_PRODUCT}/src/)
set(VAULTIC_API_INC_DIR ${VAULTIC_API_SRC_DIR}/common
                        ${VAULTIC_API_SRC_DIR}/common/comms
                        ${VAULTIC_API_SRC_DIR}/arch/embedded/common
                        ${VAULTIC_API_SRC_DIR}/device/vaultic_2XX_family)

set(VAULTIC_API_SRCS    ${VAULTIC_API_SRC_DIR}/arch/embedded/common/vaultic_mem.c
                        ${VAULTIC_API_SRC_DIR}/arch/${TARGET_NAME}/vaultic_control_driver.c
                        ${VAULTIC_API_SRC_DIR}/arch/${TARGET_NAME}/vaultic_timer_delay.c
                        ${VAULTIC_API_SRC_DIR}/common/vaultic_command.c
                        ${VAULTIC_API_SRC_DIR}/common/vaultic_crc16.c
                        ${VAULTIC_API_SRC_DIR}/common/vaultic_utils.c
                        ${VAULTIC_API_SRC_DIR}/common/comms/vaultic_block_protocol.c
                        ${VAULTIC_API_SRC_DIR}/common/comms/vaultic_comms.c
                        ${VAULTIC_API_SRC_DIR}/common/comms/vaultic_protocol.c
                        ${VAULTIC_API_SRC_DIR}/device/vaultic_2XX_family/vaultic_api.c
                        ${VAULTIC_API_SRC_DIR}/arch/embedded/common/vaultic_twi_peripheral.c
                        ${VAULTIC_API_SRC_DIR}/arch/${TARGET_NAME}/vaultic_twi_driver.c)     
                        

if(VAULTIC_BUILD_CRYPTO_EXT)
    # Declare additional files from VaultIC API which are required by other apps
    set(VAULTIC_API_CRYPTO_INC_DIR 
                            ${VAULTIC_API_SRC_DIR}/crypto
                            ${VAULTIC_API_SRC_DIR}/crypto/certificate)                        

    set(VAULTIC_API_CRYPTO_SRCS 
                            ${VAULTIC_API_SRC_DIR}/crypto/certificate/x509parser.c)
endif()

# Compiling options required by VaultIC API                            
list (APPEND CFLAGS TARGETCHIP_VAULTIC_${VAULTIC_PRODUCT} VAULTIC_LOG_LEVEL=${VAULTIC_LOG_LEVEL} )

if(${VAULTIC_LOG_LEVEL} GREATER 0)
    list (APPEND CFLAGS "TRACE_BLOCK_PTCL_ERRORS")
    
    if(${VAULTIC_PLATFORM} STREQUAL "RASPBERRY")
        list (APPEND CFLAGS "RPI_PRINT_ERRORS")        
    endif()
endif()

if(${VAULTIC_LOG_LEVEL} GREATER 2)
    list (APPEND CFLAGS TRACE_APDU TRACE_BLOCK_PTCL)
endif()

# Build VaultIC TLS library
set (LIB_NAME vaultic_tls_${VAULTIC_PRODUCT})
add_library (${LIB_NAME} ${VAULTIC_API_SRCS} ${VAULTIC_TLS_SRCS})
target_include_directories (${LIB_NAME} PUBLIC ${VAULTIC_TLS_INC_DIR} ${VAULTIC_API_INC_DIR})
target_compile_definitions(${LIB_NAME} PUBLIC ${CFLAGS})


if(VAULTIC_BUILD_CRYPTO_EXT)
    # Build VaultIC TLS crypto library 
    set (LIB_NAME vaultic_tls_crypto)
    add_library (${LIB_NAME} ${VAULTIC_API_CRYPTO_SRCS} )
    target_include_directories (${LIB_NAME} PUBLIC ${VAULTIC_API_CRYPTO_INC_DIR} ${VAULTIC_API_INC_DIR}  )
    target_compile_definitions(${LIB_NAME} PUBLIC ${CFLAGS})
endif()





