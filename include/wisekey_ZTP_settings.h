/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/*! \file wisekey_ZTP_settings.h
    \brief All globals variables
*/

//Info Version
#define ZTP_DEMO_VERSION "1.0.3_RASPBERRY"

// Please enter your WIFI credential
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASS "YOUR_WIFI_PASSWORD"

#define INES_CONFIG_PATH "inesConfig.ini"
#define ZTP_CONFIG_PATH "ztpConfig.ini"

// HTTP REQUEST INES HEADERS
#define HEADER_USER_AGENT "user-agent"
#define HEADER_ACCEPT "accept"
#define HEADER_CONTENT_TYPE "content-type"
#define HEADER_CONTENT_LENGTH "content-length"
#define HEADER_AUTHORIZATION "authorization"
#define USER_AGENT "ZTP_C_INES_AGENT"
#define ACCEPT_VALUE "*/*"
#define JSON_CONTENT_TYPE "application/json"
#define PKCS7_CONTENT_TYPE "application/pkcs7"


//HTTP STANDARDS
#define GET_METHOD "GET"
#define POST_METHOD "POST"

//===================================================
// HTTP  REQUEST INES API REST
#define IOT_API_REST_PATH_PREFIX "/v2"

#define REST_ORGANIZATION_PREFIX "/organizations"

//Authentication
#define IOT_API_REST_AUTHENTIFICATION "/auth"

//Certification Authorities
#define IOT_API_REST_GET_CA_PREFIX "/certificationauthorities" //GET CA LIST, GET CA Details, Get CA Certificate Chain
#define IOT_API_REST_GET_CA_CERTIFICATE_CHAIN "/download" //Get CA Certificate Chain

//Certificate
#define IOT_API_REST_CERTIFICATE "/certificates"
#define IOT_API_REST_CERTIFICATE_RENEW "/renew"
#define IOT_API_REST_CERTIFICATE_REKEY "/rekey"
#define IOT_API_REST_CERTIFICATE_REVOKE "/revoke"
#define IOT_API_REST_CERTIFICATE_VALIDATE_SUFFIX "/validate"
#define IOT_API_REST_CERTIFICATE_STATUS_SUFFIX "/status"
#define IOT_API_REST_CERTIFICATE_COMMON_NAME_SUFFIX "/cn"
#define IOT_API_REST_CERTIFICATE_SERIAL_NUMBER_SUFFIX "/sn"


//Certificate Template
#define IOT_API_REST_CERTIFICATE_TEMPLATE "/certificatetemplates"

//EST API
#define IOT_API_EST_PATH_PREFIX "/.well-known/est"

#define IOT_API_EST_ARBITRARYLABEL "/arbitraryLabel"
#define IOT_API_EST_GET_CA "/cacerts"
#define IOT_API_EST_ENROLL_CERT "/simpleenroll"
#define IOT_API_EST_RE_ENROLL_CERT "/simplereenroll"
#define IOT_API_EST_SERVER_KEY_GEN "/serverkeygen"