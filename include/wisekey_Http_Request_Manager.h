/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/*! \file wisekey_Http_Request_Manager.h
    \brief HTTPS functions
*/

#include<stdio.h>
#include<stdlib.h>

#ifndef HTTP_REQUEST_MANAGER
#define HTTP_REQUEST_MANAGER

#define SA struct sockaddr


#ifdef __cplusplus
extern "C"
{
#endif
    extern int h_errno;

    /** @brief Format the request and lauch the httpsRequest_task
     *
     *  @param clientCertPath path to client cert to use to HTTPS authentification
     *  @param clientKeyPath path to client key to use to HTTPS authentification
     *  @return 0 if no error
     */
    int httpsRequestWolfssl(char*clientCertPath,char*clientKeyPath);

    /** @brief Format the request and lauch the httpsRequestWolfssl and wait for the response
     *
     *  @param clientCertPath Path to client Certificate to use, can be NULL if you use VAULT_IC Certificate
     *  @param clientKeyPath Path to client Key to use, can be NULL if you use VAULT_IC Key
     *  @param host to send the post request
     *  @param method GET/ POST
     *  @param path of the API
     *  @param headers contain the header part of the request (generate by generateHttpHeader)
     *  @param body contain the body of the request (CSR body for example)
     *  @return Char* corresponding to the response 
     */
    char *httpsRequest(char*clientCertPath,char*clientKeyPath,char *host,char* method, char *path, char *headers, char *body);

    /** @brief Generate the header part of the request
     *  @param host to send the post request
     *  @param Api of the API
     *  @param body contain the body of the request (CSR body for example)
     *  @param accesstoken contain the accesstoken previously get by getAccessTokenFromInes (NULL if not needed)
     *  @return Char* formated headers
     */
    char *generateHttpHeader(char *host, int protocol,char *api, char *body, char *accesstoken);

    /** @brief Generate the body part of the request
     *  @param templateId can be found on Ines portal
     *  @param subjects 
     *  @param CSR CSR generated
     *  @param validityPeriodDays
     *  @return CSR formated body
     */
    char *generateCSRBody(char *templateId, char *subjects, char *CSR, int validityPeriodDays);


    /** @brief Get Http Body from a Ines Response
     *  @param response from Ines
     *  @return Ines Response body
     */
    char *extractHttpResponseBody(char *response);

    /** @brief Generate the body and headers, and contact Ines
     *  @param clientCertPath Path to client Certificate to use, can be NULL if you use VAULT_IC Certificate
     *  @param clientKeyPath Path to client Key to use, can be NULL if you use VAULT_IC Key
     *  @param host Ines Endpoint
     *  @param protocol choose into INES_PROTOCOL enum (API_REST or EST_API)
     *  @param pathPrefix first part of the path to ressource (before organization id)
     *  @param inesOrgId Organization Id
     *  @param accessToken if necessary, NULL if not
     *  @param method GET, POST, DELETE
     *  @param apiname select one of IOT_API_*
     *  @param custom_suffix final part of the path
     *  @param body body part of the request if needed
     *  @param useVaultIc TRUE if you want to use a Key or certificate store into VAULT-IC, FALSE if not
     *  @param VaultIcKeyIndex index of the key to use in VAULT-IC, keep at 0 if you don't use
     *  @param VaultIcCertIndex index of the Certificate to use in VAULT-IC, keep at 0 if you don't use
     *  @return Ines Response, NULL if failure
     */
    char *inesApi(char* clientCert,char*clientKey,char* host,int protocol,char *pathPrefix, char *inesOrgId,char *accessToken,char* method,char* apiname, char* custom_suffix,char* body,bool useVaultIc,int VaultIcKeyIndex,int VaultIcCertIndex);

#ifdef __cplusplus
}
#endif

#endif /*HTTP_REQUEST_MANAGER*/
