/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

// System libs
#include <stdio.h>

// SEAL SQ libs
#include "wisekey_Ines_API.h"
#include "wisekey_Http_Request_Manager.h"
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Tools.h"
#include "wisekey_ZTP_settings.h"

#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
#include "vaultic_tls_config.h"
#include <vaultic_tls.h>
#endif

char* apiREST_process(config_values_t config, char* method,char* apiname, char* custom_suffix,char* body){

    bool use_vaultic=FALSE;
    int key_index=0;
    int cert_index=0;

    if(strcmp(config.USE_VAULTIC,"TRUE")==0)  
    {
        wkey_log(LOG_INFO,"VAULTIC USE isn't supported for REST API, please remove USE_VAULTIC option and use local certificates");
        return NULL;
    }

    if(method==NULL||apiname==NULL)
    {
        wkey_log(LOG_ERROR,"apiREST_process : Invalid argument");
        return NULL;
    }

    char *rawResponse = inesApi(config.CLIENT_CERT_PATH,config.CLIENT_KEY_PATH,config.INES_REST_SERVER_URL,API_REST,IOT_API_REST_PATH_PREFIX,NULL,NULL,POST_METHOD,IOT_API_REST_AUTHENTIFICATION,NULL,NULL,use_vaultic,key_index,cert_index);

    if(!rawResponse)
    {
        wkey_log(LOG_ERROR, "NO ACCESS TOKEN");
        return NULL;
    }

    authentication_t authentication_Struct = {"NULL"};
    json_value *value = convertStringIntoJsontype(rawResponse);

    fillResultStruct(INES_RESPONSE_TYPE_AUTHENTICATION,&authentication_Struct,value);

    if(strcmp(authentication_Struct.access_token,"NULL")==0)
    {
        wkey_log(LOG_ERROR, "NO ACCESS TOKEN");
        return NULL;
    }

    wkey_log(LOG_INFO, "SENDING REQUEST");

    rawResponse = inesApi(config.CLIENT_CERT_PATH,config.CLIENT_KEY_PATH,config.INES_REST_SERVER_URL,API_REST,IOT_API_REST_PATH_PREFIX,config.INES_ORG_ID,authentication_Struct.access_token,method,apiname,custom_suffix,body,use_vaultic,key_index,cert_index);

    if(authentication_Struct.access_token)
        free(authentication_Struct.access_token);
    
    return rawResponse;
}

char* apiEST_process(config_values_t config,char* clientCertPath,char*clientKeyPath,char* method,char* apiname, char* custom_suffix,char* body){
    
    if(((clientCertPath==NULL||clientKeyPath==NULL)&&(strcmp(config.USE_VAULTIC,"TRUE")!=0))||method==NULL||apiname==NULL)
    {
        wkey_log(LOG_ERROR,"apiEST_process : Invalid argument");
        return NULL;
    }
    
    bool use_vaultic=FALSE;
    int key_index=0;
    int cert_index=0;
        
    if(strcmp(config.USE_VAULTIC,"TRUE")==0)  
    {
        

        #ifdef TARGETCHIP_VAULTIC_292
        use_vaultic=TRUE;
        key_index= VAULTIC_FACTORY_KEY_INDEX;
        cert_index=VAULTIC_FACTORY_CERT_INDEX;
        #elif TARGETCHIP_VAULTIC_408
        use_vaultic=TRUE;
        cert_index=SSL_VIC_DEVICE_CERT;
        #else
        wkey_log(LOG_WARNING,".ini file is define on USE_VAULTIC=TRUE but TARGETCHIP_VAULTIC_292 or TARGETCHIP_VAULTIC_408 isn't defined");
        use_vaultic=FALSE;
        #endif
    }
    
    char *rawResponse = inesApi(clientCertPath,clientKeyPath,config.INES_EST_SERVER_URL,API_EST,IOT_API_EST_PATH_PREFIX,NULL,NULL,method,apiname,NULL,body,use_vaultic,key_index,cert_index);

    return rawResponse;
}


//CERTIFICATE APIs
certificate_t apiREST_issueCertificate(config_values_t config, char *templateId, char *subjects, char *CSR)
{
    certificate_t certificate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};
    
    if(templateId==NULL||subjects==NULL||CSR==NULL)
    {
        wkey_log(LOG_ERROR,"apiREST_issueCertificate : Invalid argument");
        return certificate;
    }

    char *body = generateCSRBody(templateId, subjects, CSR, 30);

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, NULL, body);

    if (!response)
        return certificate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certificate, value);

    json_value_free(value);

    return certificate;
}

int apiREST_getCertificateList(config_values_t config,certificate_t* certificate_List, char* commonName, int certificate_ListSize, int pageNum)
{
    int numberOfItems=0;
    char* customPrefix = NULL;

    if(commonName)
    {
        if(pageNum>0)
            wkey_log(LOG_WARNING,"\'pageNum\' argument is useless if you use commonName filter");
        
        customPrefix = malloc(strlen(IOT_API_REST_CERTIFICATE_COMMON_NAME_SUFFIX)+strlen("/")+strlen(commonName)+1);
        sprintf(customPrefix,"%s/%s",IOT_API_REST_CERTIFICATE_COMMON_NAME_SUFFIX,commonName);
    }
    else
    {
        customPrefix = malloc(strlen("?pagenum=1&pagesize=")+4+4+1);
        sprintf(customPrefix,"?pagenum=%d&pagesize=%d",pageNum,certificate_ListSize/sizeof(certificate_t));
    }

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE, customPrefix,NULL);

    if (customPrefix)
        free(customPrefix);

    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }

    numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(certificate_ListSize/sizeof(certificate_t)))
    {
        wkey_log(LOG_ERROR,"certificate_List seems too low to store all CA, please improve it to at least %d",numberOfItems);
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CERTIFICATE,certificate_List,value);
    }

    json_value_free(value);

    return numberOfItems;

}

certificate_t apiREST_renewRekeyCertificate(config_values_t config, int certificate_id, int revokeOriginal, char *CSR)
{

    certificate_t certficate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};

    char *customSufix = NULL;
    char *bodytemplate = "{\r\n%s%s,\r\n\"revoke_original_certificate\":%s\r\n}";
    char *body;

    char *revokestate = (revokeOriginal == 0) ? "false" : "true";

    int bodylenght = strlen(bodytemplate) + strlen(revokestate) + 1;

    if (CSR)
    {
        customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_CERTIFICATE_REKEY) + 10 /*CA_id*/ + 1);
        sprintf(customSufix, "/%d%s", certificate_id, IOT_API_REST_CERTIFICATE_REKEY);
        bodylenght += strlen(CSR) + strlen("\"csr\":");
    }
    else
    {
        customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_CERTIFICATE_RENEW) + 10 /*CA_id*/ + 1);
        sprintf(customSufix, "/%d%s", certificate_id, IOT_API_REST_CERTIFICATE_RENEW);
    }
    body = malloc(bodylenght);

    sprintf(body, "{\r\n");

    if (CSR)
    {
        strcat(body, "\"csr\":\"");
        strcat(body, removeCSR_Headers(CSR));
        strcat(body, "\",\r\n");
    }

    strcat(body, "\"revoke_original_certificate\":");
    strcat(body, revokestate);
    strcat(body, "\r\n}");

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, customSufix, body);

    if (body)
        free(body);

    if (customSufix)
        free(customSufix);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certficate, value);

    json_value_free(value);

    return certficate;
}

int apiREST_revokeCertificate(config_values_t config, int certId, int revocation_reason, char *revocationComment)
{

    char *bodyTemplate = "{\r\n\"revocation_reason\":\"%s\",\r\n\"revocationComment\":\"%s\"\r\n}";
    int ret = -1;
    char *revokeReason;

    switch (revocation_reason)
    {
    case REVOKE_KEY_COMPROMISE:
        revokeReason = "keyCompromise";
        break;
    case REVOKE_CA_COMPROMISE:
        revokeReason = "cACompromise";
        break;

    case REVOKE_AFFILIATION_CHANGED:
        revokeReason = "affiliationChanged";
        break;

    case REVOKE_SUPERSEDED:
        revokeReason = "superseded";
        break;

    case REVOKE_CESSATION_OF_OPERATION:
        revokeReason = "cessationOfOperation";
        break;

    case REVOKE_CERTIFICATE_HOLD:
        revokeReason = "certificateHold";
        break;

    case REVOKE_REMOVE_FROM_CRL:
        revokeReason = "removeFromCRL";
        break;

    case REVOKE_PRIVILEGE_WITHDRAW:
        revokeReason = "privilegeWithdrawn";
        break;

    case REVOKE_AA_COMPROMISE:
        revokeReason = "aACompromise";
        break;

    default:
        revokeReason = "unspecified";
        break;
    }

    char *customSufix = malloc(10 + strlen(IOT_API_REST_CERTIFICATE_REVOKE) + 1);
    char *body = malloc(strlen(revokeReason) + strlen(revocationComment) + strlen(bodyTemplate) + 1);

    sprintf(customSufix, "/%d%s", certId, IOT_API_REST_CERTIFICATE_REVOKE);
    sprintf(body, bodyTemplate, revokeReason, revocationComment);

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, customSufix, body);

    if (customSufix)
        free(customSufix);

    if (!response)
        return -1;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    if (strcmp(extractJsonValue(value, "message", NULL), "OK") == 0)
    {
        wkey_log(LOG_SUCCESS, "Certificate Revoked");
        ret = 0;
    }

    if (response_body)
        free(response_body);

    json_value_free(value);

    return ret;
}

certificate_status_t apiREST_validateCertificate(config_values_t config, char *certificate)
{    
    certificate_status_t certficate_status = {"NULL", "NULL", "NULL", "NULL"};

    if(certificate==NULL)
    {
        wkey_log(LOG_ERROR,"apiREST_validateCertificate : Invalid argument");
        return certficate_status;
    }

    char *body = malloc(strlen("{\r\n\"certificate_data\": \"%s\"\r\n}") + strlen(certificate) + 1);
    sprintf(body, "{\r\n\"certificate_data\": \"%s\"\r\n}", certificate);
    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, IOT_API_REST_CERTIFICATE_VALIDATE_SUFFIX, body);

    if (!response)
        return certficate_status;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE_STATUS, &certficate_status, value);

    json_value_free(value);

    return certficate_status;
}

certificate_status_t apiREST_getRevocationInformation(config_values_t config, char *certificate)
{
    
    certificate_status_t certficate = {"NULL", "NULL", "NULL", "NULL"};

    if(certificate==NULL)
    {
        wkey_log(LOG_ERROR,"apiREST_getRevocationInformation : Invalid argument");
        return certficate;
    }


    char *body = malloc(strlen("{\r\n\"certificate_data\": \"%s\"\r\n}") + strlen(certificate) + 1);

    sprintf(body, "{\r\n\"certificate_data\": \"%s\"\r\n}", certificate);

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, IOT_API_REST_CERTIFICATE_STATUS_SUFFIX, body);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE_STATUS, &certficate, value);

    json_value_free(value);

    return certficate;
}

certificate_t apiREST_getCertificateDetails(config_values_t config, char *thumbprint, int certID)
{
    char *customSufix = "NULL";

    certificate_t certficate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};

    if ((thumbprint) && (certID != 0))
    {
        wkey_log(LOG_ERROR, "BAD ARGUMENT, fill only one of thumbprint or certID");
        return certficate;
    }

    if (certID > 0)
    {
        customSufix = malloc(12);
        sprintf(customSufix, "/%d", certID);
    }

    else if (thumbprint)
    {
        customSufix = malloc(strlen("/thumbprint/") + strlen(thumbprint) + 2);
        sprintf(customSufix, "/thumbprint/%s", thumbprint);
    }

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE, customSufix, NULL);

    if (customSufix)
        free(customSufix);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    if (response_body)
        free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certficate, value);

    json_value_free(value);

    return certficate;
}

int apiREST_getCertificatebySN(config_values_t config,certificate_t* certificate_List, char* serialNumber, int certificate_ListSize)
{
    int numberOfItems=0;
    char* customPrefix = NULL;

    if (serialNumber==NULL)
    {
        wkey_log(LOG_ERROR,"apiREST_getCertificatebySN : Invalid argument");
        return -1;
    }

    customPrefix = malloc(strlen(IOT_API_REST_CERTIFICATE_SERIAL_NUMBER_SUFFIX)+strlen("/")+strlen(serialNumber)+1);
    sprintf(customPrefix,"%s/%s",IOT_API_REST_CERTIFICATE_SERIAL_NUMBER_SUFFIX,serialNumber);

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE, customPrefix,NULL);

    if (customPrefix)
        free(customPrefix);

    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }

    numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(certificate_ListSize/sizeof(certificate_t)))
    {
        wkey_log(LOG_ERROR,"certificate_List seems too low to store all CA, please improve it to at least %d",numberOfItems);
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CERTIFICATE,certificate_List,value);
    }

    json_value_free(value);

    return numberOfItems;

}

//CERTIFICATE APIs

//Certificate Template APIs
int apiREST_getCertificateTemplateList(config_values_t config,certificate_template_t* certificateTemplate_List, int certificateTemplate_ListSize)
{  
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE_TEMPLATE, NULL,NULL);

    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);
        
    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }
    
    int numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(certificateTemplate_ListSize/sizeof(certificate_template_t)))
    {
        wkey_log(LOG_ERROR,"certificate_template_t seems too low to store all CA, please improve it to at least %d",numberOfItems);
        numberOfItems=-1;
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE,certificateTemplate_List,value);
    }

    json_value_free(value);

    return numberOfItems;

}

//Certificate Template APIs

//CA APIs
int apiREST_getCAList(config_values_t config,CA_details_t *CA_list,int CA_listSize)
{
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, NULL, NULL);


    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }

    int numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(CA_listSize/sizeof(CA_details_t)))
    {
        wkey_log(LOG_ERROR,"CA_list seems too low to store all CA, please improve it to at least %d",numberOfItems);
        numberOfItems=-1;
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CA_LIST,CA_list,value);
    }


    json_value_free(value);

    return numberOfItems;

}

CA_details_t apiREST_getCAdetails(config_values_t config, int CA_id)
{
    CA_details_t CA_details = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};
    char *customSufix = malloc(6);
    sprintf(customSufix, "/%d", CA_id);
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, customSufix, NULL);
    
    if (customSufix)
        free(customSufix);

    if (!response)
        return CA_details;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    fillResultStruct(INES_RESPONSE_TYPE_CA_DETAILS, &CA_details, value);

    json_value_free(value);

    return CA_details;
}

CA_certificat_chain_t apiREST_getCACertificateChain(config_values_t config, int CA_id)
{
    struct CA_certificat_chain_t CA_chaindetails = {{"NULL", "NULL", "NULL"}, {"NULL", "NULL", "NULL"}};
    char *customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_GET_CA_CERTIFICATE_CHAIN) + 10 /*CA_id*/ + 1);
    sprintf(customSufix, "/%d%s", CA_id, IOT_API_REST_GET_CA_CERTIFICATE_CHAIN);

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, customSufix, NULL);

    if (customSufix)
        free(customSufix);

    if (!response)
        return CA_chaindetails;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);
    free(body);

    fillResultStruct(INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN, &CA_chaindetails, value);
    json_value_free(value);

    return CA_chaindetails;
}
//CA APIs

// EST API
char *apiEST(config_values_t config,char* clientCertPath,char*clientKeyPath,int mode, char *body, bool arbitraryLabel)
{
    if(clientCertPath==NULL||clientKeyPath==NULL)
    {
        if(strcmp(config.USE_VAULTIC,"TRUE")!=0)
        {
            wkey_log(LOG_ERROR,"apiEST : Invalid argument");
            return NULL;
        }
    }

    char *certificate = "NULL";
    char *api = NULL;
    char *method = NULL;

    switch (mode)
    {
    case GET_CA_CERTIFICATE:
        if ((body) || (arbitraryLabel==TRUE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_GET_CA) + 1);
        sprintf(api, IOT_API_EST_GET_CA);
        break;

    case GET_CA_CERTIFICATE_ARBITRARY_LABEL:
        if ((body) || (!arbitraryLabel==FALSE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_ARBITRARYLABEL)+strlen(IOT_API_EST_GET_CA) + 1);
        sprintf(api,"%s%s",IOT_API_EST_ARBITRARYLABEL, IOT_API_EST_GET_CA);
        break;

    case ENROLL_CERTIFICATE:
        if ((!body) || (arbitraryLabel==TRUE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_ENROLL_CERT) + 1);
        sprintf(api, IOT_API_EST_ENROLL_CERT);
        break;

    case ENROLL_CERTIFICATE_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel==FALSE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_ARBITRARYLABEL)+strlen(IOT_API_EST_ENROLL_CERT) + 1);
        sprintf(api,"%s%s",IOT_API_EST_ARBITRARYLABEL, IOT_API_EST_ENROLL_CERT);
        break;

    case RE_ENROLL_CERTIFICATE:
        if ((!body) || (arbitraryLabel==TRUE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_RE_ENROLL_CERT) + 1);
        sprintf(api, IOT_API_EST_RE_ENROLL_CERT);
        break;

    case RE_ENROLL_CERTIFICATE_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel==FALSE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_ARBITRARYLABEL)+strlen(IOT_API_EST_ENROLL_CERT) + 1);
        sprintf(api,"%s%s",IOT_API_EST_ARBITRARYLABEL, IOT_API_EST_ENROLL_CERT);
        break;

    case ENROLL_CERTIFICATE_SERVER_KEY_GEN:
        if ((!body) || (arbitraryLabel==TRUE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_SERVER_KEY_GEN) + 1);
        sprintf(api, IOT_API_EST_SERVER_KEY_GEN);
        break;

    case ENROLL_CERTIFICATE_SERVER_KEY_GEN_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel==FALSE))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_ARBITRARYLABEL)+strlen(IOT_API_EST_SERVER_KEY_GEN) + 1);
        sprintf(api,"%s%s",IOT_API_EST_ARBITRARYLABEL, IOT_API_EST_SERVER_KEY_GEN);
        break;

    default:
        wkey_log(LOG_ERROR, "Unexpected EST_API");
        return "NULL";
        break;
    }

    char *rawResponse = apiEST_process(config,clientCertPath,clientKeyPath,method, api, NULL, body);

    if (api)
        free(api);

    char *responseCpy;

    if (rawResponse)
    {
        responseCpy = malloc(strlen(rawResponse) + 1);
        strcpy(responseCpy, rawResponse);
        certificate = extractHttpResponseBody(responseCpy);

        if (responseCpy)
            free(responseCpy);
    }
    else
        wkey_log(LOG_ERROR, "Error while requesting INES");

    if (rawResponse)
        free(rawResponse);

    return certificate;
}
// EST API