/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/**
 * \file wisekey_Tools.c
 * \brief Useful tools to use Ines SDK
 * \version 1.3
 * \date 09/10/2023
 *
 * This files implements all the basic tools function to use Ines SDK
 *
 */

// System libs
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

// SEAL SQ libs
#include "wisekey_Tools.h"
#include "wisekey_Crypto_Tools.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "../extlibs/ini/ini.h"
#include "../extlibs/json/json.h"


#define SALT_SIZE 8
#define EC256

char *createDeviceName(config_values_t config)
{
    int rand_value;
    char *device_name;

    if(!config.DEVICE_NAME_PREFIX)
    {
        device_name = malloc(strlen("WKEY_ZTOUCH_DEFAULT_NAME") + 16);
        wkey_log(LOG_INFO,"DEFAULT NAME");
        sprintf(device_name,"%s" ,"WKEY_ZTOUCH_DEFAULT_NAME");
        return device_name;

    }

    srand(time(NULL));

    for (int i = 0; i != 10; i++)
    {
        rand_value = rand() % 10001;
    }

    device_name = malloc(strlen(config.DEVICE_NAME_PREFIX) + 6 + 1);

    sprintf(device_name,"%s_%d" ,config.DEVICE_NAME_PREFIX, rand_value);

    return device_name;
}

void rebootEsp()
{    
    wkey_log(LOG_WARNING, "Restarting ESP...");
    for (int i = 5; i >= 0; i--)
    {
    }
    fflush(stdout);
    //esp_restart();
}

char *openFile(const char *path)
{
    struct stat stat_file;
    stat(path, &stat_file);
    char *buff = malloc(stat_file.st_size + 10);

    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        return NULL;
    }

    fread(buff, 1, stat_file.st_size, file);
    fclose(file);

    if (buff[stat_file.st_size - 1] == '\n')
    {
        buff[stat_file.st_size - 1] = '\0';
    }
    else
    {
        buff[stat_file.st_size] = '\0';
    }
    return buff;
}


int checkCertificateAndKeyDisponibility(config_values_t config, bool need_check_key)
{
    struct stat st;
        
    if (stat(config.DEVICE_CERT_PATH, &st) != 0) {
        wkey_log(LOG_ERROR, "File %s doesn't exist",config.DEVICE_CERT_PATH);
        return -1;
    }

    if(need_check_key==TRUE)
    {
        if (stat(config.SECURE_KEY_PATH, &st) != 0) {
            wkey_log(LOG_ERROR, "File %s doesn't exist",config.SECURE_KEY_PATH);
            return -1;
        }
    }
    return 0;
}

char *inesRawCartificatetoFormatedcert(char *rawCert)
{
    const char *separators = "\\";
    char *tempRawCert = malloc(strlen(rawCert) + 1);
    memset(tempRawCert, 0, strlen(rawCert) + 1);

    char *strseparated = strtok(rawCert, separators);
    char *template = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n";
    char *formatedCertificate;

    while (strseparated != NULL)
    {
        if (strseparated[0] == 'n')
        {
            strseparated[0] = '\n';
        }
        strcat(tempRawCert, strseparated);
        strseparated = strtok(NULL, separators);
    }

    formatedCertificate = malloc(strlen(template) + strlen(rawCert) + 1);
    sprintf(formatedCertificate, template, rawCert);

    free(tempRawCert);

    return formatedCertificate;
}

char *estRawCartificatetoFormatedcert(char *rawCert)
{
    PKCS7 *pkcs7;
    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    unsigned char*finalpem;
   
    unsigned char* templatepem = "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----";

    unsigned char* pem = malloc(strlen(rawCert)+strlen(templatepem));
    sprintf(pem,templatepem,rawCert);
        int pemSz = strlen(pem);



    unsigned char buff[2048];
    int buffSz = sizeof(buff)/sizeof(char);
    int ret;

    ret=wc_CertPemToDer(pem, pemSz, buff, buffSz, 0);
    if(ret <= 0) {
        wkey_log(LOG_ERROR,"wc_CertPemToDer %d",ret);
        return NULL;
    }

    free(pem);

    ret = wc_PKCS7_VerifySignedData(pkcs7,buff,ret);
    if ( ret < 0 ) {
        wkey_log(LOG_ERROR,"wc_PKCS7_VerifySignedData %d",ret);
        return NULL;

    }

    finalpem= malloc(2048);
    ret = wc_DerToPem(pkcs7->cert[0], pkcs7->certSz[0], finalpem, 2048, 0);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "EST CERT DER to PEM failed: %d\n", ret);
        return NULL;
    }

    return finalpem;
}

int writeAndSaveFile(char *name, char *content, int size)
{    
    int ret = -1;
    /* Variable to store user content */
    
    if(name==NULL||content==NULL)
        return ret;

    FILE *file = NULL;


    file = fopen(name, "wb");
    if (file)
    {
        ret = (int)fwrite(content, 1, size, file);
        fclose(file);
    }

    return ret;
}

json_value* convertStringIntoJsontype(char* string)
{
    int file_size;
    json_value* value;

    file_size = strlen(string);
    char*cursor;
    char*stringCopy=malloc(strlen(string)+2);

    if(string)
    {
        cursor = strstr(string,"{");
        sprintf(stringCopy,cursor);
        cursor = strrchr(stringCopy,'}');
        sprintf(cursor+1,"%c",'\0');
    }
    else
        return NULL;
        
    value = json_parse(stringCopy,file_size);

    if (value == NULL) {
            fprintf(stderr, "Unable to parse data\n");
            return NULL;
    }

    free(stringCopy);

    return value;
}

static char* process_value(json_value*value)
{
    char* returnvalue=NULL;

    switch (value->type)
    {
        case json_none:
                break;
        case json_null:
                returnvalue =NULL;
        case json_object:   
                break;
        case json_array:
                break;
        case json_integer:
                returnvalue = malloc(11);
                sprintf(returnvalue,"%ld",(long)value->u.integer);
                break;
        case json_double:
                returnvalue= malloc(12);
                sprintf(returnvalue,"%f",value->u.dbl);
                break;
        case json_string:
                returnvalue= malloc(strlen(value->u.string.ptr)+1);
                sprintf(returnvalue,"%s",value->u.string.ptr);
        case json_boolean:
                //wkey_log(LOG_ERROR,"Unexpected JSON type Boolean");
                break;
        default:
            break;
    }

    return returnvalue;
}

char *extractJsonValue(json_value* value, char*object,char*object2)
{
        int length,length2;

        if (value == NULL) {
                return NULL;
        }

        length = value->u.object.length;

        for (int x = 0; x < length; x++) {
                if(strcmp(value->u.object.values[x].name,object)==0)
                {
                    if(object2)
                    {

                        length2 = value->u.object.values[x].value->u.object.length; 
                        for (int y = 0; y < length2; y++) 
                        {
                            if(strcmp(value->u.object.values[x].value->u.object.values[y].name,object2)==0)
                                {      
                                    return process_value(value->u.object.values[x].value->u.object.values[y].value);
                                }
                        }
                    }
                    else
                        return process_value(value->u.object.values[x].value);
                }
        }
    
    return NULL;
}

int storeJsonValueIntoStructValue(char**structValue,json_value*value, char* object,char*object2)
{
    char *valuetostore = extractJsonValue(value, object,object2);

    if(valuetostore)
    {
        *structValue = malloc(strlen(valuetostore)+1); 
        memset(*structValue,0,strlen(valuetostore)+1);
        strncpy(*structValue,valuetostore,strlen(valuetostore));
        free(valuetostore);
        return 0;
    }
    else
    {
        *structValue="NULL";
    }
    

    return -1;
}

void wkey_log(int type, char *fmt, ...)
{

    va_list ap; /* points to each unnamed arg in turn */
    char *p, *sval;
    int ival;
    double dval;
    va_start(ap, fmt); /* make ap point to 1st unnamed arg */

    switch (type)
    {
    case LOG_WARNING:
        printf("\e[0;33mSEAL SQ WARNING : ");
        break;
    case LOG_STEP_INDICATOR:
        printf("\e[1;34;47mWSEAL SQ STEP ");
        break;

    case LOG_ERROR:
        printf("\e[1;37;41mSEAL SQ ERROR : ");
        break;

    case LOG_DEBUGING:
        printf("\e[1;37;45mSEAL SQ DEBUGING INFO : ");
        break;
        
    case LOG_SUCCESS:
        printf("\e[1;37;42mSEAL SQ SUCCESS : ");
        break;

    default:
        printf("\e[0mSEAL SQ INFO : ");
        break;
    }

    for (p = fmt; *p; p++)
    {
        if (*p != '%')
        {
            putchar(*p);
            continue;
        }
        switch (*++p)
        {
        case 'd':
            ival = va_arg(ap, int);
            printf("%d", ival);
            break;
        case 'f':
            dval = va_arg(ap, double);
            printf("%f", dval);
            break;
        case 's':
            for (sval = va_arg(ap, char *); *sval; sval++)
                putchar(*sval);
            break;
        default:
            putchar(*p);
            break;
        }
    }

    printf("\e[0m\r\n");
    va_end(ap); /* clean up when done */
}

void fillArrayList(int type, void*OutputArray, json_value *value)
{

    int numberOfItems=value->u.object.values[0].value->u.array.length;

    for(int i=0;i<numberOfItems;i++)
    {

        switch (type)
        {
        case INES_RESPONSE_TYPE_CA_LIST:        
            fillResultStruct(type, (CA_details_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        case INES_RESPONSE_TYPE_CERTIFICATE:        
            fillResultStruct(type, (certificate_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:        
            fillResultStruct(type, (certificate_template_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        default:
            break;
        }
    }

}

void fillResultStruct(int type, void *input_Struct, json_value *value)
{
    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct authentication_t* authentication_Struct = input_Struct;
    struct certificate_template_t* certificateTemplate_Struct = input_Struct;

    switch (type)
    {
    case INES_RESPONSE_TYPE_AUTHENTICATION:
        storeJsonValueIntoStructValue(&authentication_Struct->access_token, value, "access_token",NULL);
        break;

    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.subject, value, "root", "subject");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.issuer, value, "root", "issuer");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.certificate, value, "root", "certificate");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.subject, value, "issuing", "subject");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.issuer, value, "issuing", "issuer");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.certificate, value, "issuing", "certificate");
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        storeJsonValueIntoStructValue(&CA_details_Struct->id, value, "ca", "id");
        storeJsonValueIntoStructValue(&CA_details_Struct->caAlias, value, "ca", "caAlias");
        storeJsonValueIntoStructValue(&CA_details_Struct->thumbprint, value, "ca", "thumbprint");
        storeJsonValueIntoStructValue(&CA_details_Struct->serverName, value, "ca", "serverName");
        storeJsonValueIntoStructValue(&CA_details_Struct->caName, value, "ca", "caName");
        storeJsonValueIntoStructValue(&CA_details_Struct->description, value, "ca", "description");
        storeJsonValueIntoStructValue(&CA_details_Struct->certificate, value, "ca", "certificate");
        break;
    
    case INES_RESPONSE_TYPE_CA_LIST:
        storeJsonValueIntoStructValue(&CA_details_Struct->id, value,"id",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->caAlias, value, "caAlias",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->thumbprint, value, "thumbprint",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->serverName, value, "serverName",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->caName, value, "caName",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->description, value, "description",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->certificate, value, "certificate",NULL);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        storeJsonValueIntoStructValue(&certificate_Struct->certificate_id, value, "certificate_id", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->organization_id, value, "organization_id", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->common_name, value, "common_name", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->issued_dn, value, "issued_dn", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->certificate, value, "certificate", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->certificate_pkcs12, value, "certificate_pkcs12", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->passphrase, value, "passphrase", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->status, value, "status", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->issuer, value, "issuer", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->serial_number, value, "serial_number", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->valid_from, value, "valid_from", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->valid_until, value, "valid_until", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->thumbprint, value, "thumbprint", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->san, value, "san", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->revocation_reason, value, "revocation_reason",NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->revocation_date, value, "revocation_date",NULL);
        break;
    
    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        storeJsonValueIntoStructValue(&certificate_Status_Struct->status, value, "status", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->detail, value, "detail", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->reason, value, "reason", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->revocation_date, value, "revocationDate", NULL);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->template_id, value, "template_id", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->organization_id, value, "organization_id", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->name, value, "name", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->description, value, "description", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->status, value, "status", NULL);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }
}

void displayResults(int type, void *input_Struct)
{
    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct certificate_template_t *certificate_Template_Struct = input_Struct;


    switch (type)
    {
    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        printf("\r\n\033[1;30;47m--- CA Chain Result ---\033[0m\r\n");
        printf("\033[1;37m- root\r\n");
        printf("|-- subject : %s\r\n", CA_certificat_chain_Struct->root.subject);
        printf("|-- issuer : %s\r\n", CA_certificat_chain_Struct->root.issuer);
        printf("|-- certificate : %s\r\n", CA_certificat_chain_Struct->root.certificate);
        printf("- issuing\r\n");
        printf("|-- subject : %s\r\n", CA_certificat_chain_Struct->issuing.subject);
        printf("|-- issuer : %s\r\n", CA_certificat_chain_Struct->issuing.issuer);
        printf("|-- certificate : %s\r\n", CA_certificat_chain_Struct->issuing.certificate);
        printf("\033[1;30;47m--- END CA Chain Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        printf("\r\n\033[1;30;47m--- CA Details Result ---\033[0m\r\n");
        printf("\033[1;37m- CA\r\n");
        printf("|-- id : %s\r\n", CA_details_Struct->id);
        printf("|-- caAlias : %s\r\n", CA_details_Struct->caAlias);
        printf("|-- thumbprint : %s\r\n", CA_details_Struct->thumbprint);
        printf("|-- serverName : %s\r\n", CA_details_Struct->serverName);
        printf("|-- caName : %s\r\n", CA_details_Struct->caName);
        printf("|-- description : %s\r\n", CA_details_Struct->description);
        printf("|-- certificate : %s\r\n", CA_details_Struct->certificate);
        printf("\033[1;30;47m--- END CA Details Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        printf("\r\n\033[1;30;47m--- Certficate Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate\r\n");
        printf("|-- certificate_id : %s\r\n", certificate_Struct->certificate_id);
        printf("|-- organization_id : %s\r\n", certificate_Struct->organization_id);
        printf("|-- common_name : %s\r\n", certificate_Struct->common_name);
        printf("|-- issued_dn : %s\r\n", certificate_Struct->issued_dn);
        printf("|-- certificate : %s\r\n", certificate_Struct->certificate);
        printf("|-- certificate_pkcs12 : %s\r\n", certificate_Struct->certificate_pkcs12);
        printf("|-- passphrase : %s\r\n", certificate_Struct->passphrase);
        printf("|-- status : %s\r\n", certificate_Struct->status);
        printf("|-- issuer : %s\r\n", certificate_Struct->issuer);
        printf("|-- serial_number : %s\r\n", certificate_Struct->serial_number);
        printf("|-- valid_from : %s\r\n", certificate_Struct->valid_from);
        printf("|-- valid_until : %s\r\n", certificate_Struct->valid_until);
        printf("|-- thumbprint : %s\r\n", certificate_Struct->thumbprint);
        printf("|-- san : %s\r\n", certificate_Struct->san);
        printf("\033[1;30;47m--- END Certficate Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        printf("\r\n\033[1;30;47m--- Certficate Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate Status\r\n");
        printf("|-- status : %s\r\n", certificate_Status_Struct->status);
        printf("|-- detail : %s\r\n", certificate_Status_Struct->detail);
        printf("|-- recation reason : %s\r\n", certificate_Status_Struct->reason);
        printf("|-- revocationDate : %s\r\n", certificate_Status_Struct->revocation_date);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        printf("\r\n\033[1;30;47m--- Certficate Template Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate Template\r\n");
        printf("|-- template_id : %s\r\n", certificate_Template_Struct->template_id);
        printf("|-- organization_id : %s\r\n", certificate_Template_Struct->organization_id);
        printf("|-- name : %s\r\n", certificate_Template_Struct->name);
        printf("|-- description : %s\r\n", certificate_Template_Struct->description);
        printf("|-- status : %s\r\n", certificate_Template_Struct->status);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }
}

int generatekeyAndCSR(config_values_t config, char**CSR, char**subjects)
{
    char *deviceName = NULL;
    ecc_key pKey;
    static CertName certDefaultName;
    deviceName = createDeviceName(config);
    int ret;
    
    memcpy(certDefaultName.country, config.DEVICE_COUNTRY, strlen(config.DEVICE_COUNTRY));
    certDefaultName.countryEnc = CTC_PRINTABLE;
    memcpy(certDefaultName.commonName, deviceName, strlen(deviceName));
    certDefaultName.commonNameEnc = CTC_UTF8;
    memcpy(certDefaultName.serialDev, config.DEVICE_SERIAL_NUMBER, strlen(config.DEVICE_SERIAL_NUMBER));
    certDefaultName.serialDevEnc = CTC_PRINTABLE;

    *subjects = generateSubjects(&certDefaultName);

    if(strcmp(config.USE_VAULTIC,"TRUE")==0)
    {    
        wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Generate CSR (Certificate Signin Request) with VaultIC");
        *CSR = generateCSRwithVAULTIC(&pKey, &certDefaultName);
    }
    else
    {
        wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Generate Key and CSR (Certificate Signin Request) with WolfSSL generator");
        generateAndSavePrivateEccKey(&pKey, config.SECURE_KEY_PATH);

        if ((ret=wc_ecc_check_key(&pKey)) != MP_OKAY)
        {
            wkey_log(LOG_ERROR, "Error while generating private Key %d",ret);
            return -1;
        }    
        
        *CSR = generateCSR(&pKey, &certDefaultName);
        wc_ecc_free(&pKey);
    }

    if (deviceName)
        free(deviceName);

    if (!CSR)
    {
        wkey_log(LOG_ERROR, "Error while creating CSR : ");
        return -2;
    }
    
    return 0;
}


void freeResultStruct(int type, void *input_Struct)
{

    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct certificate_template_t *certificate_Template_Struct = input_Struct;


    switch (type)
    {
    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        if((CA_certificat_chain_Struct->root.subject) && (strcmp(CA_certificat_chain_Struct->root.subject,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.subject);
        if((CA_certificat_chain_Struct->root.issuer) && (strcmp(CA_certificat_chain_Struct->root.issuer,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.issuer);
        if((CA_certificat_chain_Struct->root.certificate) && (strcmp(CA_certificat_chain_Struct->root.certificate,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.certificate);
        if((CA_certificat_chain_Struct->issuing.subject) && (strcmp(CA_certificat_chain_Struct->issuing.subject,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.subject);        
        if((CA_certificat_chain_Struct->issuing.issuer) && (strcmp(CA_certificat_chain_Struct->issuing.issuer,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.issuer);   
        if((CA_certificat_chain_Struct->issuing.certificate) && (strcmp(CA_certificat_chain_Struct->issuing.certificate,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.certificate);   
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        if((CA_details_Struct->id) && (strcmp(CA_details_Struct->id,"NULL")!=0))
            free(CA_details_Struct->id);
        if((CA_details_Struct->caAlias) && (strcmp(CA_details_Struct->caAlias,"NULL")!=0))
            free(CA_details_Struct->caAlias);
        if((CA_details_Struct->thumbprint) && (strcmp(CA_details_Struct->thumbprint,"NULL")!=0))
            free(CA_details_Struct->thumbprint);
        if((CA_details_Struct->serverName) && (strcmp(CA_details_Struct->serverName,"NULL")!=0))
            free(CA_details_Struct->serverName);        
        if((CA_details_Struct->caName) && (strcmp(CA_details_Struct->caName,"NULL")!=0))
            free(CA_details_Struct->caName);   
        if((CA_details_Struct->description) && (strcmp(CA_details_Struct->description,"NULL")!=0))
            free(CA_details_Struct->description); 
        if((CA_details_Struct->certificate) && (strcmp(CA_details_Struct->certificate,"NULL")!=0))
            free(CA_details_Struct->certificate); 
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        if((certificate_Struct->certificate_id) && (strcmp(certificate_Struct->certificate_id,"NULL")!=0))
            free(certificate_Struct->certificate_id);
        if((certificate_Struct->organization_id) && (strcmp(certificate_Struct->organization_id,"NULL")!=0))
            free(certificate_Struct->organization_id);
        if((certificate_Struct->common_name) && (strcmp(certificate_Struct->common_name,"NULL")!=0))
            free(certificate_Struct->common_name);
        if((certificate_Struct->issued_dn) && (strcmp(certificate_Struct->issued_dn,"NULL")!=0))
            free(certificate_Struct->issued_dn);
        if((certificate_Struct->certificate) && (strcmp(certificate_Struct->certificate,"NULL")!=0))
            free(certificate_Struct->certificate);
        if((certificate_Struct->certificate_pkcs12) && (strcmp(certificate_Struct->certificate_pkcs12,"NULL")!=0))
            free(certificate_Struct->certificate_pkcs12);
        if((certificate_Struct->passphrase) && (strcmp(certificate_Struct->passphrase,"NULL")!=0))
            free(certificate_Struct->passphrase);
        if((certificate_Struct->status) && (strcmp(certificate_Struct->status,"NULL")!=0))
            free(certificate_Struct->status);
        if((certificate_Struct->issuer) && (strcmp(certificate_Struct->issuer,"NULL")!=0))
            free(certificate_Struct->issuer);
        if((certificate_Struct->serial_number) && (strcmp(certificate_Struct->serial_number,"NULL")!=0))
            free(certificate_Struct->serial_number);
        if((certificate_Struct->valid_from) && (strcmp(certificate_Struct->valid_from,"NULL")!=0))
            free(certificate_Struct->valid_from);
        if((certificate_Struct->valid_until) && (strcmp(certificate_Struct->valid_until,"NULL")!=0))
            free(certificate_Struct->valid_until);
        if((certificate_Struct->thumbprint) && (strcmp(certificate_Struct->thumbprint,"NULL")!=0))
            free(certificate_Struct->thumbprint);
        if((certificate_Struct->san) && (strcmp(certificate_Struct->san,"NULL")!=0))
            free(certificate_Struct->san);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        if((certificate_Status_Struct->status) && (strcmp(certificate_Status_Struct->status,"NULL")!=0))
            free(certificate_Status_Struct->status);
        if((certificate_Status_Struct->detail) && (strcmp(certificate_Status_Struct->detail,"NULL")!=0))
            free(certificate_Status_Struct->detail);
        if((certificate_Status_Struct->reason) && (strcmp(certificate_Status_Struct->reason,"NULL")!=0))
            free(certificate_Status_Struct->reason);
        if((certificate_Struct->revocation_date) && (strcmp(certificate_Status_Struct->revocation_date,"NULL")!=0))
            free(certificate_Status_Struct->revocation_date);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        if((certificate_Template_Struct->description) && (strcmp(certificate_Template_Struct->description,"NULL")!=0))
            free(certificate_Template_Struct->description);
        if((certificate_Template_Struct->name) && (strcmp(certificate_Template_Struct->name,"NULL")!=0))
            free(certificate_Template_Struct->name);
        if((certificate_Template_Struct->organization_id) && (strcmp(certificate_Template_Struct->organization_id,"NULL")!=0))
            free(certificate_Template_Struct->organization_id);
        if((certificate_Template_Struct->status) && (strcmp(certificate_Template_Struct->status,"NULL")!=0))
            free(certificate_Template_Struct->status);
        if((certificate_Template_Struct->template_id) && (strcmp(certificate_Template_Struct->template_id,"NULL")!=0))
            free(certificate_Template_Struct->template_id);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }

}


