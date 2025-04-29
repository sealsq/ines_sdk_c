/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

// System libs
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>

// SEAL SQ libs
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Tools.h"
#include "wisekey_ZTP_settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"

#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
#include "wolfssl/wolfcrypt/port/wisekey/vaultic.h"
#include "vaultic_tls.h"
#include "vaultic_tls_config.h"
#endif

#define EC256

#define LARGE_TEMP_SZ 4096


static void removeChar(char* s, char c)
{
 
    int j, n = strlen(s);
    for (int i = j = 0; i < n; i++)
        if (s[i] != c)
            s[j++] = s[i];
 
    s[j] = '\0';
}

char *removeCertificateHeaders(char *cert)
{
    if(cert==NULL)
        return NULL;

    char *cpy = strstr(cert,"-----BEGIN CERTIFICATE-----\n");
    if(cpy)
        sprintf(cert,cpy+strlen("-----BEGIN CERTIFICATE-----\n"));
    cpy = strstr(cert,"\n-----END CERTIFICATE-----");
    if(cpy)
        sprintf(cpy,"%c",'\0');
    removeChar(cert,'\n');
    return cert;
}

char *removeCSR_Headers(char *CSR)
{
    char *cpy = strstr(CSR,"-----BEGIN CERTIFICATE REQUEST-----\n");
    sprintf(CSR,cpy+strlen("-----BEGIN CERTIFICATE REQUEST-----\n"));
    cpy = strstr(CSR,"\n-----END CERTIFICATE REQUEST-----");
    sprintf(cpy,"%c",'\0');

    removeChar(CSR,'\n');

    return CSR;
}

int generateAndSavePrivateEccKey(ecc_key *ecKey, char *outFilePath)
{
    int ret;
    WC_RNG rng;
    byte *der = NULL;
    byte *pem = NULL;
    int derSz;
#ifdef WOLFSSL_DER_TO_PEM
    int pemSz;
    FILE *file = NULL;
    char outFile[255];
#endif

    der = malloc(ECC_BUFSIZE);

    pem = malloc(LARGE_TEMP_SZ);

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "RNG initialization failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    ret = wc_ecc_init(ecKey);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Key initialization failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    ret = wc_ecc_make_key_ex(&rng, 32, ecKey, ECC_SECP256R1);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Key generation failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    wc_FreeRng(&rng);

    ret = wc_EccKeyToDer(ecKey, der, LARGE_TEMP_SZ);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Key To DER failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }
    derSz = ret;

    // memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, LARGE_TEMP_SZ, ECC_PRIVATEKEY_TYPE);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Key DER to PEM failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }
    pemSz = ret;
    snprintf(outFile, sizeof(outFile), outFilePath);

    file = fopen(outFile, "wb");

    if (file)
    {
        ret = (int)fwrite(pem, 1, pemSz, file);
        if (ret <= 0)
        {
            wkey_log(LOG_ERROR, "Saving PEM Key failed: %d\n", ret);
            free(pem);
            free(der);
            fclose(file);
            return ret;
        }
        else
            wkey_log(LOG_INFO, "ECC KEY generated and saved into \"%s\"\n", outFile);
        fclose(file);
    }

    free(pem);
    free(der);

    return 1;
}

char* template = "{\"oid\": \"%s\", \"value\": \"%s\"}";

void concatenateSubject(char* strsubjects,char*oid,char *value,int*first)
{
    if(*first==FALSE)
        strcat(strsubjects,",");

    char*subject=malloc(strlen(template)+strlen(oid)+strlen(value));
    sprintf(subject,template,oid,value);
    strcat(strsubjects,subject);
    free(subject);
    *first=FALSE;
}


int countStrSubjectSize(char*oid,char *value,int*first)
{
    int size =0;
        
    if(*first==FALSE)
        size+=strlen(",");        
        
    size+= strlen(template);
    size+= strlen(oid);
    size+= strlen(value);
    *first=FALSE;

    return size;

}

char *generateSubjects(CertName *certDefaultName)
{   
    char* subjectString=NULL;
    int firstsubject=TRUE;

//Count size of the full string of subject    
    int subjectStringSize = strlen("[]")+1;

    if(certDefaultName->commonName)
        subjectStringSize+=countStrSubjectSize(OID_COMMON_NAME,certDefaultName->commonName,&firstsubject);

    if(certDefaultName->country)
        subjectStringSize+=countStrSubjectSize(OID_COUNTRY,certDefaultName->country,&firstsubject);

    /*if(certDefaultName->email)
        subjectStringSize+=countStrSubjectSize(OID_EMAIL,certDefaultName->email,&firstsubject);*/
    
    if(certDefaultName->locality)
        subjectStringSize+=countStrSubjectSize(OID_LOCALITY_NAME,certDefaultName->locality,&firstsubject);
        
    if(certDefaultName->org)
        subjectStringSize+=countStrSubjectSize(OID_ORGANIZATION_NAME,certDefaultName->org,&firstsubject);
    
    if(certDefaultName->postalCode)
        subjectStringSize+=countStrSubjectSize(OID_POSTAL_CODE,certDefaultName->postalCode,&firstsubject);
    
    if(certDefaultName->serialDev)
        subjectStringSize+=countStrSubjectSize(OID_DEVICE_SERIAL_NUMBER,certDefaultName->serialDev,&firstsubject);

    subjectString=malloc(subjectStringSize);

//Fill the string
    firstsubject=TRUE;

    sprintf(subjectString,"["); 

    if(certDefaultName->commonName)
        concatenateSubject(subjectString,OID_COMMON_NAME,certDefaultName->commonName,&firstsubject);

    if(certDefaultName->country)
        concatenateSubject(subjectString,OID_COUNTRY,certDefaultName->country,&firstsubject);
    
    /*if(certDefaultName->email)
        concatenateSubject(subjectString,OID_EMAIL,certDefaultName->email,&firstsubject);*/
    
    if(certDefaultName->locality)
        concatenateSubject(subjectString,OID_LOCALITY_NAME,certDefaultName->locality,&firstsubject);

    if(certDefaultName->org)
        concatenateSubject(subjectString,OID_ORGANIZATION_NAME,certDefaultName->org,&firstsubject);

    if(certDefaultName->postalCode)
        concatenateSubject(subjectString,OID_POSTAL_CODE,certDefaultName->postalCode,&firstsubject);
    
    if(certDefaultName->serialDev)
        concatenateSubject(subjectString,OID_DEVICE_SERIAL_NUMBER,certDefaultName->serialDev,&firstsubject);

    strcat(subjectString,"]");

    return subjectString;
}

char *generateCSRwithVAULTIC(ecc_key *ecKey,CertName* certDefaultName)
{

#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)

    int ret;
    Cert *req;
    int err=0;

    byte *der = NULL;    
    int derSz;

    byte *outVaultic = NULL;
    byte *hash;
    static byte *pem = NULL;

    der = malloc(ECC_BUFSIZE);
    hash = malloc(P256_BYTE_SZ);
    outVaultic = malloc(ECC_BUFSIZE);
    pem = malloc(LARGE_TEMP_SZ);
    req = malloc(sizeof(Cert));
        

    unsigned char au8Qx[P256_BYTE_SZ]={0};
    unsigned char au8Qy[P256_BYTE_SZ]={0};

    ret=-1;


    /* Open session with VaultIC */
    if(vlt_tls_init() !=0) {
        fprintf(stderr, "ERROR: vic_tls_init error\n");
        return NULL;
    }

    /* Sign input message using VaultIC */
#ifdef TARGETCHIP_VAULTIC_408  
    wkey_log(LOG_INFO,"[vlt_tls_read_pub_key_P256 TARGETCHIP_VAULTIC_408]\n");
    if(ret=vlt_tls_read_pub_key_P256(ECC_OPERATIONAL_Pubk_Index,au8Qx, au8Qy) != 0)
	{
        wkey_log(LOG_ERROR,"VAULTIC 408 vlt_tls_read_pub_key_P256");
        return NULL;
	}
#else	
	wkey_log(LOG_INFO,"[vlt_tls_read_operational_pub_key_P256 TARGETCHIP_VAULTIC_292]\n");    
    if (vlt_tls_read_operational_pub_key_P256(au8Qx, au8Qy) !=0) {
        wkey_log(LOG_ERROR,"VAULTIC 292 vlt_tls_read_operational_pub_key_P256\n");
        return NULL;
    }
#endif /*TARGETCHIP_VAULTIC_408*/

    if( (err = wc_ecc_import_unsigned(ecKey, au8Qx, au8Qy,  NULL, ECC_SECP256R1)) != 0) {
        wkey_log(LOG_ERROR,"wc_ecc_import_unsigned %d\n",err);
        return NULL;
    }

    derSz = ret;

    ret = wc_InitCert(req);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Init Cert failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return NULL;
    }

    req->version = 0;
    req->sigType = CTC_SHA256wECDSA;

    memcpy(&req->subject, certDefaultName, sizeof(CertName));


    ret = wc_MakeCertReq_ex(req, der, LARGE_TEMP_SZ, ECC_TYPE, ecKey);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Make Cert Req failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return NULL;
    }

    CertSignCtx  certSignCtx_lcl;
    CertSignCtx* certSignCtx = &certSignCtx_lcl;
    int digestSz = 0, typeH = 0;

    int hashSz = wc_Sha256Hash(der, req->bodySz,hash);
    if (hashSz!=0) {
         wkey_log(LOG_ERROR,"HashForSignature\n");
    }

    byte sig_R[P256_BYTE_SZ];
    byte sig_S[P256_BYTE_SZ];
    unsigned int outSz =ECC_BUFSIZE;

    /* Sign input message using VaultIC */
#ifdef TARGETCHIP_VAULTIC_408  
    wkey_log(LOG_INFO,"[vlt_tls_compute_signature_P256 TARGETCHIP_VAULTIC_408]\n");
    if (err=vlt_tls_compute_signature_P256(ECC_OPERATIONAL_Privk_Index,hash, P256_BYTE_SZ, sig_R , sig_S) !=0) {
        wkey_log(LOG_ERROR,"ERROR: vlt_tls_compute_signature_P256 err=%d",err);
        return NULL;
    }
#endif /*TARGETCHIP_VAULTIC_408*/

#ifdef TARGETCHIP_VAULTIC_292 	
	wkey_log(LOG_INFO,"[vlt_tls_read_pub_key_P256 TARGETCHIP_VAULTIC_292]\n");  
    if (err=vlt_tls_compute_signature_P256(VAULTIC_OPERATIONAL_KEY_INDEX,hash, P256_BYTE_SZ, sig_R , sig_S) !=0) {
        wkey_log(LOG_ERROR,"WOLFSSL_VAULTIC_EccSignCb %d\n",err);
        return NULL;
    }
#endif /*TARGETCHIP_VAULTIC_292*/

    /* Convert R and S to signature */
    if( (err=wc_ecc_rs_raw_to_sig(sig_R, P256_BYTE_SZ, sig_S, P256_BYTE_SZ, outVaultic, &outSz)) != 0) {
        wkey_log(LOG_ERROR,"ERROR: wc_ecc_rs_raw_to_sig err=%d",err);
        return NULL;
    }

    derSz = AddSignature(der, req->bodySz, outVaultic, outSz,req->sigType);

    ret = wc_DerToPem(der, derSz, pem, LARGE_TEMP_SZ, CERTREQ_TYPE);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "CSR DER to PEM failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return NULL;
    }

    /* Close connection with VaultIC */
    if(vlt_tls_close()!=0) {
        fprintf(stderr, "ERROR: vlt_tls_close error\n");
    }

    if(der)
        free(der);
    if(req)
        free(req);

    return (char *)pem;
    
#else

    wkey_log(LOG_ERROR,"VAULT-IC lib seems unavailable");
    return NULL;

#endif /*#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)*/
}

char *generateCSR(ecc_key *ecKey, CertName* certDefaultName)
{
    int ret;
    Cert *req;

    WC_RNG rng;

    byte *der = NULL;
    int derSz;

    static byte *pem = NULL;

    der = malloc(ECC_BUFSIZE);

    pem = malloc(LARGE_TEMP_SZ);

    req = malloc(sizeof(Cert));

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "RNG initialization failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-1";
    }

    ret = wc_EccKeyToDer(ecKey, der, LARGE_TEMP_SZ);
    if (ret < 0)
    {
        wkey_log(LOG_ERROR, "wc_EccKeyToDer failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-1";
    }
    derSz = ret;

    ret = wc_InitCert(req);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Init Cert failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-1";
    }

    req->version = 0;
    req->sigType = CTC_SHA256wECDSA;

    memcpy(&req->subject, certDefaultName, sizeof(CertName));


    ret = wc_MakeCertReq_ex(req, der, LARGE_TEMP_SZ, ECC_TYPE, ecKey);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Make Cert Req failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-4";
    }

    // last
    ret = wc_SignCert_ex(req->bodySz, req->sigType, der, LARGE_TEMP_SZ, ECC_TYPE, ecKey, &rng);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Sign Cert failed: %d\n", ret);
    }
    derSz = ret;

    // memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, LARGE_TEMP_SZ, CERTREQ_TYPE);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "CSR DER to PEM failed: %d\n", ret);
    }

    if(der)
        free(der);
    if(req)
        free(req);

    return (char *)pem;
}
