/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

// System libs
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <time.h>
#include <fcntl.h>
#include <stdbool.h>

/* socket includes */
#include <arpa/inet.h>

// SEAL SQ libs
#include "wisekey_ZTP_settings.h"
#include "wisekey_Tools.h"
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Http_Request_Manager.h"

//#include "vaultic_tls_priv.h"

#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
#include "vaultic_tls_config.h"
#include "vaultic_tls.h"
#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>
#include <wolfssl/wolfcrypt/port/wisekey/vaultic_tls.h>
#endif

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>


typedef unsigned char byte;

#define MAXLINE 32768

#define DEFAULT_PORT 11111

/* Constants that aren't configurable in menuconfig */
#define WEB_PORT "443"

struct https_handler{
    int status;
    char* response;
    char *host;
    char *message;
    bool use_Vaultic;
    int  key_index;
    int  cert_index;
}Handler_https;

#define BUFFER_SIZE 16000

int httpsRequestWolfssl(char*clientCertPath,char*clientKeyPath)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    struct hostent     *he; 
    size_t             len;
    int                ret;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    /* Check for proper calling convention */

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        return -1;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* resolve hostname */
    if ( (he = gethostbyname(Handler_https.host) ) == NULL ) {
        wkey_log(LOG_ERROR, "ERROR: gethostbyname\n");
    }

    /* copy the network address to sockaddr_in structure */
    memcpy(&servAddr.sin_addr, he->h_addr_list[0], he->h_length);
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(443); /* on DEFAULT_PORT */
    
    wkey_log(LOG_INFO, "Connecting to IP %s %s\n",inet_ntoa(servAddr.sin_addr),he->h_name);

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        ret = -1;
        return ret;
    }
    //wolfSSL_Debugging_ON();
    
    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        close(sockfd);          /* Close the connection to the server       */;
        ret = -1;
        return ret;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        close(sockfd);          /* Close the connection to the server       */;
        return ret;
    }    
    
    if ((ret =wolfSSL_CTX_load_system_CA_certs(ctx))!= SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load CA err !%d\n",ret);
        wolfSSL_CTX_free(ctx); 
        wolfSSL_Cleanup();
        ret = -1;
        return ret;
    }

    if(Handler_https.use_Vaultic==TRUE)
    {
#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)

        wkey_log(LOG_INFO,"Use Vaultic Credencials keyindex = %d",Handler_https.key_index);

        /* Open session with VaultIC */
        if(vlt_tls_init() !=0) {
            fprintf(stderr, "ERROR: vic_tls_init error\n");
            ret = -1;
            wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
            wolfSSL_Cleanup();
            return -1; 
        }

        /*Load VaultIC certificates */    
#ifdef TARGETCHIP_VAULTIC_292
        vlt_tls_select_static_priv_key(Handler_https.key_index);
#elif TARGETCHIP_VAULTIC_408
        set_CurrenVaultickeyIndex(ECC_FACTORY_Privk_Index);
#endif        
        if(( ret = WOLFSSL_VAULTIC_LoadCertificates(ctx,Handler_https.cert_index)) != 0) {
            fprintf(stderr, "ERROR: failed to load VaultIC certificates.\n");
            wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
            wolfSSL_Cleanup();
            return -1; 
        }

        /* Setup wolfSSL VaultIC callbacks */
        WOLFSSL_VAULTIC_SetupPkCallbacks(ctx);
#endif /*defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)*/

    }
    else
    {
        if ((ret =  wolfSSL_CTX_use_certificate_file(ctx, clientCertPath,SSL_FILETYPE_PEM))
            != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: %d failed to load client certificate %s, please check the file.\n",
                    ret,clientCertPath);
            wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
            wolfSSL_Cleanup();
            return -1;
        }

        if ((ret =  wolfSSL_CTX_use_PrivateKey_file(ctx, clientKeyPath,SSL_FILETYPE_PEM))
            != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: %d failed to load client key %s, please check the file.\n",
                    ret,clientKeyPath);
            wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
            wolfSSL_Cleanup();
            return -1;
        }
    }


    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
        wolfSSL_Cleanup();
        ret = -1;
        return ret;
    }
    

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL errno = %d\n",ret);
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, Handler_https.message, strlen(Handler_https.message))) != strlen(Handler_https.message)) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, strlen(Handler_https.message));
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

    char* response = malloc(BUFFER_SIZE);

    /* Read the server data into our buff array */
    memset(response, 0, BUFFER_SIZE);
    if ((ret = wolfSSL_read(ssl, response, BUFFER_SIZE-1)) == -1) {
        wolfSSL_free(ssl);        
        fprintf(stderr, "ERROR: SEAL SQ failed to read err = %d\n",ret);
        ret = -1;
        return ret; 
    }
    
    int err;
    int responseSize;

    while(ret==BUFFER_SIZE-1)
    {
        /*if ((ret = wolfSSL_Rehandshake(ssl)) != WOLFSSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
            responseSize = strlen(response);
            response = realloc(response,responseSize + BUFFER_SIZE +1);*/

            if (err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE ||
                err == APP_DATA_READY) {
                //do {
                if (err == APP_DATA_READY) {
                        if ((ret = wolfSSL_read(ssl, response+responseSize,
                            BUFFER_SIZE-1)) < 0) {
                            fprintf(stderr, "ERROR: SEAL SQ failed to read 2 err = %d\n",ret);
                        /* HANDLE ERROR */
                        }
                }
                err = wolfSSL_get_error(ssl, 0);

            }
        //}
    }

    responseSize+=strlen(response)+1;

    Handler_https.response=malloc(responseSize);
    sprintf(Handler_https.response,"%s",response);
        
    wolfSSL_shutdown(ssl);
    
    #if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
    /* Close connection with VaultIC */
    if(vlt_tls_close()!=0) {
        fprintf(stderr, "ERROR: vlt_tls_close error\n");
    }
    #endif /*defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)*/

    free(response);

    Handler_https.status=0;
    ret = 0;
    return ret;
}

char *generateHttpHeader(char *host, int protocol,char *api, char *body, char *accesstoken)
{
    char *headers = "";
    int headers_size = 0;
    char *contentLen = "0";

    if(body){
        contentLen = malloc(11);
        sprintf(contentLen, "%d", strlen(body));
    }
    char *contentType;

    if(protocol==API_EST)
        contentType=PKCS7_CONTENT_TYPE;
    else
        contentType=JSON_CONTENT_TYPE;

    char *accesstokenTemplate = "%s: Bearer %s \r\n";
    char *accesstokenheader = "";

    if (accesstoken)
    {
        accesstokenheader = malloc(strlen(accesstokenTemplate) + strlen(HEADER_AUTHORIZATION) + strlen(accesstoken) +1);
        sprintf(accesstokenheader, accesstokenTemplate, HEADER_AUTHORIZATION, accesstoken);
    }

    // Message Template
    char *normalRequestTemplate = "%s: %s\r\n%s%s: %s\r\n%s: %s\r\n%s: %s\r\n";
    // Message Size
    headers_size += strlen(normalRequestTemplate);
    headers_size += strlen(HEADER_USER_AGENT) + strlen(USER_AGENT);
    headers_size += strlen(HEADER_CONTENT_TYPE) + strlen(HEADER_CONTENT_LENGTH);
    headers_size += strlen(HEADER_ACCEPT) + strlen(ACCEPT_VALUE);
    headers_size += strlen(contentType) + strlen(contentLen) + strlen(accesstokenheader) + 1;
    headers = malloc(headers_size);

    sprintf(headers, normalRequestTemplate, 
            HEADER_USER_AGENT, USER_AGENT,
            accesstokenheader, 
            HEADER_CONTENT_TYPE, contentType, 
            HEADER_ACCEPT, ACCEPT_VALUE,
            HEADER_CONTENT_LENGTH, contentLen);

    if (accesstoken)
    {
        free(accesstokenheader);
    }

    if(body)
    {
        free(contentLen);
    }

    return headers;
}

char *generateCSRBody(char *templateId, char *subjects, char *CSR, int validityPeriodDays)
{
    char *bodytemplate = "{\"template_id\": %s,\"subject\": %s,\"san\":[{\"name\": \"dns\",\"value\": \"wisekeydemo.com\"}], \"csr\": \"%s\" ,\"passphrase\": \"\",\"include_chain_in_pkcs12\": true, \"valid_from\": \"\", \"validity_period\": %d}";

    char csrcpy[strlen(CSR)+1];
    strcpy((char*)&csrcpy,CSR);

    const char *separators = "\r\n";
    char *CSRtreated = malloc(strlen(CSR) + 10);

    memset(CSRtreated, 0, strlen(CSR) + 10);
    char *strseparated = strtok(csrcpy, separators);

    while (strseparated != NULL)
    {
        strcat(CSRtreated, "\\n");
        strcat(CSRtreated, strseparated);
        strseparated = strtok(NULL, separators);
    }

    char *body = malloc(strlen(bodytemplate) + strlen(templateId) + strlen(CSRtreated) + strlen(subjects) + 4 /*validityPeriodDays*/+ 1);
    sprintf(body, bodytemplate, templateId, subjects, CSRtreated, validityPeriodDays);

    if(CSRtreated)
        free(CSRtreated);
    
    return body;
}

char *httpsRequest(char*clientCertPath,char*clientKeyPath,char *host,char* method,char *path, char *headers, char *body)
{

    Handler_https.status=1;
    Handler_https.host=host;

    char* httpMessageTemplate = "%s %s HTTP/1.1\r\nHost: %s\r\n";
    char* response=NULL;
    int message_size;
    
    /* How big is the message? */
    message_size = 0;
    message_size += strlen(httpMessageTemplate);
    message_size += strlen(method); /* method         */
    message_size += strlen(host);
    message_size += strlen(path); /* path           */
    message_size += strlen("\r\n");
    message_size += 4;

    if (headers)
    {
        message_size += strlen(headers);
    }

    if (body)
    {
        message_size += strlen(body);
    }

    /* allocate space for the message */
    Handler_https.message = malloc(message_size);

    sprintf(Handler_https.message, httpMessageTemplate, method,path, host); /*path*/

    if (headers)
    {
        strcat(Handler_https.message, headers);
    }
    
    strcat(Handler_https.message, "\r\n");

    if (body)
    {
        strcat(Handler_https.message, body);
    }
    wkey_log(LOG_DEBUGING," **********  Sended ********** \n%s\n**********  End Sended **********",Handler_https.message);

    if(httpsRequestWolfssl(clientCertPath,clientKeyPath)!=0)
    {
      return NULL;
    }    

    while(1)
    {
        if(Handler_https.status==0)
            break;
    }

    wkey_log(LOG_DEBUGING," **********  Received ********** \n%s\n**********  End Received **********",Handler_https.response);

    if(Handler_https.message)
        free(Handler_https.message);
    
    if(!Handler_https.response || strlen(Handler_https.response)<2)
        return NULL;

    response = malloc(strlen(Handler_https.response)+1);
    strcpy(response,Handler_https.response);
    
    if(Handler_https.response)
        free(Handler_https.response);
    
    return response;
}

char* extractHttpResponseBody(char* response)
{
    char* body=NULL;
    for(int i = 0;i<strlen(response);i++)
    {
        if(response[i]=='\r')
            if(response[i+1]=='\n')
                    if(response[i+2]=='\r')
                        if(response[i+3]=='\n')
                        {
                            body = malloc(strlen(response)+1-i-4);
                            sprintf(body,"%s",response+i+4);
                            break;
                        }
    }
    return body;

}

//INES SDK V1
char *inesApi(char* clientCertPath,char*clientKeyPath,char* host,int protocol,char *pathPrefix, char *inesOrgId,char *accessToken,char* method,char* apiname, char* custom_suffix,char* body,bool useVaultIc,int VaultIcKeyIndex,int VaultIcCertIndex)
{
    Handler_https.use_Vaultic=useVaultIc;
    Handler_https.key_index=VaultIcKeyIndex;
    Handler_https.cert_index=VaultIcCertIndex;

    int api_Str_Size;
    char *response;

    api_Str_Size = strlen("https://")+strlen(host) + strlen(pathPrefix) + strlen(apiname)+ 1;
    
    if(inesOrgId){
        api_Str_Size += strlen(REST_ORGANIZATION_PREFIX);
        api_Str_Size += strlen("/");
        api_Str_Size += strlen(inesOrgId);
    }    
    
    if(custom_suffix){
        api_Str_Size += strlen(custom_suffix);
    }

    char *api = malloc(api_Str_Size);

    sprintf(api,"https://%s%s",host,pathPrefix);

    if(inesOrgId){

        strcat(api,REST_ORGANIZATION_PREFIX);
        strcat(api,"/");
        strcat(api,inesOrgId);
    }

    strcat(api,apiname);

    if(custom_suffix){

        strcat(api,custom_suffix);
    }

    char *headers = generateHttpHeader(host,protocol,api,body, accessToken);

    response = httpsRequest(clientCertPath,clientKeyPath,host, method, api, headers, body);

    if(api)
        free(api);
    if(headers)
        free(headers);
    
    if(!response || (strlen(response)<2))
    {
        wkey_log(LOG_ERROR, "No response from Ines\r\n");
        return NULL;
    }

    if (!strstr(response, "200 OK"))
    {
        wkey_log(LOG_ERROR, "see INES response : \r\n%s",response);
            
        if(response)
            free(response);
        return NULL; 
    }


    return response;    
}
