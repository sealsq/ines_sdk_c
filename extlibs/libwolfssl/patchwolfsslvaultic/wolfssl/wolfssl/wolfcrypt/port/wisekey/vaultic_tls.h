#ifndef VLT_TLS_H
#define VLT_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef VAULTIC_LOG_LEVEL
#define VAULTIC_LOG_LEVEL 0
#endif

#if(VAULTIC_LOG_LEVEL>0)
#include <stdio.h>
#endif

#if(VAULTIC_LOG_LEVEL>=1)
#define VIC_LOGE(...) printf("[VaultIC_TLS] ERROR ");printf(__VA_ARGS__);printf("\n");
#else
#define VIC_LOGE(...) do { } while(0);
#endif

#if(VAULTIC_LOG_LEVEL>=2)
#define VIC_LOGW(...) printf("[VaultIC_TLS] WARNING ");printf(__VA_ARGS__);printf("\n");
#else
#define VIC_LOGW(...) do { } while(0);
#endif

#if(VAULTIC_LOG_LEVEL>=3)
#define VIC_LOGI(...) printf("[VaultIC_TLS] INFO ");printf(__VA_ARGS__);printf("\n");
#else
#define VIC_LOGI(...) do { } while(0);
#endif

#if(VAULTIC_LOG_LEVEL>=4)
#define VIC_LOGV(...) printf("[VaultIC_TLS] DEBUG ");printf(__VA_ARGS__);printf("\n");
#else
#define VIC_LOGV(...) do { } while(0);
#endif

#if(VAULTIC_LOG_LEVEL>=4)
#define VIC_LOG_PRINT_BUFFER(buf, len) PrintHexBuffer((unsigned char*)buf, len);printf("\n");
#else
#define VIC_LOG_PRINT_BUFFER(buf, len) do { } while(0);
#endif

/* Definition of public constants */
typedef enum {
	SSL_VIC_DEVICE_CERT,
	SSL_VIC_CA_CERT
} ssl_vic_cert_type;

#define P256_BYTE_SZ 			32

/* Definition of public functions */
int vlt_tls_init(void);
int vlt_tls_close(void);

int vlt_tls_get_cert_size(ssl_vic_cert_type cert_type);
int vlt_tls_read_cert(unsigned char * cert_buf, ssl_vic_cert_type cert_type);
int vlt_tls_verify_signature_P256(const unsigned char * hash, int hashLen, unsigned char *signature, unsigned char *pubKeyX, unsigned char *pubKeyY);

#ifdef TARGETCHIP_VAULTIC_408
int vlt_tls_compute_signature_P256(int privKey_index, const unsigned char hash[P256_BYTE_SZ], int hashLen, unsigned char pu8SigR[P256_BYTE_SZ], unsigned char pu8SigS[P256_BYTE_SZ]);
#else
int vlt_tls_compute_signature_P256(int keyindex, const unsigned char * pu8Msg, int msgLen, unsigned char *pu8SigR, unsigned char *pu8SigS);
#endif /*TARGETCHIP_VAULTIC_408*/

#ifndef VLT_TLS_NO_ECDH
int vlt_tls_keygen_P256(unsigned char *pubkey_x , unsigned char *pubkey_y);
int vlt_tls_compute_shared_secret_P256(unsigned char *pu8Pubkey_x , unsigned char *pu8Pubkey_y, unsigned char *outSecret);
#endif


#endif /* VLT_TLS_H */
