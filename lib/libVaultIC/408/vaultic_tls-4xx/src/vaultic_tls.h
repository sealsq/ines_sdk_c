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
#define VIC_LOGE(...) printf("\n[VaultIC_TLS] ERROR ");printf(__VA_ARGS__);printf("\n");
#else
#define VIC_LOGE(...) do { } while(0);
#endif

#if(VAULTIC_LOG_LEVEL>=2)
#define VIC_LOGD(...) printf("\n[VaultIC_TLS] DEBUG ");printf(__VA_ARGS__);printf("\n");
#define VIC_LOGD_PRINT_BUFFER(buf, len) PrintHexBuffer((unsigned char*)buf, len);printf("\n");
#else
#define VIC_LOGD(...) do { } while(0);
#define VIC_LOGD_PRINT_BUFFER(buf, len) do { } while(0);
#endif

/* Definition of public constants */
typedef enum {
	SSL_VIC_DEVICE_CERT,
	SSL_VIC_CA_CERT
} ssl_vic_cert_type;

#define P256_BYTE_SZ       32

/* Definition of public functions */
int vlt_tls_init(void);
int vlt_tls_close(void);
int vlt_tls_read_pub_key_P256(int pubKeyIndex,unsigned char pubKeyX[P256_BYTE_SZ], unsigned char pubKeyY[P256_BYTE_SZ]);
int vlt_tls_get_cert_size(ssl_vic_cert_type cert_type);
int vlt_tls_read_cert(unsigned char * cert_buf, ssl_vic_cert_type cert_type);
int vlt_tls_verify_signature_P256(const unsigned char  hash[P256_BYTE_SZ], int hashLen, const unsigned char signature[2*P256_BYTE_SZ], const unsigned char pubKeyX[P256_BYTE_SZ], const unsigned char pubKeyY[P256_BYTE_SZ]);
int vlt_tls_compute_signature_P256(int privKey_index, const unsigned char hash[P256_BYTE_SZ], int hashLen, unsigned char pu8SigR[P256_BYTE_SZ], unsigned char pu8SigS[P256_BYTE_SZ]);
#ifndef VLT_TLS_NO_ECDH
int vlt_tls_keygen_P256(unsigned char pubKeyX[P256_BYTE_SZ] , unsigned char pubKeyY[P256_BYTE_SZ]);
int vlt_tls_compute_shared_secret_P256(const unsigned char pubKeyX[P256_BYTE_SZ] , const unsigned char pubKeyY[P256_BYTE_SZ], unsigned char outSecret[P256_BYTE_SZ]);
#endif
void vlt_tls_left_pad_P256(unsigned char buffer[P256_BYTE_SZ], int len);

#endif /* VLT_TLS_H */