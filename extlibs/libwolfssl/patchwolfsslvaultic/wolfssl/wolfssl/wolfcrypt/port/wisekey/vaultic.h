#ifndef _WOLFPORT_VAULTIC_H_
#define _WOLFPORT_VAULTIC_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>

void set_CurrenVaultickeyIndex(int choosekeyindex);

int WOLFSSL_VAULTIC_EccKeyGenCb(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx);

int WOLFSSL_VAULTIC_EccVerifyCb(WOLFSSL* ssl,
   const unsigned char* sig, unsigned int sigSz,
   const unsigned char* hash, unsigned int hashSz,
   const unsigned char* keyDer, unsigned int keySz,
   int* result, void* ctx);

int WOLFSSL_VAULTIC_EccSignCb(WOLFSSL* ssl,
    const byte* in, word32 inSz,
    byte* out, word32* outSz,
    const byte* key, word32 keySz, void* ctx);

int WOLFSSL_VAULTIC_EccSharedSecretCb(WOLFSSL* ssl,
    ecc_key* otherKey,
    unsigned char* pubKeyDer, unsigned int* pubKeySz,
    unsigned char* out, unsigned int* outlen,
    int side, void* ctx);
    
int WOLFSSL_VAULTIC_LoadCertificates(WOLFSSL_CTX* ctx, int cert_type); 

/* Helper API's for setting up callbacks */
int WOLFSSL_VAULTIC_SetupPkCallbacks(WOLFSSL_CTX* ctx);
int WOLFSSL_VAULTIC_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx);

#endif /* _WOLFPORT_VAULTIC_H_ */
