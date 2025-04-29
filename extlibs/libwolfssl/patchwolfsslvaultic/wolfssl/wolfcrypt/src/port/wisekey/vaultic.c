
#include <wolfssl/wolfcrypt/settings.h>

#define WOLFSSL_VAULTIC
#define HAVE_PK_CALLBACKS

#ifdef WOLFSSL_VAULTIC

#ifndef HAVE_PK_CALLBACKS
#error Please define HAVE_PK_CALLBACKS in compiling options
#endif 
#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>
#include <wolfssl/wolfcrypt/port/wisekey/vaultic_tls.h>
#ifdef WOLFSSL_VAULTIC_DEBUG
#include <stdio.h>
extern void PrintHexBuffer(unsigned char *pucBuffer, int size);
#define VAULTIC_LOG(...) printf(__VA_ARGS__)
#define VAULTIC_LOG_BUFFER(buffer , size) PrintHexBuffer(buffer , size)
#else
#define VAULTIC_LOG(...) do { } while(0)
#define VAULTIC_LOG_BUFFER(a,b) do { } while(0)
#endif

#define P256_BYTE_SZ 32

#ifndef WOLFSSL_VAULTIC_NO_ECDH

int CurrenVaultickeyIndex=0;
/**
 * \brief Key Gen Callback (used by TLS server)
 */
void set_CurrenVaultickeyIndex(int choosekeyindex)
{
    CurrenVaultickeyIndex=choosekeyindex;
    printf("new key index is =%d",CurrenVaultickeyIndex);
}



/**
 * \brief Key Gen Callback (used by TLS server)
 */
int WOLFSSL_VAULTIC_EccKeyGenCb(WOLFSSL* ssl, ecc_key* key, word32 keySz, int ecc_curve, void* ctx)
{
    int err;
    byte pubKeyX[P256_BYTE_SZ];
    byte pubKeyY[P256_BYTE_SZ];

    (void)ssl;
    (void)ctx;

    VAULTIC_LOG("[WOLFSSL_VAULTIC_EccKeyGenCb]\n");

    /* check requested curve params */
    if( ecc_curve != ECC_SECP256R1 ){
        VAULTIC_LOG("WARNING: ecc_curve != ECC_SECP256R1\n");
        return( NOT_COMPILED_IN );
    }
    if( keySz != P256_BYTE_SZ ){
        VAULTIC_LOG("WARNING: keysize != 32. We are supporting ECC P256 case only\n");
        return( NOT_COMPILED_IN );
    }

    /* generate new ephemeral key on device */
    if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
        VAULTIC_LOG("ERROR: vtls_tls_keygen_P256\n");
        return WC_HW_E;
    }

    /* load generated public key into key, used by wolfSSL */
    if( (err = wc_ecc_import_unsigned(key, pubKeyX, pubKeyY,  NULL, ecc_curve)) != 0) {
        VAULTIC_LOG("ERROR: wc_ecc_import_unsigned\n");
    }

    return err;
}
#endif

/**
 * \brief Verify Certificate Callback.
 *
 */
int WOLFSSL_VAULTIC_EccVerifyCb(WOLFSSL* ssl,
                                const unsigned char* sig, unsigned int sigSz,
                                const unsigned char* hash, unsigned int hashSz,
                                const unsigned char* keyDer, unsigned int keySz,
                                int* result, void* ctx)
{
    int err;
    byte signature[2*P256_BYTE_SZ];
    byte *r, *s;
    word32 r_len = P256_BYTE_SZ, s_len = P256_BYTE_SZ;
    byte pubKeyX[P256_BYTE_SZ];
    byte pubKeyY[P256_BYTE_SZ];
    word32 pubKeyX_len = sizeof(pubKeyX);
    word32 pubKeyY_len = sizeof(pubKeyY);
    ecc_key key;
    word32 inOutIdx = 0;

    VAULTIC_LOG("[WOLFSSL_VAULTIC_EccVerifyCb]\n");

    (void)ssl;
    (void)ctx;
    *result=0;

    if (keyDer == NULL || sig == NULL || hash == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }

    if ( (err = wc_ecc_init(&key)) != 0) {
        VAULTIC_LOG("ERROR: wc_ecc_init\n");
        return err;
    }

    /* Decode the public key */
    if( (err = wc_EccPublicKeyDecode(keyDer, &inOutIdx, &key, keySz)) !=0) {
        VAULTIC_LOG("ERROR: wc_EccPublicKeyDecode\n");
        wc_ecc_free(&key);
        return err;
    }

    /* Extract Raw X and Y coordinates of the public key */
    if( (err = wc_ecc_export_public_raw(&key, pubKeyX, &pubKeyX_len,
        pubKeyY, &pubKeyY_len)) !=0) {
        VAULTIC_LOG("ERROR: wc_ecc_export_public_raw\n");
        wc_ecc_free(&key);
        return err;
    }

    /* Check requested curve */
    if( key.dp->id != ECC_SECP256R1 ){
        VAULTIC_LOG("WARNING: id != ECC_SECP256R1\n");
        wc_ecc_free(&key);
        return NOT_COMPILED_IN ;
    }
        
    /* Extract R and S from signature */
    XMEMSET(signature, 0, sizeof(signature));
    r = &signature[0];
    s = &signature[sizeof(signature)/2];
    err = wc_ecc_sig_to_rs(sig, sigSz, r, &r_len, s, &s_len);
    wc_ecc_free(&key);
    if(err !=0) {
        VAULTIC_LOG("ERROR: wc_ecc_sig_to_rs\n");
    }
        
    /* Verify signature with VaultIC */
    if (vlt_tls_verify_signature_P256(hash, hashSz, signature, pubKeyX, pubKeyY) != 0) {
        VAULTIC_LOG("ERROR: vault_tls_verify_signature_P256\n");
        return WC_HW_E;
    }
    else {
        *result=1;
        return 0;
    }
}


/**
 * \brief Sign Certificate Callback.
 */
int WOLFSSL_VAULTIC_EccSignCb(WOLFSSL* ssl, const byte* in,
                                 word32 inSz, byte* out, word32* outSz,
                                 const byte* key, word32 keySz, void* ctx)
{
    int err;
    (void)ssl;
    (void)ctx;

    byte sig_R[P256_BYTE_SZ];
    byte sig_S[P256_BYTE_SZ];

    VAULTIC_LOG("[WOLFSSL_VAULTIC_EccSignCb]\n");
    printf("key index is =%d",CurrenVaultickeyIndex);

    /* Sign input message using VaultIC */
    #ifdef TARGETCHIP_VAULTIC_408  
    VAULTIC_LOG("[vlt_tls_compute_signature_P256 TARGETCHIP_VAULTIC_408]\n");
    if (vlt_tls_compute_signature_P256(CurrenVaultickeyIndex,in , inSz, sig_R , sig_S) !=0) {
        VAULTIC_LOG("ERROR: vlt_tls_compute_signature_P256 verify Key index of your key is 0x09\n");
        return WC_HW_E;
    }
	#else
	VAULTIC_LOG("[vlt_tls_compute_signature_P256 TARGETCHIP_VAULTIC_292]\n");
    if (vlt_tls_compute_signature_P256(CurrenVaultickeyIndex,in , inSz, sig_R , sig_S) !=0) {
        VAULTIC_LOG("ERROR: vlt_tls_compute_signature_P256\n");
        return WC_HW_E;
    }
	#endif /*TARGETCHIP_VAULTIC_408*/

    /* Convert R and S to signature */
    if( (err=wc_ecc_rs_raw_to_sig(sig_R, P256_BYTE_SZ, sig_S, P256_BYTE_SZ, out, outSz)) != 0) {
        VAULTIC_LOG("ERROR: wc_ecc_rs_raw_to_sig\n");
        return err;
    }

    return err;
}

#ifndef WOLFSSL_VAULTIC_NO_ECDH
/**
 * \brief Create pre master secret using peer's public key and self private key.
 */
int WOLFSSL_VAULTIC_EccSharedSecretCb(WOLFSSL* ssl, ecc_key* otherPubKey,
                              unsigned char* pubKeyDer, unsigned int* pubKeySz,
                              unsigned char* out, unsigned int* outlen,
                              int side, void* ctx)
{
    VAULTIC_LOG("[WOLFSSL_VAULTIC_EccSharedSecretCb]\n");

    int err;
    byte otherPubKeyX[P256_BYTE_SZ];
    byte otherPubKeyY[P256_BYTE_SZ];
    word32 otherPubKeyX_len = sizeof(otherPubKeyX);
    word32 otherPubKeyY_len = sizeof(otherPubKeyY);
    byte pubKeyX[P256_BYTE_SZ];
    byte pubKeyY[P256_BYTE_SZ];

    ecc_key tmpKey;

    (void)ssl;
    (void)ctx;

    /* check requested curve */
    if( otherPubKey->dp->id != ECC_SECP256R1 ){
        VAULTIC_LOG("WARNING: id != ECC_SECP256R1\n");
        return( NOT_COMPILED_IN );
    }

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {

        /* Export otherPubKey raw X and Y */
        err = wc_ecc_export_public_raw(otherPubKey,
            &otherPubKeyX[0], (word32*)&otherPubKeyX_len,
            &otherPubKeyY[0], (word32*)&otherPubKeyY_len);
        if (err != 0) {
            VAULTIC_LOG("ERROR: wc_ecc_export_public_raw\n");
            return err;
        }

        /* TLS v1.2 and older we must generate a key here for the client only.
         * TLS v1.3 calls key gen early with key share */
        if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {

            if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
                VAULTIC_LOG("ERROR: vlt_tls_keygen_P256\n");
                return WC_HW_E;
            }

            /* convert raw unsigned public key to X.963 format for TLS */
            if ( (err = wc_ecc_init(&tmpKey)) != 0) {
                VAULTIC_LOG("ERROR: wc_ecc_init\n");
                return err;
            }            
            
            if( (err = wc_ecc_import_unsigned(&tmpKey, pubKeyX, pubKeyY,
                NULL, ECC_SECP256R1)) != 0) {
                VAULTIC_LOG("ERROR: wc_ecc_import_unsigned\n");
            }                    

            if (err == 0) {
                if( (err = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz)) !=0) {
                    VAULTIC_LOG("ERROR: wc_ecc_import_unsigned\n");
                }
            }                    
                
            wc_ecc_free(&tmpKey);
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        if ( (err = wc_ecc_init(&tmpKey)) != 0) {
            VAULTIC_LOG("ERROR: wc_ecc_init\n");
            return err;
        }            

        /* import peer's key and export as raw unsigned for hardware */
        if( (err = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey, ECC_SECP256R1))!=0) {
            VAULTIC_LOG("ERROR: wc_ecc_import_x963_ex\n");
        }
        
        if (err == 0) {
            if( (err = wc_ecc_export_public_raw(&tmpKey, otherPubKeyX, &otherPubKeyX_len,
                otherPubKeyY, &otherPubKeyY_len)) !=0 ) {
                VAULTIC_LOG("ERROR: wc_ecc_export_public_raw\n");
            }
        }
        wc_ecc_free(&tmpKey);
    }
    else {
        return BAD_FUNC_ARG;
    }

    /* Compute shared secret */
    if (vlt_tls_compute_shared_secret_P256(otherPubKeyX, otherPubKeyY, out)  != 0)  {
        VAULTIC_LOG("ERROR: vlt_tls_compute_shared_secret_P256\n");
        return WC_HW_E;
    }

    *outlen = P256_BYTE_SZ;

    return 0;
}
#endif

/**
 * \brief Read VaultIC Certificates and add them to wolfssl context
 */
int WOLFSSL_VAULTIC_LoadCertificates(WOLFSSL_CTX* ctx, int cert_type) 
{
    int ret = -1;
    
    // Device certificate
    unsigned char *device_cert= NULL;
    int sizeof_device_cert=0;
    
    /* Read Device certificate in VaultIC */
    VAULTIC_LOG("Read Device Certificate in VaultIC at index : %d\n",cert_type);
    if ((sizeof_device_cert = vlt_tls_get_cert_size(cert_type)) == -1) {
        VAULTIC_LOG("ERROR: No Device Certificate found in VaultIC\n");
        return -1;
    }

    device_cert = XMALLOC(sizeof_device_cert, NULL, DYNAMIC_TYPE_ECC_BUFFER);

    if (vlt_tls_read_cert(device_cert, cert_type) !=0 ) {
        VAULTIC_LOG("ERROR: vlt_tls_read_cert Device\n");
        goto free_cert_buffers;
    }

    /* Load Device certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_buffer(ctx, device_cert,
        sizeof_device_cert, WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        VAULTIC_LOG("ERROR: failed to load Device certificate %s",wc_GetErrorString(ret));
        goto free_cert_buffers;
    }
    
    /* VaultIC certificates successfully injected into wolfSSL */
    ret = 0;

free_cert_buffers:
    if(device_cert != NULL) XFREE(device_cert,NULL, DYNAMIC_TYPE_ECC_BUFFER);
    
    return ret;
}


int WOLFSSL_VAULTIC_SetupPkCallbacks(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetEccSignCb(ctx, WOLFSSL_VAULTIC_EccSignCb);
    #ifdef TARGETCHIP_VAULTIC_408 
    /*VIC 292 isn't enought powerfull to verify some signature*/ 
    //wolfSSL_CTX_SetEccVerifyCb(ctx, WOLFSSL_VAULTIC_EccVerifyCb);
    #endif /*TARGETCHIP_VAULTIC_408*/
    
#ifndef WOLFSSL_VAULTIC_NO_ECDH
    wolfSSL_CTX_SetEccKeyGenCb(ctx, WOLFSSL_VAULTIC_EccKeyGenCb);    
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, WOLFSSL_VAULTIC_EccSharedSecretCb);
#endif
    return 0;
}

int WOLFSSL_VAULTIC_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx)
{
#ifndef WOLFSSL_VAULTIC_NO_ECDH
    wolfSSL_SetEccKeyGenCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, user_ctx);
#endif
    wolfSSL_SetEccSignCtx(ssl, user_ctx);
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    return 0;
}

#endif

