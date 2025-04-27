#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_identity_authentication.h"
#include "vaultic_file_system.h"
#include "vaultic_tls.h"
#include "vaultic_tls_config.h"
#include <string.h>

#define CHECK_APDU(label,a) {	VIC_LOGD(label);\
								int ret_status= (a);\
							 	if (ret_status!= VLT_OK) {VIC_LOGE("%s error %4.4x",label,ret_status);return -1;}\
							}

static int vlt_read_file( const char *szVicFilePath, VLT_U8 *u8DataBuffer, VLT_U16 u16BufferSize);

static int vlt_api_init_done = FALSE;

static int vlt_read_file( const char *szVicFilePath, VLT_U8 *u8DataBuffer, VLT_U16 u16BufferSize)
{
	VLT_FS_ENTRY_PARAMS  structFileEntry;
	VLT_U32 u32DataLength;

	if (szVicFilePath == NULL )
		return -1;

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_read_file error: VaultIC API not initialized" );
		return -1;
	}

	CHECK_APDU("VltFsOpenFile",VltFsOpenFile(strlen(szVicFilePath), (VLT_PU8) szVicFilePath, FALSE,&structFileEntry) );

	// just return file size if input buffer params are null
	if ((u8DataBuffer == NULL) && (u16BufferSize ==0)) {
		CHECK_APDU("VltFsCloseFile",VltFsCloseFile());
		return structFileEntry.u32FileSize;
	}

	// check input buffer pointer
	if (u8DataBuffer == NULL) return -1;

	// check input buffer size
	u32DataLength = structFileEntry.u32FileSize;
	if(u32DataLength >u16BufferSize) return -1;

	CHECK_APDU("VltFsReadFile",VltFsReadFile( VLT_SEEK_FROM_START, u8DataBuffer, &u32DataLength ));

	CHECK_APDU("VltFsCloseFile",VltFsCloseFile());

	return u32DataLength;
}

/**
 * \brief Get the size of a certificate stored in VaultIC
 *
 * \param[in]	cert_type		type of certificate to be read
 *
 * \return length of the certificate
 * \return -1 in case of error
 */
int vlt_tls_get_cert_size(ssl_vic_cert_type cert_type)
{
	return vlt_tls_read_cert(NULL, cert_type);
}

/**
 * \brief Read a certificate stored in VaultIC
 *
 * \param[out]	cert_buf		buffer to store the certificate
 * \param[in]	cert_type		type of certificate to be read
 *
 * \return 0 in case of success
 * \return -1 in case of error
 */
int vlt_tls_read_cert(unsigned char * cert_buf, ssl_vic_cert_type cert_type)
{
	int cert_size;
	char szVicFilePath[100];

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE( "vlt_tls_read_cert error: VaultIC API not initialized" );
		return -1;
	}

	strcpy(szVicFilePath, CERTS_DIR_PATH);

	switch(cert_type) {
		case SSL_VIC_DEVICE_CERT:
			strcat(szVicFilePath, DEVICE_CERT_NAME);
			break;

		case SSL_VIC_CA_CERT:
			strcat(szVicFilePath, CA_CERT_NAME);
			break;

		default:
			VIC_LOGE("vlt_tls_read_cert error: Unexpected certificate type");
			return -1;
	}

	// read certificate size in vaultic
	if ((cert_size = vlt_read_file(szVicFilePath, NULL, 0)) < 0){
		VIC_LOGE("vlt_tls_read_cert size error ");
		return -1;
	}

	// just return certificate size if buffer pointer is null
	if (NULL == cert_buf)
	{
		return cert_size;
	}

	VIC_LOGD("vlt_tls_read_cert");

	// read certificate in vaultic
	if ( vlt_read_file(szVicFilePath, cert_buf, cert_size) < 0){
		VIC_LOGE("vlt_tls_read_cert error ");
		return -1;
	}

	// log certificate read in vaultic
	VIC_LOGD("%s certificate read in VaultIC",szVicFilePath);
	VIC_LOGD_PRINT_BUFFER(cert_buf,cert_size);

	return 0;
}

/**
 * \brief Verify an ECC P256 signature using VaultIC
 *
 * \param[in]   hash        hash of input message
 * \param[in]   hashLen     size of input hash
 * \param[in]   signature   signature to verify
 * \param[in]   pubKeyX     Public Key (Qx part) used to verify signature
 * \param[in]   pubKeyY     Public Key (Qy part) used to verify signature
 *
 * \return  0 success
 * \return -1 error
 */
int vlt_tls_verify_signature_P256(const unsigned char  hash[P256_BYTE_SZ], int hashLen, const unsigned char signature[2*P256_BYTE_SZ], const unsigned char pubKeyX[P256_BYTE_SZ], const unsigned char pubKeyY[P256_BYTE_SZ])
{
	VLT_FILE_PRIVILEGES ECDSApubKeyPrivileges = {0};
	VLT_KEY_OBJECT ECDSArmPubKEy;
	VLT_ALGO_PARAMS strctAlgoParms;

	VIC_LOGD("vlt_tls_verify_signature_P256 (using VaultIC)");

	VIC_LOGD("Hash");
	VIC_LOGD_PRINT_BUFFER(hash,hashLen);

	VIC_LOGD("Signature");
	VIC_LOGD_PRINT_BUFFER(signature,2*P256_BYTE_SZ);

	VIC_LOGD("PubKeyX");
	VIC_LOGD_PRINT_BUFFER(pubKeyX,P256_BYTE_SZ);

	VIC_LOGD("PubKeyY");
	VIC_LOGD_PRINT_BUFFER(pubKeyY,P256_BYTE_SZ);

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_tls_verify_signature_P256 error: VaultIC API not initialized" );
		return( -1 );
	}

	if( (hash==NULL) || (signature==NULL) || (pubKeyX==NULL) || (pubKeyY==NULL)) {
		VIC_LOGE("vlt_tls_verify_signature_P256 error: Invalid input params" );
		return -1;
	}

	VIC_LOGD("VltDeleteKey RPK (Temporary Public Key)");
	VltDeleteKey(ECC_RPK_Group,ECC_RPK_Pubk_Index);

    ECDSApubKeyPrivileges.u8Read = TEMP_KEY_READ_AC;
    ECDSApubKeyPrivileges.u8Write = TEMP_KEY_WRITE_AC;
    ECDSApubKeyPrivileges.u8Delete = TEMP_KEY_DEL_AC;
    ECDSApubKeyPrivileges.u8Execute = TEMP_KEY_EXEC_AC;
    
    VLT_U8 au8Qx[P256_BYTE_SZ];
    VLT_U8 au8Qy[P256_BYTE_SZ];
    host_memcpy(au8Qx, pubKeyX, P256_BYTE_SZ);
    host_memcpy(au8Qy, pubKeyY, P256_BYTE_SZ);
    
	ECDSArmPubKEy.enKeyID = VLT_KEY_ECC_PUB;
	ECDSArmPubKEy.data.EcdsaPubKey.u16QLen = P256_BYTE_SZ;
	ECDSArmPubKEy.data.EcdsaPubKey.pu8Qx = au8Qx;
	ECDSArmPubKEy.data.EcdsaPubKey.pu8Qy = au8Qy;
	ECDSArmPubKEy.data.EcdsaPubKey.u8DomainParamsGroup = ECC_P256_Para_Group;
	ECDSArmPubKEy.data.EcdsaPubKey.u8DomainParamsIndex = ECC_P256_Para_Index;
	ECDSArmPubKEy.data.EcdsaPubKey.enAssurance = 0;
	CHECK_APDU("VltPutKey RPK (Temporary Public Key)", VltPutKey(ECC_RPK_Group,ECC_RPK_Pubk_Index,&ECDSApubKeyPrivileges,&ECDSArmPubKEy));

	strctAlgoParms.u8AlgoID = VLT_ALG_SIG_ECDSA_GFP;

	switch( hashLen )
    {
		case 32:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA256+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA256");
            break;
		case 48:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA384+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA384");
            break;
		case 64:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA512+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA512");
            break;

		default:
			return -1;
            break;
	}

	CHECK_APDU("VltInitializeAlgorithm Temporary Public Key / Verify Signature",
				VltInitializeAlgorithm(
					ECC_RPK_Group,
					ECC_RPK_Pubk_Index,
					VLT_VERIFY_MODE,
					&strctAlgoParms) );

	CHECK_APDU("VltVerifySignature",
				VltVerifySignature( hashLen, hash, 2*P256_BYTE_SZ, signature) );

	VIC_LOGD("VltVerifySignature success");

	return( 0 );
}

/**
 * \brief Compute an ECC P256 signature using VaultIC static private key
 *
 * \param[in]	pu8Msg			input message
 * \param[in]   msgLen     		size of input message
 * \param[out]  pu8SigR    		R part of the computed signature
 * \param[out]  pu8SigS    		S part of the computed signature
 *
 * \return  0 success
 * \return -1 error
 */

int vlt_tls_compute_signature_P256(int privKeyIndex,const unsigned char * pu8Msg, int msgLen, unsigned char *pu8SigR, unsigned char *pu8SigS)
{
	VLT_U8 au8Signature[2*P256_BYTE_SZ]; //P256 signature r+s = 64 bytes
	VLT_U16 u16SignatureLen;
	VLT_ALGO_PARAMS strctAlgoParms;

	VIC_LOGD("vlt_tls_compute_signature_P256 (using VaultIC 408)");

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_tls_compute_signature_P256 error: VaultIC API not initialized" );
		return - 1;
	}

	if( (pu8Msg==NULL) || (pu8SigR==NULL) || (pu8SigS==NULL)) {
		VIC_LOGE("vlt_tls_compute_signature_P256 error: Invalid input params" );
		return -1;
	}

	strctAlgoParms.u8AlgoID = VLT_ALG_SIG_ECDSA_GFP;

	switch( msgLen )
    {
		case 32:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA256+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA256");
            break;
		case 48:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA384+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA384");
            break;
		case 64:
			strctAlgoParms.data.EcdsaDsa.enDigestId = (VLT_ALG_DIG_SHA512+ 0x80);
			VIC_LOGD("Digest =  VLT_ALG_DIG_SHA512");
            break;

		default:
			VIC_LOGD("raw message input length 0x%zx. Apply with default SHA256. \n", msgLen );
			strctAlgoParms.data.EcdsaDsa.enDigestId = VLT_ALG_DIG_SHA256;
            break;
	}

	CHECK_APDU("VltInitializeAlgorithm Sign with Device Private Key",
				VltInitializeAlgorithm(
					ECC_EK_Group,
					privKeyIndex,
					VLT_SIGN_MODE,
					&strctAlgoParms) );

	CHECK_APDU("VltGenerateSignature",  VltGenerateSignature( msgLen, pu8Msg, &u16SignatureLen, sizeof(au8Signature),au8Signature) );

	host_memcpy(pu8SigR, au8Signature , P256_BYTE_SZ );
	host_memcpy(pu8SigS, au8Signature+P256_BYTE_SZ, P256_BYTE_SZ );

	VIC_LOGD("Hash");
	VIC_LOGD_PRINT_BUFFER(pu8Msg,msgLen);

	VIC_LOGD("Signature");
	VIC_LOGD_PRINT_BUFFER(au8Signature,2*P256_BYTE_SZ);

    return( 0 );
}

#ifndef VLT_TLS_NO_ECDH

/**
 * \brief Generate an ECC P256 key pair using VaultIC
 *
 * \param[out]	pubkey_x		Public Key (Qx part)
 * \param[out]	pubkey_y		Public Key (Qy part)

 * \return  0 success
 * \return -1 error
 */
int vlt_tls_keygen_P256(unsigned char *pubkey_x , unsigned char *pubkey_y)
{
	VLT_FILE_PRIVILEGES ECDHpubKeyPrivileges = {0};
	VLT_FILE_PRIVILEGES ECDHpriKeyPrivileges = {0};
	VLT_KEY_GEN_DATA pECCKeyGenData;
	VLT_KEY_OBJECT ECDHpubKEy;

	VIC_LOGD("vlt_tls_keygen_P256");

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_tls_keygen_P256 error: VaultIC API not initialized" );
		return -1;
	}

	if( (pubkey_x==NULL) || (pubkey_y==NULL) ) {
		VIC_LOGE("vlt_tls_keygen_P256 error: Invalid input params" );
		return -1;
	}

	ECDHpubKeyPrivileges.u8Read = TEMP_KEY_READ_AC;
    ECDHpubKeyPrivileges.u8Write = TEMP_KEY_WRITE_AC;
    ECDHpubKeyPrivileges.u8Delete = TEMP_KEY_DEL_AC;
    ECDHpubKeyPrivileges.u8Execute = TEMP_KEY_EXEC_AC;

	ECDHpriKeyPrivileges.u8Read = 0x00; // Never
    ECDHpriKeyPrivileges.u8Write = TEMP_KEY_WRITE_AC;
    ECDHpriKeyPrivileges.u8Delete = TEMP_KEY_DEL_AC;
    ECDHpriKeyPrivileges.u8Execute = TEMP_KEY_EXEC_AC;

    //Delete the target key pair group/index to make sure it is clean
    VIC_LOGD("VltDeleteKey ECDH_KG Priv (Generated Key Pair)");
    VltDeleteKey(ECDH_KG_Group,(ECDH_KG_Pubk_Index + 1));  //priv = pub + 1

    VIC_LOGD("VltDeleteKey ECDH_KG Pub (Generated Key Pair)");
    VltDeleteKey(ECDH_KG_Group,ECDH_KG_Pubk_Index);

    //
	// Step 2 : generate ECDSA key pair then read the public key out

	pECCKeyGenData.enAlgoID = VLT_ALG_KPG_ECDSA_GFP;
	pECCKeyGenData.data.EcdsaDsaKeyGenObj.u8DomainParamsGroup = ECC_P256_Para_Group;
	pECCKeyGenData.data.EcdsaDsaKeyGenObj.u8DomainParamsIndex = ECC_P256_Para_Index;

	CHECK_APDU("VltGenerateKeyPair", VltGenerateKeyPair(ECDH_KG_Group,ECDH_KG_Pubk_Index,&ECDHpubKeyPrivileges,ECDH_KG_Group,(ECDH_KG_Pubk_Index + 1),&ECDHpriKeyPrivileges,&pECCKeyGenData ) );

	ECDHpubKEy.enKeyID = VLT_KEY_ECC_PUB;
	ECDHpubKEy.data.EcdsaPubKey.u16QLen = P256_BYTE_SZ;
	ECDHpubKEy.data.EcdsaPubKey.pu8Qx = pubkey_x;
	ECDHpubKEy.data.EcdsaPubKey.pu8Qy = pubkey_y;
	CHECK_APDU("VltReadKey" , VltReadKey(ECDH_KG_Group,ECDH_KG_Pubk_Index,&ECDHpubKEy));

	VIC_LOGD("PubKeyX (VaultIC)");
	VIC_LOGD_PRINT_BUFFER(pubkey_x,P256_BYTE_SZ);

	VIC_LOGD("PubKeyY (VaultIC)");
	VIC_LOGD_PRINT_BUFFER(pubkey_y,P256_BYTE_SZ);

    return( 0 );
}

/**
 * \brief Compute ECDH Shared Secret using VaultIC
 * \note vlt_tls_keygen_P256 must be executed first
 *
 * \param[in]	pubKeyX		"Other" Public Key (Qx part)
 * \param[in]	pubKeyY		"Other" Public Key (Qy part)
 * \param[out]	outSecret		Shared Secret computed
 *
 * \return  0 success
 * \return -1 error
 */
int vlt_tls_compute_shared_secret_P256(const unsigned char pubKeyX[P256_BYTE_SZ] , const unsigned char pubKeyY[P256_BYTE_SZ], unsigned char outSecret[P256_BYTE_SZ])
{
	VLT_FILE_PRIVILEGES ECDHpubKeyPrivileges = {0};
	VLT_KEY_OBJECT ECDHrmPubKEy;
	VLT_KEY_MATERIAL keyMaterial;
	VLT_FILE_PRIVILEGES DHAgreementAccess;
	VLT_KEY_OBJECT dhKeyObj;

	VIC_LOGD("vlt_tls_compute_shared_secret_P256 (using VaultIC 408)");

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_tls_ecdh_compute_shared error: VaultIC API not initialized" );
		return -1;
	}

	if( (pubKeyX==NULL) || (pubKeyY==NULL) || (outSecret==NULL) ) {
		VIC_LOGE("vlt_tls_ecdh_compute_shared error: Invalid input params" );
		return -1;
	}

	VIC_LOGD("VltDeleteKey ECDH_KGrm Pub");
	VltDeleteKey(ECDH_KGrm_Group,ECDH_KGrm_Pubk_Index);

	ECDHpubKeyPrivileges.u8Read = TEMP_KEY_READ_AC;
    ECDHpubKeyPrivileges.u8Write = TEMP_KEY_WRITE_AC;
    ECDHpubKeyPrivileges.u8Delete = TEMP_KEY_DEL_AC;
    ECDHpubKeyPrivileges.u8Execute = TEMP_KEY_EXEC_AC;

	ECDHrmPubKEy.enKeyID = VLT_KEY_ECC_PUB;

    VLT_U8 au8Qx[P256_BYTE_SZ];
    VLT_U8 au8Qy[P256_BYTE_SZ];
    host_memcpy(au8Qx, pubKeyX, P256_BYTE_SZ);
    host_memcpy(au8Qy, pubKeyY, P256_BYTE_SZ);

	ECDHrmPubKEy.data.EcdsaPubKey.u16QLen = P256_BYTE_SZ;
	ECDHrmPubKEy.data.EcdsaPubKey.pu8Qx = au8Qx;
	ECDHrmPubKEy.data.EcdsaPubKey.pu8Qy = au8Qy;
	ECDHrmPubKEy.data.EcdsaPubKey.u8DomainParamsGroup = ECC_P256_Para_Group;
	ECDHrmPubKEy.data.EcdsaPubKey.u8DomainParamsIndex = ECC_P256_Para_Index;
	ECDHrmPubKEy.data.EcdsaPubKey.enAssurance = VLT_PKV_NON_UNASSURED;
	CHECK_APDU("VltPutKey ECDH_KGrm Pub" , VltPutKey(ECDH_KGrm_Group,ECDH_KGrm_Pubk_Index,&ECDHpubKeyPrivileges,&ECDHrmPubKEy));

	keyMaterial.enAlgoID = VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GFp;
	keyMaterial.u8StaticResponderPrivKeyGroup = ECDH_KG_Group;
	keyMaterial.u8StaticResponderPrivKeyIndex = (ECDH_KG_Pubk_Index + 1);
	keyMaterial.data.staticUnified.u8InitiatorPubKeyGroup = ECDH_KGrm_Group;
	keyMaterial.data.staticUnified.u8InitiatorPubKeyIndex = ECDH_KGrm_Pubk_Index;

	DHAgreementAccess.u8Read = TEMP_KEY_READ_AC;
	DHAgreementAccess.u8Write = TEMP_KEY_WRITE_AC;
	DHAgreementAccess.u8Delete = TEMP_KEY_DEL_AC;
	DHAgreementAccess.u8Execute = TEMP_KEY_EXEC_AC;

	VIC_LOGD("VltDeleteKey ECDH Shared Secret");
	VltDeleteKey(ECDH_Share_Group,ECDH_Share_Index);

	CHECK_APDU("Construct DH agreement" , VltConstructDHAgreement(ECDH_Share_Group,ECDH_Share_Index,&DHAgreementAccess,&keyMaterial) ) ;

	//Read DH Agreement key
	//---------------------------------------------------------------------

	dhKeyObj.enKeyID = VLT_KEY_SECRET_VALUE;
	dhKeyObj.data.SecretKey.u16KeyLength = P256_BYTE_SZ;
	dhKeyObj.data.SecretKey.pu8Key = outSecret;

	dhKeyObj.data.SecretKey.u8Mask = 0x00;
	CHECK_APDU ("VltReadKey ECDH Shared Secret" , VltReadKey(ECDH_Share_Group,ECDH_Share_Index,&dhKeyObj));

	VIC_LOGD("PubKeyX (other)");
	VIC_LOGD_PRINT_BUFFER(pubKeyX, P256_BYTE_SZ);

	VIC_LOGD("PubKeyY (other)");
	VIC_LOGD_PRINT_BUFFER(pubKeyY, P256_BYTE_SZ);

	VIC_LOGD("Shared Secret");
	VIC_LOGD_PRINT_BUFFER(outSecret, P256_BYTE_SZ);

	return( 0 );
}

#endif // VLT_TLS_NO_ECDH



/**
 * \brief Read an ECC P256 public key in VaultIC
 *
 * \param[out]  pubKeyIndex		Public Key to choose
 * \param[out]	pubkey_x		Public Key (Qx part)
 * \param[out]	pubkey_y		Public Key (Qy part)

 * \return  0 success
 * \return -1 error
 */
int vlt_tls_read_pub_key_P256(int pubKeyIndex,unsigned char pubkey_x[P256_BYTE_SZ] , unsigned char pubkey_y[P256_BYTE_SZ])
{
	VLT_KEY_OBJECT structKeyObj={0};
    
    VIC_LOGD("vlt_tls_read_pub_key_P256");

	if(vlt_api_init_done == FALSE) {
		VIC_LOGE("vlt_tls_read_pub_key_P256 error: VaultIC API not initialized" );
		return -1;
	}

	if( (pubkey_x==NULL) || (pubkey_y==NULL) ) {
		VIC_LOGE("vlt_tls_read_pub_key_P256 error: Invalid input params" );
		return -1;
	}

	structKeyObj.enKeyID = VLT_KEY_ECC_PUB;
	structKeyObj.data.EcdsaPubKey.u16QLen = P256_BYTE_SZ;
	structKeyObj.data.EcdsaPubKey.pu8Qx = pubkey_x;
	structKeyObj.data.EcdsaPubKey.pu8Qy = pubkey_y;
	structKeyObj.data.EcdsaPubKey.u8DomainParamsGroup = ECC_P256_Para_Group;
	structKeyObj.data.EcdsaPubKey.u8DomainParamsIndex = ECC_P256_Para_Index;
    
    CHECK_APDU("VltReadKey", VltReadKey(ECC_EK_Group,pubKeyIndex,&structKeyObj ));
    
	VIC_LOGD("PubKeyX (VaultIC)");
	VIC_LOGD_PRINT_BUFFER(pubkey_x,P256_BYTE_SZ);

	VIC_LOGD("PubKeyY (VaultIC)");
	VIC_LOGD_PRINT_BUFFER(pubkey_y,P256_BYTE_SZ);

	return 0;
}

/**
 * \brief Open TLS session with VaultIC

 * \return  0 success
 * \return -1 error
 */
int vlt_tls_init()
{
    VLT_INIT_COMMS_PARAMS params = { 0 };
    VLT_TARGET_INFO chipInfo;

	VIC_LOGD( "vlt_tls_init 408");

    params.VltBlockProtocolParams.u16msSelfTestDelay = SELF_TESTS_DELAY;
    params.VltBlockProtocolParams.u32msTimeout = APDU_TIMEOUT; 

#ifdef USE_TWI
    params.enCommsProtocol = VLT_TWI_COMMS;
    params.VltTwiParams.u16BitRate = I2C_BITRATE;
    params.VltTwiParams.u8Address = I2C_ADDRESS; // I2C address
#endif
#ifdef USE_SPI
	params.enCommsProtocol = VLT_SPI_COMMS;
	params.VltSpiParams.u16BitRate = SPI_BITRATE;
#endif

	VIC_LOGD( "VltApiInit starting");
	if (VltApiInit(&params) != VLT_OK) {
    	VIC_LOGE( "VltApiInit failed");
		return -1;
	}

    VIC_LOGD( "VltApiInit done");

    if (VltGetInfo(&chipInfo) != VLT_OK) {
        // First Get Info can fail with a 6988 if the secure channel was not closed properly
        // In that case we just need to resend the command (as the 6988 will have closed the channel)
        CHECK_APDU("VltGetInfo" , VltGetInfo(&chipInfo));
    }

if (chipInfo.enRole == VLT_EVERYONE) {
	// User not authenticated
#ifdef USE_SEC_CHANNEL
    // Authenticate User 1 with SCP03
    unsigned char aucS_MacStaticKey[]= SMAC_KEY;
    unsigned char aucS_EncStaticKey[]= SENC_KEY;

    KEY_BLOB kblMacStatic;
    kblMacStatic.keyType = VLT_KEY_AES_128;
    kblMacStatic.keySize = sizeof(aucS_MacStaticKey);
    kblMacStatic.keyValue = aucS_MacStaticKey;

    KEY_BLOB kblEncStatic;
    kblEncStatic.keyType = VLT_KEY_AES_128;
    kblEncStatic.keySize = sizeof(aucS_EncStaticKey);
    kblEncStatic.keyValue = aucS_EncStaticKey;

    KEY_BLOB_ARRAY theKeyBlobs = { 0 };
    theKeyBlobs.u8ArraySize = 2;
    theKeyBlobs.pKeys[0] = &kblMacStatic;
    theKeyBlobs.pKeys[1] = &kblEncStatic;

    CHECK_APDU("VltAuthInit TLS User", VltAuthInit(
        VLT_AUTH_SCP03,
        TLS_USER_ID,
		VLT_NON_APPROVED_USER,
        VLT_CMAC_CENC_RMAC_RENC,
        theKeyBlobs ) ) ;
#else
    // Authenticate User 0 with password
	VLT_U8 u8UserPassword[20];
	host_memset(u8UserPassword, 0x00, 20);
	host_memcpy(u8UserPassword, (VLT_PU8) TLS_USER_PIN, TLS_USER_PIN_LEN);

	CHECK_APDU("VltSubmitPassword TLS User",VltSubmitPassword(TLS_USER_ID,VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword));
#endif
	}
	vlt_api_init_done = TRUE;
	return 0;
}

/**
 * \brief Close TLS session with VaultIC

 * \return  0 success
 * \return -1 error
 */

int vlt_tls_close()
{
	VIC_LOGD("vlt_tls_close");
	VltAuthClose();
	CHECK_APDU("VltApiClose", VltApiClose());
	vlt_api_init_done = FALSE;
	return 0;
}

/**
 * \brief Left pad a 256 bit buffer with 00s
 */
void vlt_tls_left_pad_P256(unsigned char buffer[P256_BYTE_SZ], int len)
{
    uint8_t u8BufTemp[P256_BYTE_SZ]={0};
    uint32_t u32NbPaddingBytes=P256_BYTE_SZ-len;
    
    host_memset(u8BufTemp, 0, u32NbPaddingBytes);
    host_memcpy(u8BufTemp + u32NbPaddingBytes, buffer, len);
    host_memcpy(buffer, u8BufTemp, P256_BYTE_SZ);
}
