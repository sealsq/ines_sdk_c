/**
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2017 Wisekey
*
* @note    All products are provided by Wisekey subject to Wisekey Evaluation License Terms and Conditions
* @note    and the provisions of any agreements made between Wisekey and the Customer concerning the same
* @note    subject matter.
* @note    In ordering a product covered by this document the Customer agrees to be bound by those Wisekey's
* @note    Evaluation License Terms and Conditions and agreements and nothing contained in this document
* @note    constitutes or forms part of a contract (with the exception of the contents of this disclaimer notice).
* @note    A copy of Wisekey's Evaluation License Terms and Conditions is available on request. Export of any
* @note    Wisekey product outside of the EU may require an export license.
*
* @note    The information in this document is provided in connection with Wisekey products. No license,
* @note    express or implied, by estoppel or otherwise, to any intellectual property right is granted by this
* @note    document or in connection with the provisions of Wisekey products.
*
* @note    Wisekey makes no representations or warranties with respect to the accuracy or completeness of the
* @note    contents of this document and reserves the right to make changes to specifications and product
* @note    descriptions at any time without notice.
*
* @note    THE PRODUCT AND THE RELATED DOCUMENTATION ARE PROVIDED "AS IS", AND CUSTOMER UNDERSTANDS
* @note    THAT IT ASSUMES ALL RISKS IN RELATION TO ITS USE OF THE PRODUCT AND THE PRODUCT'S
* @note    QUALITY AND PERFORMANCE.
*
* @note    EXCEPT AS SET FORTH IN INSIDE SECURE'S EVALUATION LICENSE TERMS AND CONDITIONS OR IN ANY
* @note    AGREEMENTS MADE BETWEEN WISEKEY AND THE CUSTOMER CONCERNING THE SAME SUBJECT MATTER,
* @note    WISEKEY OR ITS SUPPLIERS OR LICENSORS ASSUME NO LIABILITY WHATSOEVER. CUSTOMER
* @note    AGREES AND ACKNOWLEDGES THAT WISEKEY SHALL HAVE NO RESPONSIBILITIES TO CUSTOMER TO
* @note    CORRECT ANY DEFECTS OR PROBLEMS IN THE PRODUCT OR THE RELATED DOCUMENTATION, OR TO
* @note    ENSURE THAT THE PRODUCT OPERATES PROPERLY.  WISEKEY DISCLAIMS ANY AND ALL WARRANTIES
* @note    WITH RESPECT TO THE PRODUCT AND THE RELATED DOCUMENTATION, WHETHER EXPRESS, STATUTORY
* @note    OR IMPLIED INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTY OF MERCHANTABILITY,
* @note    SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
*
* @note    WISEKEY SHALL HAVE NO LIABILITY WHATSOEVER TO CUSTOMER IN CONNECTION WITH THIS
* @note    WISEKEY'S EVALUATION TERMS AND CONDITIONS, INCLUDING WITHOUT LIMITATION, LIABILITY FOR
* @note    ANY PROBLEMS IN OR CAUSED BY THE PRODUCT OR THE RELATED DOCUMENTATION, WHETHER DIRECT,
* @note    INDIRECT, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, SPECIAL OR INCIDENTAL DAMAGES (INCLUDING,
* @note    WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, LOSS OF REVENUE, BUSINESS INTERRUPTION,
* @note    LOSS OF GOODWILL, OR LOSS OF INFORMATION OR DATA) NOTWITHSTANDING THE THEORY OF
* @note    LIABILITY UNDER WHICH SAID DAMAGES ARE SOUGHT, INCLUDING BUT NOT LIMITED TO CONTRACT,
* @note    TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY, STRICT LIABILITY, STATUTORY LIABILITY OR
* @note    OTHERWISE, EVEN IF WISEKEY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
*
*/

#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_tls.h"
#include "vaultic_tls_priv.h"
#include "vaultic_tls_config.h"
#include <vaultic_crc16.h>
#include <string.h>

#define CHECK_OK(label,a) {	VIC_LOGV(label);\
								int ret_status= (a);\
							 	if (ret_status!= VLT_OK) {VIC_LOGE("%s error %4.4x",label,ret_status);return -1;}\
							}

static int vlt_tls_init_done = FALSE;

static const unsigned char InitialPairingKey[VLT_LEN_PAIRING_KEY] = INITIAL_PAIRING_KEY;
static unsigned char CurrentPairingKey[VLT_LEN_PAIRING_KEY] = INITIAL_PAIRING_KEY;

/** @cond SHOW_INTERNAL */
typedef struct
{
    int tag; // record tag
    int len; // record len
    int data_offset; // offset of data in binary area
} ST_REC;
/** @endcond  */

static int nb_recs;                // number of records in binary area
static ST_REC records[MAX_NB_RECS];
static VLT_PAIRING_MODE pairingMode;
static int StaticPrivKeyIndex=STATIC_KEY_INDEX; // default value for index of static device private key
static int EphemeralPrivKeyIndex= EPH_KEY_KEY_INDEX; // default value for index of ephemeral device private key

static int operationalPrivKeyIndex=VAULTIC_OPERATIONAL_KEY_INDEX; // default value for index of static device private key

/**
 * \brief Returns the record id of known certificates as defined in vaultic_tls_config.h
 *
 * \return -1 in case of error
 */

static int GetCertificateID(ssl_vic_cert_type cert_type)
{
    switch (cert_type)
    {
        case SSL_VIC_CA_CERT:
            return REC_ID_CA_CERT;

        case SSL_VIC_DEVICE_CERT:
            return REC_ID_DEVICE_CERT;
            
        default: 
            return -1;
    }
    return -1;
}

/**
 * \brief Analyzes the binary area, check its format and retrieve the header of the records it contains
 *
 * \return -1 in case of error
 */
static int analyze_bin_area()
{
    unsigned char binarea_header[BINAREA_HDR_SZ];
    unsigned char rec_infos[2];
    unsigned char rec_header[TLV_HEADER_SZ];

    // read header of binary area
    CHECK_OK("VltReadBin binary area header",  VltReadBin( binarea_header, 0, BINAREA_HDR_SZ));

    // check format
    if(binarea_header[OFFSET_FORMAT] != BINAREA_FORMAT)
    {
        VIC_LOGE( "vlt_tls_analyze_bin_area error: Unsupported binary area format" );
        return -1;
    }

    // check version
    if(binarea_header[OFFSET_VERSION] != BINAREA_VERSION)
    {
        VIC_LOGE( "vlt_tls_analyze_bin_area error: Unsupported binary area version" );
        return -1;
    }

    // read number of record 
    int offset = BINAREA_HDR_SZ;
    CHECK_OK("VltReadBin binary area record infos",  VltReadBin( rec_infos, offset, sizeof(rec_infos)));
/*
    if(rec_infos[OFFSET_TAG]!=TAG_REC_INFOS)
    {
        VIC_LOGE( "vlt_tls_analyze_bin_area error: Unexpected tag for record infos" );
        return -1;
    }
	
	

    if(INT16(rec_infos[0],rec_infos[1])!=REC_INFOS_DATA_SZ)
    {
        VIC_LOGE( "vlt_tls_analyze_bin_area error: Unexpected length for record infos" );
        return -1;
    }
	
	*/

    // total number of records stored in binary area
    nb_recs= INT16(rec_infos[0],rec_infos[1]);
    
    VIC_LOGI("Number of records : %2X", nb_recs);
    
    if(nb_recs > MAX_NB_RECS)
    {
        VIC_LOGE( "vlt_tls_analyze_bin_area error: Unexpected value for nb_recs nb_recs=%u", nb_recs);
        return -1;
    }
	
	

    // Point of first record
    offset += sizeof(rec_infos);

    // Get details of each records in binary area
    for (int i=0; i < nb_recs; i++)
    {
        CHECK_OK("VltReadBin binary area record header",  VltReadBin( rec_header, offset, sizeof(rec_header)));

        records[i].tag = rec_header[OFFSET_TAG];
		VIC_LOGI("tags found : %u", records[i].tag)
        records[i].len = INT16(rec_header[OFFSET_LEN], rec_header[OFFSET_LEN+1]);
        offset += TLV_HEADER_SZ;
        records[i].data_offset = offset;
        offset += records[i].len;
		offset += 2; // crc
    }

    return VLT_OK;
 }


static int check_rec_id(int rec_id)
{
    if( (rec_id <=0) || (rec_id > nb_recs) )
    {
        return -1;
    }

    return VLT_OK;
}


/**
 * \brief Get the size of a certificate stored in VaultIC
 *
 * \param[in]  cert_type  type of certificate
 *
 * \return length of the certificate
 * \return -1 in case of error
 */

int vlt_tls_get_cert_size(ssl_vic_cert_type cert_type)
{
    int cert_length;
    int rec_id;

    // check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_get_cert_size error: VaultIC TLS not initialized" );
        return - 1;
    }

    // check rec_id range
    rec_id = GetCertificateID(cert_type);
    if(check_rec_id(rec_id) != VLT_OK) {
        VIC_LOGE("vlt_tls_get_cert_size error: Invalid record id" );
        return - 1;
    }

    rec_id--;

    // check rec_id points on a certificate
    if((records[rec_id].tag != TAG_CA_CERTIFICATE) &&  (records[rec_id].tag != TAG_END_CERTIFICATE)) {
        VIC_LOGE("vlt_tls_get_cert_size error: Invalid record tag :%u",  records[rec_id].tag);
        return - 1;
    }

    // return length of the certificate
    cert_length = records[rec_id].len;
    if (cert_length > MAX_CERT_SZ) {
        VIC_LOGE("vlt_tls_get_cert_size error: Suspicious certificate size" );
        return - 1;
    }

    return cert_length;
}

/**
 * \brief Read a certificate stored in VaultIC
 *
 * \param[out]	cert_buf    buffer to store the certificate
 * \param[in]  cert_type    type of certificate
 *
 * \return 0 in case of success
 * \return -1 in case of error
 */
int vlt_tls_read_cert(unsigned char * cert_buf, ssl_vic_cert_type cert_type)
{
    int offset;
    int cert_size;
    int cert_crc;
    int rec_index;
    unsigned char crc_buff[CRC_SZ];

	VIC_LOGI("vlt_tls_read_cert");
    // read certificate size
    if((cert_size=vlt_tls_get_cert_size(cert_type))==-1)
    {
        VIC_LOGE( "vlt_tls_read_cert error: invalid index" );
        return -1;
    }


    // read certificate
    rec_index = GetCertificateID(cert_type) - 1;
    offset = records[rec_index].data_offset;
	VIC_LOGI("Records data offset : %u", offset);
    CHECK_OK("VltReadBinArea record data",  VltReadBinArea( cert_buf, offset, cert_size));

    offset += cert_size; // jump to crc

    // read crc
    CHECK_OK("VltReadBin record crc",  VltReadBin(crc_buff, offset, sizeof(crc_buff)) );
    cert_crc= INT16(crc_buff[0], crc_buff[1]);

    // compute crc on data received
    VLT_U16 computed_crc = CRC_INIT;
    CHECK_OK("VltCrc16", VltCrc16(&computed_crc, cert_buf, cert_size));    // CRC on DATA bytes received
	
	VIC_LOGI("buffer CRC");
	VIC_LOG_PRINT_BUFFER(cert_buf, cert_size)

    if(cert_crc != computed_crc)
    {
        VIC_LOGE( "vlt_tls_read_cert error: wrong crc" );
        printf("getSize\r\n");
        return -1;

    }

    return 0;
}

/**
 * \brief Read the ECC P256 public key stored in VaultIC
 * \note By default the private key defined by STATIC_KEY_INDEX is used, but can be changed
 *       by calling  vlt_tls_select_static_priv_key() before calling this function
 * \param[out]  pubKeyX  buffer to store the public key part Qx
 * \param[out]  pubKeyY  buffer to store the public key part Qy
 *
 * \return 0 in case of success
 * \return -1 in case of error
 */
int vlt_tls_read_pub_key_P256(unsigned char pubKeyX[P256_BYTE_SZ], unsigned char pubKeyY[P256_BYTE_SZ])
{
	VIC_LOGI("vlt_tls_read_pub_key");
    
    // check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_read_pub_key error: VaultIC TLS not initialized" );
        return - 1;
    }

    CHECK_OK("Read Public Key",
               VltReadPubKey(StaticPrivKeyIndex, pubKeyX, pubKeyY));
    return 0;

}

/**
 * \brief Read the ECC P256 public key stored in VaultIC
 * \note By default the private key defined by STATIC_KEY_INDEX is used, but can be changed
 *       by calling  vlt_tls_select_static_priv_key() before calling this function
 * \param[out]  pubKeyX  buffer to store the public key part Qx
 * \param[out]  pubKeyY  buffer to store the public key part Qy
 *
 * \return 0 in case of success
 * \return -1 in case of error
 */
int vlt_tls_read_operational_pub_key_P256(unsigned char pubKeyX[P256_BYTE_SZ], unsigned char pubKeyY[P256_BYTE_SZ])
{
	VIC_LOGI("vlt_tls_read_operational_pub_key_P256");
    
    // check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_read_pub_key error: VaultIC TLS not initialized" );
        return - 1;
    }

    CHECK_OK("Read Public Key",
               VltReadPubKey(operationalPrivKeyIndex, pubKeyX, pubKeyY));
    return 0;

}

/**
 * \brief Verify an ECC P256 signature using VaultIC
 *
 * \param[in]	hash			hash of input message
 * \param[in]   hashLen     	size of input hash
 * \param[in]   signature   signature to verify
 * \param[in]   pubKeyX    	Public Key (Qx part) used to verify signature
 * \param[in]   pubKeyY    	Public Key (Qy part) used to verify signature
 *
 * \return  0 success
 * \return -1 error
 */
int vlt_tls_verify_signature_P256(const unsigned char hash[P256_BYTE_SZ], int hashLen, const unsigned char signature[2*P256_BYTE_SZ], const unsigned char pubKeyX[P256_BYTE_SZ], const unsigned char pubKeyY[P256_BYTE_SZ])
{
    VIC_LOGI("vlt_tls_verify_signature_P256");

    // Check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_verify_signature_P256 error: VaultIC TLS not initialized" );
        return - 1;
    }

    // Check input hash len
    if(hashLen < P256_BYTE_SZ ) {

        VIC_LOGE("vlt_tls_verify_signature_P256 error: unsupported hash length" );
        return - 1;
    }

    // Verify Signature using input public key
    CHECK_OK("VltVerifySignature",
                VltVerifySignature( 0, KEY_GROUP_NONE, hash, signature, pubKeyX, pubKeyY, CurrentPairingKey));

	return( 0 );
}

/**
 * \brief Verify an ECC P256 signature using VaultIC internal public key
 *    (especially suited for firmware verification)
 *
 * \param[in]   hash            hash of input message
 * \param[in]   hashLen         size of input hash
 * \param[in]   signature       signature to verify
 * \param[in]   pubKeyIndex     Index of public key in VaultIC
 *
 * \return  0 success
 * \return -1 error
 */
int vlt_tls_verify_signature_P256_internal(const unsigned char hash[P256_BYTE_SZ], int hashLen, const unsigned char signature[2*P256_BYTE_SZ], int pubKeyIndex)
{
    VIC_LOGI("vlt_tls_verify_signature_P256_internal");

    // Check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_verify_signature_P256_internal error: VaultIC TLS not initialized" );
        return - 1;
    }

    // Check input hash len
    if(hashLen < P256_BYTE_SZ ) {

        VIC_LOGE("vlt_tls_verify_signature_P256_internal error: unsupported hash length" );
        return - 1;
    }

    // Verify Signature using VaultIC internal public key
    CHECK_OK("VltVerifySignature",
                VltVerifySignature( pubKeyIndex, KEY_GROUP_KEYRING, hash, signature, NULL, NULL, CurrentPairingKey));

    return( 0 );
}


/**
 * \brief Change index of static private key used by vlt_tls_compute_signature_P256
 *
 * \param[in]   key_id          key index in static key ring of VaultIC
 */
void vlt_tls_select_static_priv_key(int key_id)
{
    StaticPrivKeyIndex = key_id;
}

/**
 * \brief Change index of ephemeral private key used by vlt_tls_keygen_P256 and vlt_tls_compute_shared_secret_P256
 *
 * \param[in]   key_id          key index in ephemeral key ring of VaultIC
 */

void vlt_tls_select_ephemeral_priv_key(int key_id)
{
    EphemeralPrivKeyIndex = key_id;
}


/**
 * \brief Compute an ECC P256 signature using VaultIC static private key
 * \note By default the private key defined by STATIC_KEY_INDEX is used, but can be changed
 *       by calling  vlt_tls_select_static_priv_key() before calling this function
 *
 * \param[in]   hash            hash of input message
 * \param[in]   hashLen         size of input hash
 * \param[out]  sigR    		R part of the computed signature
 * \param[out]  sigS    		S part of the computed signature
 *
 * \return  0 success
 * \return -1 error
 */

int vlt_tls_compute_signature_P256(int keyidex,const unsigned char hash[P256_BYTE_SZ], int hashLen, unsigned char sigR[P256_BYTE_SZ], unsigned char sigS[P256_BYTE_SZ])
{
    VLT_U8 au8Signature[2*P256_BYTE_SZ]; //P256 signature r+s = 64 bytes

    VIC_LOGI("vlt_tls_compute_signature_P256");
    
    // Check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_compute_signature_P256 error: VaultIC TLS not initialized" );
        return - 1;
    }

    // Check input hash len
    if(hashLen < P256_BYTE_SZ ) {
        VIC_LOGE("vlt_tls_compute_signature_P256 error: unsupported hash length" );
        return - 1;
    }

    // Generate signature using VaultIC device private key
    CHECK_OK("VltGenerateSignature", VltGenerateSignature ( keyidex, KEY_GROUP_KEYRING, hash, au8Signature));

    // Separate signature components
    host_memcpy(sigR, au8Signature , P256_BYTE_SZ );
    host_memcpy(sigS, au8Signature+P256_BYTE_SZ, P256_BYTE_SZ );

	VIC_LOGV("Hash");
	VIC_LOG_PRINT_BUFFER(hash,hashLen);

	VIC_LOGV("Signature [R]");
	VIC_LOG_PRINT_BUFFER(sigR,P256_BYTE_SZ);

    VIC_LOGV("Signature [S]");
    VIC_LOG_PRINT_BUFFER(sigS,P256_BYTE_SZ);

    return( 0 );
}


/**
 * \brief Generate an ephemeral ECC P256 key pair using VaultIC
 * \note By default the private key defined by EPH_KEY_KEY_INDEX is used, but can be changed
 *       by calling vlt_tls_select_ephemeral_priv_key() before calling this function
 *
 * \param[out]	pubKeyX		Public Key (Qx part)
 * \param[out]	pubKeyY		Public Key (Qy part)

 * \return  0 success
 * \return -1 error
 */
int vlt_tls_keygen_P256(unsigned char pubKeyX[P256_BYTE_SZ] , unsigned char pubKeyY[P256_BYTE_SZ])
{
    VIC_LOGI("vlt_tls_keygen_P256");
    
    // Check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_keygen_P256 error: VaultIC TLS not initialized" );
        return - 1;
    }

    // Generate ephemeral key pair using VaultIC
    CHECK_OK("VltGenEphKeyPair", VltGenEphKeyPair(EphemeralPrivKeyIndex, pubKeyX, pubKeyY));

    return 0;
    }

/**
 * \brief Compute ECDH Shared Secret using VaultIC

 * \note By default the private key defined by EPH_KEY_KEY_INDEX is used, but can be changed
 *       by calling vlt_tls_select_ephemeral_priv_key() before calling this function
 *
 * \pre vlt_tls_keygen_P256 must be executed first
 *
 * \param[in]	pubKeyX		"Other" Public Key (Qx part)
 * \param[in]	pubKeyY		"Other" Public Key (Qy part)
 * \param[out]	outSecret   Computed Shared Secret
 *
 * \return  0 success
 * \return -1 error
 */
int vlt_tls_compute_shared_secret_P256(const unsigned char pubKeyX[P256_BYTE_SZ] , const unsigned char pubKeyY[P256_BYTE_SZ], unsigned char outSecret[P256_BYTE_SZ])
{
	VIC_LOGI("vlt_tls_compute_shared_secret_P256");

    // Check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_compute_shared_secret_P256 error: VaultIC TLS not initialized" );
        return - 1;
    }

    // Compute Shared Secret using VaultIC
    CHECK_OK("VltComputeEcdhSecret", VltComputeEcdhSecret(EphemeralPrivKeyIndex, KEY_GROUP_EPHEMERAL, pubKeyX, pubKeyY, CurrentPairingKey, outSecret));

	VIC_LOGV("PubKeyX (other)");
	VIC_LOG_PRINT_BUFFER(pubKeyX, P256_BYTE_SZ);

	VIC_LOGV("PubKeyY (other)");
	VIC_LOG_PRINT_BUFFER(pubKeyY, P256_BYTE_SZ);

	VIC_LOGV("Shared Secret");
	VIC_LOG_PRINT_BUFFER(outSecret, P256_BYTE_SZ);

	return( 0 );
}


/**
 * \brief Open TLS session with VaultIC

 * \return  0 success
 * \return -1 error
 */
int vlt_tls_init()
{
    printf( "Vault-IC 292 session Init\r\n");
    VLT_TARGET_INFO chipInfo;
    VLT_INIT_COMMS_PARAMS params = { 0 };

    params.VltBlockProtocolParams.u16msSelfTestDelay = SELF_TESTS_DELAY;
    params.VltBlockProtocolParams.u32msTimeout = APDU_TIMEOUT; 

    params.enCommsProtocol = VLT_TWI_COMMS;
    params.VltTwiParams.u16BitRate = I2C_BITRATE;
    params.VltTwiParams.u8Address = I2C_ADDRESS; // I2C address

	VIC_LOGV( "VltApiInit starting");
	if (VltApiInit(&params) != VLT_OK) {
    	VIC_LOGE( "VltApiInit failed");
		return -1;
	}

    VIC_LOGV( "VltApiInit done");

	CHECK_OK("VltGetInfo" , VltGetInfo(&chipInfo));
	pairingMode = chipInfo.enPairingMode;

	CHECK_OK("analyze_bin_area" , analyze_bin_area());

	vlt_tls_init_done = TRUE;
	return 0;
}

/**
 * \brief Close TLS session with VaultIC

 * \return  0 success
 * \return -1 error
 */

int vlt_tls_close()
{
	VIC_LOGI("vlt_tls_close");

	CHECK_OK("VltApiClose", VltApiClose());
	vlt_tls_init_done = FALSE;
	return 0;
}


/**
 * \brief Update pairing key
 *
 * \return  0 success
 * \return -1 error
 */

int vlt_tls_update_pairing()
{
	VIC_LOGI( "vlt_tls_update_pairing");
    
    // check tls init done
    if(vlt_tls_init_done == FALSE) {
        VIC_LOGE("vlt_tls_update_pairing error: VaultIC TLS not initialized" );
        return - 1;
    }

    switch (pairingMode)
    {
        /* compute using current pairing key */
        case VLT_PAIRING_MODE_CURRENT_KEY:
            CHECK_OK("VltUpdatePairing Current", VltUpdatePairing(CurrentPairingKey, CurrentPairingKey));
            break;

        /* compute using initial key */
        case VLT_PAIRING_MODE_REFERENCE_KEY:
            CHECK_OK("VltUpdatePairing Reference", VltUpdatePairing(InitialPairingKey, CurrentPairingKey));
            break;

        default:
            return -1;

    }

    return 0;
}
