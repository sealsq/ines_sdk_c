#ifndef VLT_TLS_CONFIG_H
#define VLT_TLS_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* VaultIC configuration */
#define USE_SEC_CHANNEL	/* encryption of communication with VaultIC */

#define SELF_TESTS_DELAY 		700 // 0.7s VaultIC boot starting delay

/* Definition of VaultIC resources */
#ifdef USE_SPI
#define SPI_BITRATE		5000	//5Mhz
#endif

#ifdef USE_TWI
#define I2C_BITRATE		400		//400kHz
#define I2C_ADDRESS		0x5F
#endif

#define APDU_TIMEOUT	 		5000 // 5s
#define CERTS_DIR_PATH			"/"
#define DEVICE_CERT_NAME		"cer"
#define CA_CERT_NAME	    	"cacer"

#ifdef USE_SEC_CHANNEL
#define TLS_USER_ID 			VLT_USER1
#define SMAC_KEY { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
#define SENC_KEY { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
#else
#define TLS_USER_ID 			VLT_USER0
#define TLS_USER_PIN			"\0\0\0\0"
#define TLS_USER_PIN_LEN		4
#endif

//Device public key
#define ECC_EK_Group 			0xEC
#define ECC_EK_Pubk_Index 		0x07
#define ECC_EK_Privk_Index 		0x08

#define ECC_FACTORY_Privk_Index 		0x09
#define ECC_FACTORY_Pubk_Index 		0x0A

#define ECC_OPERATIONAL_Privk_Index 		0x0B
#define ECC_OPERATIONAL_Pubk_Index 		0x0C

//Temporary Key for Signature verification
#define	ECC_RPK_Group 			0xFF
#define	ECC_RPK_Pubk_Index 		0x07

//ECDH Device Public Key
#define ECDH_KG_Group 			0xAA
#define ECDH_KG_Pubk_Index 		0x22

//"Other" Public key
#define ECDH_KGrm_Group 		0xFF
#define ECDH_KGrm_Pubk_Index 	0x27

//ECDH Shared Secret
#define ECDH_Share_Group 		0xFF
#define ECDH_Share_Index 		0x33

//P256 parameters
#define ECC_P256_Para_Group 	0xE0
#define ECC_P256_Para_Index 	0x01

// Access Conditions of temporary keys
#define TEMP_KEY_READ_AC 	(1<<TLS_USER_ID)
#define TEMP_KEY_WRITE_AC 	(1<<TLS_USER_ID)
#define TEMP_KEY_DEL_AC 	(1<<TLS_USER_ID)
#define TEMP_KEY_EXEC_AC 	(1<<TLS_USER_ID)


#endif /* VLT_TLS_CONFIG_H */
