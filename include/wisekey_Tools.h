/*=======================================
SEAL SQ 2024
INeS SDK
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/*! \file wisekey_Tools.h
    \brief Function needed in order to build requests
*/

#ifndef TOOLS_H
#define TOOLS_H

#include "../extlibs/ini/ini.h"
#include "../extlibs/json/json.h"

#include <stdbool.h>


#ifdef __cplusplus
extern "C"
{
#endif

    /** @brief Ines Protocol to choose
     * 
    */
    enum INES_PROTOCOL
    {
        API_REST = 0,
        API_EST = 1,
    };


    /** @brief Create a device name for registration to IoT Hub.
     *
     * @param config .ini structure
     * @return Device name
     */
    char *createDeviceName(config_values_t config);

    /**
     * @brief Restart ESP32
     */
    void rebootEsp();

    /** @brief Open file and place it in a buffer.
     *
     *  @param path path of file to open.
     *  @return text file in buffer.
     */
    char *openFile(const char *path);

    /** @brief Save the input char* to a file
     *
     *  @param name path/to/file of file to save
     *  @param content Content of the string
     *  @param size size of the string to save
     *  @return status 0 on success
     */
    int writeAndSaveFile(char *name, char *content, int size);

    /** @brief Verify presence of certificate, certificate chain and key
     *
     *  @param config 
     *  @param need_check_key TRUE is you want to verify if private key exit, put false if you only want to verify certificate presence (VAULTIC use for example) 
     *  @return status 0 on success
     */
    int checkCertificateAndKeyDisponibility(config_values_t config, bool need_check_key);

    /** @brief Format the raw certificate sended by REST API Ines into a .pem format char*
     *
     *  @param rawCert output Certificate of Ines REST API Request
     *  @return text file in buffer.
     */
    char *inesRawCartificatetoFormatedcert(char *rawCert);

    /** @brief Format the raw certificate sended by EST API Ines into a .pem format char*
     *
     *  @param rawCert output PKCS7 Certificate of Ines EST API Request
     *  @return text file in buffer.
     */
    char *estRawCartificatetoFormatedcert(char *rawCert);
    
    /** @brief Format a string into a JSON_Value type
     *
     *  @param string to convert
     *  @return json_value type
     */
    json_value* convertStringIntoJsontype(char* string);

    /** @brief This will extract the json value choosen
     * exemple :  
     * "ca": {
        "id": 1,
        "caAlias": "DEVIOTSUBCA1 for CMS",
        "thumbprint": "F3B64C042C73F66B179B4082C773AC3BCDF761A7",
        "serverName": "_name_",
        "caName": "DEVIOTSUBCA1",
        "description": null,
        "certificate": "MIICvzCCAkagAwIBAg...+vSEIw5IfWBds24k="
        },
     * @param value is the json string
     * @param object is the first level object (ca for example)
     * @param object2 is the second level object (id, caAlias, thumbprint ...)
     * @return char* value corresponding, NULL if no value  
     */
    char *extractJsonValue(json_value *value, char *object, char *object2);

    /** @brief This will copy the value corresponding into the struct oject choosen
     * @param structValue struct fiels where to store the value
     * @param value is the json string
     * @param object is the first level object (ca for example)
     * @param object2 is the second level object (id, caAlias, thumbprint ...)
     * @return 0 if success, -1 is case of problem  
     */
    int storeJsonValueIntoStructValue(char **structValue, json_value *value, char *object, char *object2);

    /** @brief Acepted values of wkey_log(...) function
    */
    enum LOG_TYPE
    {
        LOG_INFO = 0,
        LOG_WARNING = 1,
        LOG_ERROR = 2,
        LOG_STEP_INDICATOR = 3,
        LOG_DEBUGING = 4,
        LOG_SUCCESS =5,
    };

    /** @brief Wisekey Log function
     *
     *  @param type LOG_INFO, LOG_WARNING, LOG_ERROR, LOG_STEP_INDICATOR, LOG_SUCCESS and LOG_DEBUGING
     *  @param format String to display
     *  @param ... some further arguments
     */
    void wkey_log(int type, char *format, ...);

     /// @brief Struct to store certificate details when requested from Ines
    typedef struct authentication_t
    {
        char *access_token;
    } authentication_t;


    /// @brief Struct to store certificate details when requested from Ines
    typedef struct CA_details_t
    {
        char *id;
        char *caAlias;
        char *thumbprint;
        char *serverName;
        char *caName;
        char *description;
        char *certificate;
    } CA_details_t;

    /// @brief Struct to store certificate chain when requested from Ines
    typedef struct CA_certificat_chain_detail_t
    {
        char *subject;
        char *issuer;
        char *certificate;
    } CA_certificat_chain_detail_t;

    /// @brief Struct to store certificate chain when requested from Ines
    typedef struct CA_certificat_chain_t
    {
        CA_certificat_chain_detail_t root;
        CA_certificat_chain_detail_t issuing;
    } CA_certificat_chain_t;

    /// @brief Struct to store certificate when requested from Ines
    typedef struct certificate_t
    {
        char *certificate_id;
        char *organization_id;
        char *common_name;
        char *issued_dn;
        char *certificate;
        char *certificate_pkcs12;
        char *passphrase;
        char *status;
        char *issuer;
        char *serial_number;
        char *valid_from;
        char *valid_until;
        char *revocation_reason;
        char *revocation_date;
        char *thumbprint;
        char *san;
    } certificate_t;

    /// @brief Struct to store the status of a certificate when asked from Ines
    typedef struct certificate_status_t
    {
        char *status;
        char *detail;
        char *reason;
        char *revocation_date;
    } certificate_status_t;

    /// @brief Struct to store the status of a certificate template when asked from Ines
    typedef struct certificate_template_t
    {
        char *template_id;
        char *organization_id;
        char *name;
        char *description;
        char *status;
    } certificate_template_t;

    /** @brief Enum to specify the type of struct to fill
     *
     */
    enum INES_STRUCT_TYPE
    {
        INES_RESPONSE_TYPE_CA_DETAILS = 0,
        INES_RESPONSE_TYPE_CA_LIST = 1,
        INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN = 2,
        INES_RESPONSE_TYPE_CERTIFICATE = 3,
        INES_RESPONSE_TYPE_CERTIFICATE_STATUS = 4,
        INES_RESPONSE_TYPE_AUTHENTICATION = 5,
        INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE = 6,
    };

    /** @brief fill the Array with the response from Ines
     *
     *  @param type type of structure to fill, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to fill
     *  @param value Json Value
     */
    void fillArrayList(int type, void*OutputArray, json_value *value);


    /** @brief fill the structure with the response from Ines
     *
     *  @param type type of structure to fill, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to fill
     *  @param value Json Value
     */
    void fillResultStruct(int type, void *input_Struct, json_value *value);

    /** @brief Display the result stored into the choosen structure
     *
     *  @param type type of structure to diplay, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to diplay
     */
    void displayResults(int type, void *input_Struct);

    /** @brief This will execute function to create an ECC key and the CSR with it
     *
     *  @param config Config File to choose
     *  @param CSR pointer to store CSR string
     *  @param subjects pointer to store subjects string
     *  @return 0 if no error
     */
    int generatekeyAndCSR(config_values_t config, char **CSR, char **subjects);

    /** @brief Free the struct
     *
     *  @param type type of structure to free, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to free
     */
    void freeResultStruct(int type, void *input_Struct);

#ifdef __cplusplus
}
#endif

#endif /*TOOLS_H*/
