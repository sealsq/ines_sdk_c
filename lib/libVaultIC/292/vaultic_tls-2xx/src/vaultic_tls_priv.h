#ifndef VLT_TLS_PRIV_H
#define VLT_TLS_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

/* Private Constants Definition */

#define MAX_NB_RECS        5     // Max number of records expected in binary area
#define MAX_CERT_SZ        1000  // Max reasonable size for a certificate (used for integrity check)

#define TAG_REC_INFOS      0x80 // tag of records information
#define TAG_CA_CERTIFICATE    0xC0 // tag of CA certificates
#define TAG_END_CERTIFICATE    0xC1 // tag of device certificates

#define CRC_SZ              2   // size of CRC
#define TLV_HEADER_SZ       1+2 // size of Tag | length

#define REC_INFOS_DATA_SZ   1   // size of data stored in record infos

#define BINAREA_HDR_SZ          2
#define BINAREA_FORMAT          0x01
#define BINAREA_VERSION         0x01
#define BINAREA_REC_INFOS_SZ    TLV_HEADER_SZ+REC_INFOS_DATA_SZ

#define OFFSET_FORMAT       0
#define OFFSET_VERSION      1

#define OFFSET_TAG          00
#define OFFSET_LEN          1
#define OFFSET_VAL          3

#define MSB16(x) ((x>>8)&0xFF)
#define LSB16(x) (x&0xFF)
#define INT16(a,b) ((a<<8)+b)

#define CRC_INIT 0x0000

#endif /* VLT_TLS_PRIV_H */
