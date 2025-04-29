# Wisekey Semiconductors Vaultic 4xx Port

Support for the Vaultic 4XX Secure Element hardware acceleration


## Building

To enable support define the following:

```
#define WOLFSSL_VAULTIC
#define HAVE_PK_CALLBACKS

Additional options:
#define WOLFSSL_VAULTIC_DEBUG -> to display some logs (from callbacks)
#define WOLFSSL_VAULTIC_NO_ECDH -> to let wolfssl handle the key agreement


```

