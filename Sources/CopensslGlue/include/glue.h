#ifndef CopensslGlue
#define CopensslGlue

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"

void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg);
void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names);
GENERAL_NAME *skGeneralNameValue(void *ptr, int i);

#endif
