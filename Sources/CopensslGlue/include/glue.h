#ifndef CopensslGlue
#define CopensslGlue

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"

void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg);

#endif
