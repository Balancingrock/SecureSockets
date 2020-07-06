#include "glue.h"


void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg)
{
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
    SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}

