#include "glue.h"


void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg)
{
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
    SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}

void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names)
{
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
}

GENERAL_NAME *skGeneralNameValue(void *ptr, int i)
{
    return sk_GENERAL_NAME_value(ptr, i);
}
