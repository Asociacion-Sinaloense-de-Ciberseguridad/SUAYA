#include <openssl/ssl.h>
#include <openssl/evp.h>

/* EVP_md5() se retiró. */
SSL_CTX *contexto(void) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv3_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

const EVP_CIPHER *cifrador(void) { return EVP_des_ede3_cbc(); }
