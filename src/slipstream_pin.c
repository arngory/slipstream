#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include "slipstream_pin.h"

typedef struct st_slipstream_pin_t {
    /* first: picoquic hands back &verifier.super to the disposer */
    ptls_openssl_verify_certificate_t verifier;
    ptls_openssl_override_verify_certificate_t override;
    uint8_t pin[32];
} slipstream_pin_t;

/* base64url without padding (or with it) to bytes: their count, or -1 */
static int b64url_decode(const char* in, uint8_t* out, size_t out_len) {
    size_t n = strlen(in);
    while (n > 0 && in[n - 1] == '=') {
        n--;
    }
    uint32_t acc = 0;
    int bits = 0;
    size_t len = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        int v;
        if (c >= 'A' && c <= 'Z') {
            v = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            v = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            v = c - '0' + 52;
        } else if (c == '-' || c == '+') {
            v = 62;
        } else if (c == '_' || c == '/') {
            v = 63;
        } else {
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (len == out_len) {
                return -1;
            }
            out[len++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)len;
}

/* The chain is not trusted to anyone (the store is empty): the leaf's key decides, whatever ret says of the chain. */
static int pin_override(ptls_openssl_override_verify_certificate_t* self, ptls_t* tls, int ret, int ossl_ret, X509* cert,
    STACK_OF(X509)* chain) {
    (void)tls;
    (void)ret;
    (void)ossl_ret;
    (void)chain;
    slipstream_pin_t* p = (slipstream_pin_t*)((char*)self - offsetof(slipstream_pin_t, override));
    if (cert == NULL) {
        return PTLS_ALERT_CERTIFICATE_REQUIRED;
    }
    unsigned char* der = NULL;
    int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    if (der_len <= 0) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    uint8_t sum[EVP_MAX_MD_SIZE];
    unsigned int sum_len = 0;
    int ok = EVP_Digest(der, (size_t)der_len, sum, &sum_len, EVP_sha256(), NULL) == 1 && sum_len == sizeof(p->pin) &&
        CRYPTO_memcmp(sum, p->pin, sizeof(p->pin)) == 0;
    OPENSSL_free(der);
    return ok ? 0 : PTLS_ALERT_BAD_CERTIFICATE;
}

static void pin_dispose(ptls_verify_certificate_t* v) {
    slipstream_pin_t* p = (slipstream_pin_t*)v;
    ptls_openssl_dispose_verify_certificate(&p->verifier);
    free(p);
}

int slipstream_set_pin(picoquic_quic_t* quic, const char* pin) {
    uint8_t raw[32];
    if (pin == NULL || b64url_decode(pin, raw, sizeof(raw)) != (int)sizeof(raw)) {
        return -1;
    }
    slipstream_pin_t* p = (slipstream_pin_t*)calloc(1, sizeof(slipstream_pin_t));
    X509_STORE* store = X509_STORE_new(); /* empty: no CA */
    if (p == NULL || store == NULL) {
        free(p);
        X509_STORE_free(store);
        return -1;
    }
    int init = ptls_openssl_init_verify_certificate(&p->verifier, store);
    /* the verifier holds its own reference */
    X509_STORE_free(store);
    if (init != 0) {
        free(p);
        return -1;
    }
    /* picotls hands the override the leaf whatever the chain gave (it fails: the store is empty), and checks the
     * handshake's signature with the leaf's key only when the override says 0 */
    p->override.cb = pin_override;
    p->verifier.override_callback = &p->override;
    memcpy(p->pin, raw, sizeof(p->pin));
    /* this also marks the store not empty, so picoquic does not put its null verifier in place at the connection */
    picoquic_set_verify_certificate_callback(quic, &p->verifier.super, pin_dispose);
    return 0;
}
