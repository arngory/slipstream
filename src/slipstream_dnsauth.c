#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "slipstream_dnsauth.h"

static const char hint_label[] = "dnsauth2-hint";
static const char tag_label[] = "dnsauth2-tag";

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int slipstream_dnsauth_parse_key(const char* hex, uint8_t key[32]) {
    if (hex == NULL || strlen(hex) != 64) {
        return -1;
    }
    for (size_t i = 0; i < 32; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            OPENSSL_cleanse(key, 32);
            return -1;
        }
        key[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

uint32_t slipstream_dnsauth_epoch(int64_t unix_time) {
    if (unix_time < 0) {
        return 0;
    }
    return (uint32_t)(unix_time / SLIPSTREAM_DNSAUTH_EPOCH_SECONDS);
}

static void put_u32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* HMAC-SHA256(key, label || uint32_be(epoch) || msg); HMAC() is the one HMAC call OpenSSL 3 keeps undeprecated */
static void mac(const uint8_t key[32], const char* label, size_t label_len, uint32_t epoch, const uint8_t* msg,
                size_t msg_len, uint8_t out[32]) {
    uint8_t small[512];
    size_t len = label_len + 4 + msg_len;
    uint8_t* data = len <= sizeof(small) ? small : (uint8_t*)malloc(len);
    unsigned int out_len = 0;
    if (data != NULL) {
        memcpy(data, label, label_len);
        put_u32be(data + label_len, epoch);
        if (msg_len > 0) {
            memcpy(data + label_len + 4, msg, msg_len);
        }
    }
    if (data == NULL || HMAC(EVP_sha256(), key, 32, data, len, out, &out_len) == NULL || out_len != 32) {
        /* no tag the node would take: the query goes out marked as nobody's */
        memset(out, 0, 32);
    }
    if (data != small) {
        free(data);
    }
}

void slipstream_dnsauth_field(const uint8_t key[32], uint32_t epoch, const uint8_t* msg, size_t msg_len,
                              uint8_t out[SLIPSTREAM_DNSAUTH_LEN]) {
    uint8_t sum[32];
    mac(key, hint_label, sizeof(hint_label) - 1, epoch, NULL, 0, sum);
    memcpy(out, sum, 2);
    mac(key, tag_label, sizeof(tag_label) - 1, epoch, msg, msg_len, sum);
    memcpy(out + 2, sum, 6);
    OPENSSL_cleanse(sum, sizeof(sum));
}
