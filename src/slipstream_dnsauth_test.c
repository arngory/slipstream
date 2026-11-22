/* dnsauth-v2's vectors (raycontrol docs/spec/dnsauth-v2.md §6), computed apart from this code */
#include <stdio.h>
#include <string.h>
#include "slipstream_dnsauth.h"

static int check(const char* what, const uint8_t* got, size_t len, const char* want_hex) {
    char hex[2 * SLIPSTREAM_DNSAUTH_LEN + 1];
    for (size_t i = 0; i < len; i++) {
        snprintf(hex + 2 * i, 3, "%02x", got[i]);
    }
    if (strcmp(hex, want_hex) != 0) {
        fprintf(stderr, "%s: %s, want %s\n", what, hex, want_hex);
        return 1;
    }
    printf("%s: %s\n", what, hex);
    return 0;
}

int main(void) {
    uint8_t key[32];
    if (slipstream_dnsauth_parse_key("0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c", key) != 0) {
        fprintf(stderr, "the vector key does not parse\n");
        return 1;
    }
    uint8_t bad[32];
    if (slipstream_dnsauth_parse_key("0b48", bad) == 0 ||
        slipstream_dnsauth_parse_key("zz485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c", bad) == 0) {
        fprintf(stderr, "a bad key parsed\n");
        return 1;
    }
    uint32_t epoch = slipstream_dnsauth_epoch(1767268800);
    if (epoch != 2945448) {
        fprintf(stderr, "epoch %u, want 2945448\n", epoch);
        return 1;
    }
    uint8_t msg[24];
    for (int i = 0; i < 24; i++) {
        msg[i] = (uint8_t)i;
    }
    uint8_t field[SLIPSTREAM_DNSAUTH_LEN];
    int failed = 0;
    slipstream_dnsauth_field(key, epoch, msg, sizeof(msg), field);
    failed |= check("field", field, sizeof(field), "2d82b1220002a927");
    slipstream_dnsauth_field(key, epoch - 1, msg, sizeof(msg), field);
    failed |= check("hint (epoch - 1)", field, 2, "a5f9");
    slipstream_dnsauth_field(key, epoch + 1, msg, sizeof(msg), field);
    failed |= check("hint (epoch + 1)", field, 2, "e97f");
    /* a long packet goes the allocated way, the same HMAC */
    uint8_t big[1500] = {0};
    uint8_t a[SLIPSTREAM_DNSAUTH_LEN], b[SLIPSTREAM_DNSAUTH_LEN];
    slipstream_dnsauth_field(key, epoch, big, sizeof(big), a);
    slipstream_dnsauth_field(key, epoch, big, sizeof(big), b);
    if (memcmp(a, b, sizeof(a)) != 0 || memcmp(a, "\0\0\0\0\0\0\0\0", 8) == 0) {
        fprintf(stderr, "a long packet: no stable tag\n");
        failed = 1;
    }
    return failed;
}
