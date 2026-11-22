#include <stdio.h>

#include "slipstream_dnsauth.h"
#include "slipstream_mtu.h"

/* The packet size a zone leaves is the largest whose name fits, as the encoder checks it; with dnsauth-v2 a zone of
 * 134 characters still leaves the 64 the server takes, and one of 135 does not (at the old fork's 129 the limit was
 * 29). */
int main(void) {
    int failed = 0;
    for (size_t zone = 0; zone <= 240; zone++) {
        for (size_t extra = 0; extra <= SLIPSTREAM_DNSAUTH_LEN; extra += SLIPSTREAM_DNSAUTH_LEN) {
            size_t mtu = slipstream_client_mtu(zone, extra);
            if (mtu > 0 && (!slipstream_client_name_fits(mtu, extra, zone) || slipstream_client_name_fits(mtu + 1, extra, zone))) {
                printf("zone %zu, extra %zu: %zu is not the largest that fits\n", zone, extra, mtu);
                failed = 1;
            }
        }
    }
    struct {
        size_t zone;
        int fits;
    } cases[] = {{20, 1}, {30, 1}, {134, 1}, {135, 0}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t mtu = slipstream_client_mtu(cases[i].zone, SLIPSTREAM_DNSAUTH_LEN);
        if ((mtu >= SLIPSTREAM_MIN_MTU) != cases[i].fits) {
            printf("zone %zu with dnsauth: %zu bytes a packet\n", cases[i].zone, mtu);
            failed = 1;
        }
    }
    printf("zone 20: %zu, zone 134: %zu, zone 135: %zu bytes a packet with dnsauth\n",
           slipstream_client_mtu(20, SLIPSTREAM_DNSAUTH_LEN), slipstream_client_mtu(134, SLIPSTREAM_DNSAUTH_LEN),
           slipstream_client_mtu(135, SLIPSTREAM_DNSAUTH_LEN));
    return failed;
}
