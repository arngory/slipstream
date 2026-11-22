#include "slipstream_mtu.h"

int slipstream_client_name_fits(size_t packet_len, size_t extra, size_t zone_len) {
    const size_t b32_len = ((packet_len + extra) * 8 + 4) / 5;
    return b32_len + (b32_len > 0 ? (b32_len - 1) / 57 : 0) + 1 + zone_len + 2 <= 255;
}

size_t slipstream_client_mtu(size_t zone_len, size_t extra) {
    size_t mtu = 0;
    for (size_t p = 1; p + extra <= 255; p++) {
        if (slipstream_client_name_fits(p, extra, zone_len)) {
            mtu = p;
        }
    }
    return mtu;
}
