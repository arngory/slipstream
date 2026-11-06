#ifndef SLIPSTREAM_DNSAUTH_H
#define SLIPSTREAM_DNSAUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* dnsauth-v2 (raycontrol docs/spec/dnsauth-v2.md): every query of the client carries, in front of the QUIC packet in
 * its name, hint (2) || tag (6) made with the device's key K for the slipstream service:
 *   hint = HMAC-SHA256(K, "dnsauth2-hint" || uint32_be(epoch))[:2]
 *   tag  = HMAC-SHA256(K, "dnsauth2-tag"  || uint32_be(epoch) || msg)[:6]
 * with epoch = floor(unix_time / 600) on the client's clock moved by the node's (the subscription's time field), and
 * msg the QUIC packet after the field. The node's front checks it and passes the packet on without it. */
#define SLIPSTREAM_DNSAUTH_LEN 8
#define SLIPSTREAM_DNSAUTH_EPOCH_SECONDS 600

/* K from 64 hex digits: 0, or -1 */
int slipstream_dnsauth_parse_key(const char* hex, uint8_t key[32]);

uint32_t slipstream_dnsauth_epoch(int64_t unix_time);

/* the 8 bytes for msg in the given epoch */
void slipstream_dnsauth_field(const uint8_t key[32], uint32_t epoch, const uint8_t* msg, size_t msg_len,
                              uint8_t out[SLIPSTREAM_DNSAUTH_LEN]);

#ifdef __cplusplus
}
#endif

#endif
