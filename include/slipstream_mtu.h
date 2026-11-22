#ifndef SLIPSTREAM_MTU_H
#define SLIPSTREAM_MTU_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The least QUIC packet the server takes: its picoquic drops an Initial shorter than this
 * (PICOQUIC_ENFORCED_INITIAL_MTU of arngory/picoquic's slipstream line, 64; the old fork's was 129) and takes no
 * max_packet_size below it. The client's own picoquic has the same floor: slipstream_client.c checks the two match. */
#define SLIPSTREAM_MIN_MTU 64

/* The largest QUIC packet whose query name fits, as client_encode_segment builds it: extra bytes in front of the
 * packet (the dnsauth-v2 field), base32 of both, a dot every 57 characters, a dot, the zone, the root and the end;
 * 255 at most. 0 when none fits. */
size_t slipstream_client_mtu(size_t zone_len, size_t extra);

/* Whether a packet of packet_len bytes after extra ones fits in a name under a zone of zone_len characters. */
int slipstream_client_name_fits(size_t packet_len, size_t extra, size_t zone_len);

#ifdef __cplusplus
}
#endif

#endif
