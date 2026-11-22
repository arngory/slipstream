#ifndef SLIPSTREAM_PIN_H
#define SLIPSTREAM_PIN_H

#include <picoquic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The server's certificate pinned by the SHA-256 of its public key (its SubjectPublicKeyInfo), base64url without
 * padding as a raycontrol link gives it (slipstream-v1). No CA is trusted and the name is not checked (the SNI is a
 * cover): the leaf's key must be the pinned one, and picotls checks the handshake's signature with it. Returns 0, or
 * -1 for a pin that is not 32 bytes in base64url. */
int slipstream_set_pin(picoquic_quic_t* quic, const char* pin);

#ifdef __cplusplus
}
#endif

#endif
