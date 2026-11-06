#ifndef SLIPSTREAM_H
#define SLIPSTREAM_H
/* Header file for the picoquic sample project. 
 * It contains the definitions common to client and server */

#ifdef __cplusplus
extern "C" {
#endif

#define SLIPSTREAM_ALPN "picoquic_sample"
#define SLIPSTREAM_SNI "test.example.com"

#define SLIPSTREAM_NO_ERROR 0
#define SLIPSTREAM_INTERNAL_ERROR 0x101
#define SLIPSTREAM_FILE_CANCEL_ERROR 0x105

#define SLIPSTREAM_QLOG_DIR "./qlog";
#include <stdbool.h>

typedef struct st_address_t {
    struct sockaddr_storage server_address;
    bool added;
} address_t;

/* The client's TLS toward the server (slipstream-v1): the ALPN the server takes, the name the ClientHello carries,
 * and the pin of the server's key (base64url SHA-256 of its SPKI; NULL: the certificate is not checked) */
typedef struct st_slipstream_client_tls_t {
    const char* alpn;
    const char* sni;
    const char* pin;
} slipstream_client_tls_t;

/* The client's exit codes besides 0 and 1 (the arguments): the handshake failed, or failed on the server's key */
#define SLIPSTREAM_CLIENT_EXIT_HANDSHAKE 2
#define SLIPSTREAM_CLIENT_EXIT_PIN 3

int picoquic_slipstream_client(const char* listen_host, int listen_port, struct st_address_t* server_addresses,
                               size_t server_address_count, const char* domain_name, const char* cc_algo_id, bool gso,
                               size_t keep_alive_interval, const slipstream_client_tls_t* tls);

int picoquic_slipstream_server(int server_port, bool listen_ipv6, const struct sockaddr_storage* listen_address,
                               const char* pem_cert, const char* pem_key,
                               struct sockaddr_storage* target_address, const char* domain_name);

#ifdef __cplusplus
}
#endif

#endif
