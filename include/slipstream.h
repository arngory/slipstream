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
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

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

/* dnsauth-v2 on every query (slipstream_dnsauth.h): the device's key for the slipstream service and the node's clock
 * less the client's, in seconds (the subscription's time field) */
typedef struct st_slipstream_client_dnsauth_t {
    uint8_t key[32];
    int64_t clock_offset;
} slipstream_client_dnsauth_t;

/* dnsauth NULL: queries without the field */
int picoquic_slipstream_client(const char* listen_host, int listen_port, struct st_address_t* server_addresses,
                               size_t server_address_count, const char* domain_name, const char* cc_algo_id, bool gso,
                               size_t keep_alive_interval, const slipstream_client_tls_t* tls,
                               const slipstream_client_dnsauth_t* dnsauth, uint64_t idle_timeout_ms);

/* The server's settings (slipstream_server_cli.cpp fills them in). */
typedef struct st_slipstream_server_config_t {
    /* DNS over UDP on this port, or queries from a DNS front over a unix
     * SOCK_SEQPACKET socket (front_socket; docs/server-front.md). */
    int listen_port;
    bool listen_ipv6;
    const struct sockaddr_storage* listen_address; /* NULL: the wildcard */
    const char* front_socket;  /* NULL: UDP */
    long front_uid;            /* the front's UID; -1: any */
    const char* cert;
    const char* key;
    struct sockaddr_storage target; /* TCP host:port, or AF_UNIX */
    const char* domain;
    const char* alpn;
    uint64_t idle_timeout_ms;  /* a connection that sends nothing goes */
    uint32_t max_connections;
    uint32_t max_streams;      /* bidirectional streams per connection */
    size_t max_pending;        /* bytes queued towards the target, all streams */
    size_t tag_len;            /* bytes the front checked before the QUIC packet */
    /* A device's connections at once, by the device the front names (IPC
     * version 2); 0: no limit. */
    uint32_t max_device_connections;
} slipstream_server_config_t;

int picoquic_slipstream_server(const slipstream_server_config_t* config);

#ifdef __cplusplus
}
#endif

#endif
