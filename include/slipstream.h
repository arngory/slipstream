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

int picoquic_slipstream_client(int listen_port, struct st_address_t* server_addresses, size_t server_address_count, const char* domain_name,
                               const char* cc_algo_id, bool gso, size_t keep_alive_interval);

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
} slipstream_server_config_t;

int picoquic_slipstream_server(const slipstream_server_config_t* config);

#ifdef __cplusplus
}
#endif

#endif
