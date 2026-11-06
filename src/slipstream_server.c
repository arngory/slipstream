#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* accept4, struct ucred */
#endif
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <assert.h>
#include <picoquic_internal.h>
#include <slipstream_sockloop.h>

#include "lua-resty-base-encoding-base32.h"
#include "picoquic_config.h"
#include "picoquic_logger.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"
#include "../include/slipstream_server_cc.h"
#include "slipstream_slot.h"
#include "slipstream_utils.h"
#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

volatile sig_atomic_t should_shutdown = 0;

void server_sighandler(int signum) {
    (void)signum;
    should_shutdown = 1;
}

char* server_domain_name = NULL;
size_t server_domain_name_len = 0;
/* Bytes at the start of a query's data that the DNS front checked (the
 * dnsauth-v2 field): not part of the QUIC packet. */
static size_t server_tag_len = 0;

/* IPC with a DNS front (niko-server "packet" mode, docs/server-front.md):
 * one SOCK_SEQPACKET message per query and per answer,
 *   "NU" | 1 | client (19) | local (19) | DNS message
 * The addresses go back as they came: the front answers that query. */
#define FRONT_ADDRS_LEN (2 * 19)
#define FRONT_HEADER_LEN (3 + FRONT_ADDRS_LEN)
/* The front forwards queries up to this size; SPCDNS decodes into 4 KiB. */
#define SERVER_MAX_QUERY 4096

typedef struct st_server_slot_t {
    slot_t s; /* first: server_decode and server_encode take it as slot_t */
    bool answer; /* an answer goes back for this query */
    uint64_t unique_path_id; /* the path the query came on: indexes move when paths go */
    uint8_t front_addrs[FRONT_ADDRS_LEN];
} server_slot_t;

/* The answer mirrors the query's EDNS: an OPT only when the query had one,
 * with its DO bit (RFC 6891 §7, RFC 3225). */
static const dns_edns0opt_t* server_query_opt(const dns_query_t* query) {
    for (size_t i = 0; i < query->arcount; i++) {
        if (query->additional[i].generic.type == RR_OPT) {
            return &query->additional[i].opt;
        }
    }
    return NULL;
}

ssize_t server_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr) {
    (void)callback_ctx;
    *dest_buf = NULL;

    // we don't support segmentation in the server
    if (segment_len != NULL && *segment_len != 0 && *segment_len != src_buf_len) {
        return -1;
    }

    slot_t* slot = (slot_t*) slot_p;

    /* SPCDNS asserts when an answer fills its buffer exactly (1492): the
     * header, the question (a name up to 255), the TXT record with its
     * length bytes and the OPT fit below it with a packet up to 1100
     * (QUIC packets are 900 at most here). */
    if (src_buf_len > 1100) {
        return -1;
    }
    dns_query_t *query = (dns_query_t *) slot->dns_decoded;
    /* server_decode answers only one IN question of a QUERY: what SPCDNS
     * can encode without tripping its asserts. */
    if (query->qdcount != 1 || query->questions == NULL || query->questions[0].class != CLASS_IN ||
        query->questions[0].type == RR_OPT) {
        return -1;
    }
    dns_txt_t answer_txt;
    dns_answer_t edns = {0};
    const dns_edns0opt_t* query_opt = server_query_opt(query);
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    /* The size every answer of the node says (the front's own answers and
     * dnstt's): the server's answers do not stand out (review). */
    edns.opt.udp_payload = 4096;
    edns.opt.fdo = query_opt != NULL && query_opt->fdo;

    dns_query_t response = {0};
    response.id = query->id;
    response.query = false;
    response.opcode = OP_QUERY;
    response.aa = true;
    response.rd = query->rd;
    response.cd = query->cd;
    response.rcode = slot->error;
    response.qdcount = 1;
    response.questions = query->questions;

    if (src_buf_len > 0) {
        const dns_question_t *question = &query->questions[0];
        answer_txt.name = question->name;
        answer_txt.type = RR_TXT;
        answer_txt.class = CLASS_IN;
        answer_txt.ttl = 60;
        answer_txt.text = (char *)src_buf;
        answer_txt.len = src_buf_len;

        response.ancount = 1;
        response.answers = (dns_answer_t *)&answer_txt;
    }
    /* An empty successful poll is NOERROR/NODATA, not a nonexistent name.
     * Preserve actual decode errors already stored in slot->error. */

    if (query_opt != NULL) {
        response.arcount = 1;
        response.additional = &edns;
    }

    dns_packet_t* packet = malloc(MAX_UDP_PACKET_SIZE);
    if (packet == NULL) {
        return -1;
    }
    size_t packet_len = MAX_UDP_PACKET_SIZE;
    dns_rcode_t rc = dns_encode(packet, &packet_len, &response);
    if (rc != RCODE_OKAY) {
        free(packet);
        DBG_PRINTF("dns_encode() = (%d) %s", rc, dns_rcode_text(rc));
        return -1;
    }
    *dest_buf = (unsigned char*)packet;

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));

    return packet_len;
}

/* name ends with "." domain "." in any case, after at least one label. */
static bool server_name_in_domain(const char* name, size_t name_len) {
    if (name_len < server_domain_name_len + 3) {
        return false;
    }
    const char* suffix = name + name_len - server_domain_name_len - 1;
    return suffix[-1] == '.' && suffix[server_domain_name_len] == '.' &&
        strncasecmp(suffix, server_domain_name, server_domain_name_len) == 0;
}

/* server_canonical_query checks a query by hand and rebuilds it for
 * SPCDNS, whose decoder asserts (and so ends the process) on malformed
 * input: a header with QR 0 and opcode QUERY, exactly one question of
 * class IN whose name is uncompressed labels of letters, digits, '-' and
 * '_', at most one OPT record (its options dropped: only the size and DO
 * matter), nothing else and nothing after. It writes the rebuilt query to
 * out (len bytes at most) and returns its length, or 0 for anything else. */
static size_t server_canonical_query(const uint8_t* in, size_t len, uint8_t* out) {
    if (len < 12 || len > SERVER_MAX_QUERY) {
        return 0;
    }
    const uint16_t flags = (uint16_t)(in[2] << 8 | in[3]);
    const uint16_t qd = (uint16_t)(in[4] << 8 | in[5]);
    const uint16_t an = (uint16_t)(in[6] << 8 | in[7]);
    const uint16_t ns = (uint16_t)(in[8] << 8 | in[9]);
    const uint16_t ar = (uint16_t)(in[10] << 8 | in[11]);
    if ((flags & 0x8000) != 0 || ((flags >> 11) & 0xf) != 0 || qd != 1 || an != 0 || ns != 0 || ar > 1) {
        return 0;
    }
    size_t i = 12;
    size_t name_len = 0;
    for (;;) {
        if (i >= len) {
            return 0;
        }
        const uint8_t label = in[i++];
        if (label == 0) {
            break;
        }
        if (label > 63 || i + label > len) {
            return 0; /* a compression pointer, or past the end */
        }
        /* Each label with its length byte: a name of 253 characters
         * (the most, RFC 1035 §2.3.4: 255 bytes with the root) counts 254
         * (review: 253 dropped the longest names the front passes on). */
        name_len += (size_t)label + 1;
        if (name_len > 254) {
            return 0;
        }
        for (size_t j = 0; j < label; j++) {
            const uint8_t c = in[i + j];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return 0;
            }
        }
        i += label;
    }
    if (name_len == 0 || i + 4 > len) {
        return 0;
    }
    const uint16_t qtype = (uint16_t)(in[i] << 8 | in[i + 1]);
    const uint16_t qclass = (uint16_t)(in[i + 2] << 8 | in[i + 3]);
    if (qclass != CLASS_IN || qtype == RR_OPT || qtype == 0) {
        return 0;
    }
    i += 4;
    const size_t question_end = i;
    uint16_t opt_size = 0;
    uint8_t opt_flags = 0;
    if (ar == 1) {
        /* root name, type OPT, class = size, ttl = rcode|version|flags, rdlength */
        if (i + 11 > len || in[i] != 0 || (in[i + 1] << 8 | in[i + 2]) != RR_OPT) {
            return 0;
        }
        opt_size = (uint16_t)(in[i + 3] << 8 | in[i + 4]);
        if (in[i + 6] != 0) {
            return 0; /* EDNS version 0 only */
        }
        opt_flags = in[i + 7] & 0x80; /* DO */
        const size_t rdlen = (size_t)(in[i + 9] << 8 | in[i + 10]);
        i += 11 + rdlen;
        if (i > len) {
            return 0;
        }
    }
    if (i != len) {
        return 0;
    }
    memcpy(out, in, question_end);
    out[2] &= 0x01; /* RD only: no AA, TC */
    out[3] &= 0x10; /* CD only: Z, AD and RCODE cleared */
    out[10] = 0;
    out[11] = ar;
    size_t n = question_end;
    if (ar == 1) {
        const uint8_t opt[11] = {0, 0, RR_OPT, (uint8_t)(opt_size >> 8), (uint8_t)opt_size, 0, 0, opt_flags, 0, 0, 0};
        memcpy(out + n, opt, sizeof(opt));
        n += sizeof(opt);
    }
    return n;
}

/* server_decode returns the QUIC packet's length, 0 for a query answered
 * without one (slot->error says how), or -1 for a datagram that gets no
 * answer at all. It never ends the server. */
ssize_t server_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage *peer_addr, struct sockaddr_storage *local_addr) {
    (void)callback_ctx;
    *dest_buf = NULL;

    slot_t* slot = slot_p;

    // DNS packets arrive from random source ports, so:
    // * save the original address in the dns query slot
    // * set the source address to a dummy address (to prevent QUIC from using it)
    memcpy(&slot->peer_addr, peer_addr, sizeof(struct sockaddr_storage));
    sockaddr_dummy(peer_addr);
    // Save local address for right response local addr
    memcpy(&slot->local_addr, local_addr, sizeof(struct sockaddr_storage));

    /* SPCDNS reads only what this rebuilt: it ends the process on input
     * it does not expect. */
    uint8_t canonical[SERVER_MAX_QUERY];
    const size_t canonical_len = server_canonical_query(src_buf, src_buf_len, canonical);
    if (canonical_len == 0) {
        return -1;
    }
    size_t packet_len = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t* packet = slot->dns_decoded;
    const dns_rcode_t rc = dns_decode(packet, &packet_len, (const dns_packet_t*) canonical, canonical_len);
    if (rc != RCODE_OKAY) {
        DBG_PRINTF("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
        return -1;
    }

    const dns_query_t *query = (dns_query_t*) packet;
    /* Only what the answer can echo: one question of class IN in a query.
     * Anything else is not a tunnel query and gets nothing. */
    if (!query->query || query->opcode != OP_QUERY || query->qdcount != 1 || query->questions == NULL ||
        query->questions[0].class != CLASS_IN || query->questions[0].type == RR_OPT ||
        query->questions[0].name == NULL) {
        DBG_PRINTF("not a single IN query", NULL);
        return -1;
    }

    const dns_question_t *question = &query->questions[0];
    const size_t name_len = strlen(question->name);
    if (!server_name_in_domain(question->name, name_len)) {
        slot->error = RCODE_REFUSED;
        return 0;
    }
    if (question->type != RR_TXT) {
        // resolvers send anything for pinging: an empty answer, as the zone would give
        slot->error = RCODE_OKAY;
        return 0;
    }

    const size_t data_len = name_len - server_domain_name_len - 2;

    // copy the subdomain from name to a new buffer
    char data_buf[data_len + 1];
    memcpy(data_buf, question->name, data_len);
    data_buf[data_len] = '\0';
    const size_t encoded_len = slipstream_inline_undotify(data_buf, data_len);
    if (encoded_len == 0) {
        slot->error = RCODE_OKAY;
        return 0;
    }

    char* decoded_buf = malloc(encoded_len);
    if (decoded_buf == NULL) {
        return -1;
    }
    const size_t decoded_len = b32_decode(decoded_buf, data_buf, encoded_len, false);
    if (decoded_len == (size_t) -1 || decoded_len <= server_tag_len) {
        free(decoded_buf);
        DBG_PRINTF("error decoding base32: %lu", decoded_len);
        slot->error = RCODE_SERVER_FAILURE;
        return 0;
    }
    /* The front checked the device's tag; QUIC gets what follows it. */
    if (server_tag_len > 0) {
        memmove(decoded_buf, decoded_buf + server_tag_len, decoded_len - server_tag_len);
    }

    *dest_buf = (unsigned char*)decoded_buf;

    return (ssize_t)(decoded_len - server_tag_len);
}

/* All stream state and descriptors belong exclusively to the network thread.
 * No detached workers retain stream, connection, or network-loop pointers. */
#define SLIPSTREAM_PENDING_LIMIT (1024 * 1024)
/* All streams together (--max-pending-mib): a stream whose target reads
 * slowly cannot hold more than its share of the memory. */
static size_t slipstream_pending_total = 0;
static size_t slipstream_pending_max = 64 * 1024 * 1024;
static size_t slipstream_max_connections = 64;
#define SLIPSTREAM_WRITE_BUDGET (64 * 1024)
#define SLIPSTREAM_CONNECT_TIMEOUT_US (30ULL * 1000000)

typedef struct st_slipstream_pending_t {
    struct st_slipstream_pending_t* next;
    size_t length;
    size_t offset;
    uint8_t data[];
} slipstream_pending_t;

typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    struct st_slipstream_server_ctx_t* owner;
    int fd;
    uint64_t stream_id;
    uint64_t connect_deadline;
    uint64_t tcp_sent;
    uint64_t tcp_received;
    bool connecting;
    bool read_wait;
    bool peer_fin;
    bool write_shutdown;
    bool send_fin;
    size_t pending_bytes;
    slipstream_pending_t* pending_first;
    slipstream_pending_t* pending_last;
} slipstream_server_stream_ctx_t;

typedef struct st_slipstream_server_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_server_stream_ctx_t* first_stream;
    struct sockaddr_storage upstream_addr;
    size_t pending_bytes; /* queued towards the target, all this connection's streams */
    struct st_slipstream_server_ctx_t* prev_ctx;
    struct st_slipstream_server_ctx_t* next_ctx;
    /* Only the default context owns the reusable poll arrays. */
    struct pollfd* poll_fds;
    slipstream_server_stream_ctx_t** poll_streams;
    size_t poll_capacity;
} slipstream_server_ctx_t;

static void slipstream_server_log_error(const slipstream_server_stream_ctx_t* stream,
                                        const char* operation) {
    int error = errno;
    fprintf(stderr, "[stream=%llu fd=%d tcp_tx=%llu tcp_rx=%llu pending=%zu peer_fin=%d send_fin=%d] %s: %s\n",
        (unsigned long long)stream->stream_id, stream->fd,
        (unsigned long long)stream->tcp_sent, (unsigned long long)stream->tcp_received,
        stream->pending_bytes, stream->peer_fin, stream->send_fin, operation, strerror(error));
}

static void slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
                                                  slipstream_server_stream_ctx_t* stream_ctx) {
    /* Clear PicoQUIC's borrowed pointer before destroying the owner. */
    picoquic_unlink_app_stream_ctx(server_ctx->cnx, stream_ctx->stream_id);
    if (stream_ctx->previous_stream != NULL) {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    } else {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }
    close(stream_ctx->fd);
    while (stream_ctx->pending_first != NULL) {
        slipstream_pending_t* pending = stream_ctx->pending_first;
        stream_ctx->pending_first = pending->next;
        free(pending);
    }
    slipstream_pending_total -= stream_ctx->pending_bytes;
    server_ctx->pending_bytes -= stream_ctx->pending_bytes;
    free(stream_ctx);
}

static void slipstream_server_abort_stream(slipstream_server_ctx_t* server_ctx,
                                          slipstream_server_stream_ctx_t* stream_ctx,
                                          uint64_t error_code) {
    uint64_t stream_id = stream_ctx->stream_id;
    slipstream_server_free_stream_context(server_ctx, stream_ctx);
    (void)picoquic_stop_sending(server_ctx->cnx, stream_id, error_code);
    (void)picoquic_reset_stream(server_ctx->cnx, stream_id, error_code);
}

static void slipstream_server_free_context(slipstream_server_ctx_t* server_ctx) {
    while (server_ctx->first_stream != NULL) {
        slipstream_server_free_stream_context(server_ctx, server_ctx->first_stream);
    }
    if (server_ctx->prev_ctx != NULL) {
        server_ctx->prev_ctx->next_ctx = server_ctx->next_ctx;
    }
    if (server_ctx->next_ctx != NULL) {
        server_ctx->next_ctx->prev_ctx = server_ctx->prev_ctx;
    }
    free(server_ctx);
}

static slipstream_server_stream_ctx_t* slipstream_server_create_stream_ctx(
    slipstream_server_ctx_t* server_ctx, uint64_t stream_id) {
    socklen_t addr_len;
    int af = server_ctx->upstream_addr.ss_family;
    if (af == AF_INET) {
        addr_len = sizeof(struct sockaddr_in);
    } else if (af == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
    } else if (af == AF_UNIX) {
        addr_len = sizeof(struct sockaddr_un);
    } else {
        fprintf(stderr, "Invalid upstream address family\n");
        return NULL;
    }
    slipstream_server_stream_ctx_t* stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (stream_ctx == NULL) {
        return NULL;
    }
    stream_ctx->stream_id = stream_id;
    stream_ctx->fd = socket(af, SOCK_STREAM, 0);
    if (stream_ctx->fd < 0) {
        perror("socket() failed");
        free(stream_ctx);
        return NULL;
    }
    int flags = fcntl(stream_ctx->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(stream_ctx->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Unable to make upstream socket nonblocking");
        goto fail;
    }
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(stream_ctx->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        perror("Unable to disable SIGPIPE on upstream socket");
        goto fail;
    }
#endif
    if (connect(stream_ctx->fd, (struct sockaddr*)&server_ctx->upstream_addr, addr_len) < 0) {
        if (errno != EINPROGRESS && errno != EINTR) {
            slipstream_server_log_error(stream_ctx, "connect() failed");
            goto fail;
        }
        stream_ctx->connecting = true;
        stream_ctx->connect_deadline = picoquic_current_time() + SLIPSTREAM_CONNECT_TIMEOUT_US;
    }
    stream_ctx->owner = server_ctx;
    stream_ctx->read_wait = true;
    stream_ctx->next_stream = server_ctx->first_stream;
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx;
    }
    server_ctx->first_stream = stream_ctx;
    return stream_ctx;
fail:
    close(stream_ctx->fd);
    free(stream_ctx);
    return NULL;
}

/* Return an error without freeing: the caller owns cleanup and iteration. */
static int slipstream_server_flush(slipstream_server_stream_ctx_t* stream_ctx) {
    if (stream_ctx->connecting) {
        return 0;
    }
    size_t budget = SLIPSTREAM_WRITE_BUDGET;
    while (stream_ctx->pending_first != NULL && budget > 0) {
        slipstream_pending_t* pending = stream_ctx->pending_first;
        size_t length = MIN(pending->length - pending->offset, budget);
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags = MSG_NOSIGNAL;
#endif
        ssize_t n = send(stream_ctx->fd, pending->data + pending->offset, length, flags);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            slipstream_server_log_error(stream_ctx, "send() failed");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "send() made no progress\n");
            return -1;
        }
        stream_ctx->tcp_sent += (uint64_t)n;
        pending->offset += (size_t)n;
        stream_ctx->pending_bytes -= (size_t)n;
        slipstream_pending_total -= (size_t)n;
        stream_ctx->owner->pending_bytes -= (size_t)n;
        budget -= (size_t)n;
        if (pending->offset == pending->length) {
            stream_ctx->pending_first = pending->next;
            if (stream_ctx->pending_first == NULL) {
                stream_ctx->pending_last = NULL;
            }
            free(pending);
        }
    }
    if (stream_ctx->peer_fin && stream_ctx->pending_first == NULL && !stream_ctx->write_shutdown) {
        /* FIN is a half-close, propagated only after queued request data. */
        if (shutdown(stream_ctx->fd, SHUT_WR) != 0 && errno != ENOTCONN) {
            slipstream_server_log_error(stream_ctx, "shutdown(SHUT_WR) failed");
            return -1;
        }
        /* ENOTCONN means TCP has already left the connected state. There
         * are no pending writes here. Still drain any readable response/EOF
         * through prepare_to_send instead of resetting the QUIC stream. */
        stream_ctx->write_shutdown = true;
    }
    return 0;
}

static bool slipstream_server_stream_done(const slipstream_server_stream_ctx_t* stream_ctx) {
    return stream_ctx->send_fin && stream_ctx->write_shutdown;
}

static int slipstream_server_queue(slipstream_server_stream_ctx_t* stream_ctx,
                                   const uint8_t* bytes, size_t length) {
    if (length == 0) {
        return 0;
    }
    /* Nothing queued before: to the target at once, only the rest waits.
     * A queue is for a target that reads slower than the tunnel, not for
     * every byte (review: a full budget reset streams that could write). */
    if (stream_ctx->pending_first == NULL && !stream_ctx->connecting && !stream_ctx->write_shutdown) {
        int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
        flags |= MSG_NOSIGNAL;
#endif
        ssize_t n;
        do {
            n = send(stream_ctx->fd, bytes, length, flags);
        } while (n < 0 && errno == EINTR);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            slipstream_server_log_error(stream_ctx, "send() failed");
            return -1;
        }
        if (n > 0) {
            stream_ctx->tcp_sent += (uint64_t)n;
            bytes += n;
            length -= (size_t)n;
            if (length == 0) {
                return 0;
            }
        }
    }
    if (length > SLIPSTREAM_PENDING_LIMIT - stream_ctx->pending_bytes) {
        fprintf(stderr, "Upstream write queue exceeded %d bytes on stream %llu\n",
            SLIPSTREAM_PENDING_LIMIT, (unsigned long long)stream_ctx->stream_id);
        return -1;
    }
    if (length > slipstream_pending_max - slipstream_pending_total) {
        fprintf(stderr, "Upstream write queues hold %zu bytes, the limit: stream %llu dropped\n",
            slipstream_pending_total, (unsigned long long)stream_ctx->stream_id);
        return -1;
    }
    /* One connection takes its share of the budget at most (the budget
     * over --max-connections, four streams' limit at least): it cannot
     * starve the others (review: a quarter let four take it all). */
    const size_t share = MAX(slipstream_pending_max / MAX(slipstream_max_connections, (size_t)1), (size_t)4 * SLIPSTREAM_PENDING_LIMIT);
    if (length > share - MIN(share, stream_ctx->owner->pending_bytes)) {
        fprintf(stderr, "A connection's write queues hold %zu bytes, its share: stream %llu dropped\n",
            stream_ctx->owner->pending_bytes, (unsigned long long)stream_ctx->stream_id);
        return -1;
    }
    slipstream_pending_t* pending = malloc(sizeof(*pending) + length);
    if (pending == NULL) {
        return -1;
    }
    pending->next = NULL;
    pending->length = length;
    pending->offset = 0;
    memcpy(pending->data, bytes, length);
    if (stream_ctx->pending_last != NULL) {
        stream_ctx->pending_last->next = pending;
    } else {
        stream_ctx->pending_first = pending;
    }
    stream_ctx->pending_last = pending;
    stream_ctx->pending_bytes += length;
    slipstream_pending_total += length;
    stream_ctx->owner->pending_bytes += length;
    return 0;
}

/* Wait for DNS and upstream readiness together. An activated QUIC stream is
 * no longer polled for reads until prepare_to_send consumes it or sees EAGAIN;
 * otherwise a readable TCP socket would spin while awaiting another DNS poll. */
static int slipstream_server_poll(slipstream_server_ctx_t* default_ctx,
                                  int dns_fd, short* dns_revents) {
    *dns_revents = 0;
    size_t count = 1;
    for (slipstream_server_ctx_t* ctx = default_ctx->next_ctx; ctx != NULL; ctx = ctx->next_ctx) {
        for (slipstream_server_stream_ctx_t* stream = ctx->first_stream; stream != NULL; stream = stream->next_stream) {
            count++;
        }
    }
    if (count > default_ctx->poll_capacity) {
        /* Grow both arrays together; failure preserves the old allocation. */
        struct pollfd* fds = calloc(count, sizeof(*fds));
        slipstream_server_stream_ctx_t** streams = calloc(count, sizeof(*streams));
        if (fds == NULL || streams == NULL) {
            free(fds);
            free(streams);
            return -1;
        }
        free(default_ctx->poll_fds);
        free(default_ctx->poll_streams);
        default_ctx->poll_fds = fds;
        default_ctx->poll_streams = streams;
        default_ctx->poll_capacity = count;
    }
    struct pollfd* fds = default_ctx->poll_fds;
    slipstream_server_stream_ctx_t** streams = default_ctx->poll_streams;
    fds[0] = (struct pollfd){.fd = dns_fd, .events = POLLIN};
    size_t i = 1;
    int timeout = 1000; /* also bound signal/shutdown and connect-deadline latency */
    uint64_t now = picoquic_current_time();
    for (slipstream_server_ctx_t* ctx = default_ctx->next_ctx; ctx != NULL; ctx = ctx->next_ctx) {
        for (slipstream_server_stream_ctx_t* stream = ctx->first_stream; stream != NULL; stream = stream->next_stream) {
            short events = 0;
            if (stream->connecting || stream->pending_first != NULL) {
                events |= POLLOUT;
            }
            if (!stream->connecting && stream->read_wait && !stream->send_fin) {
                events |= POLLIN;
            }
            /* Negative fd suppresses HUP/ERR on a socket with no work. */
            fds[i] = (struct pollfd){.fd = events ? stream->fd : -1, .events = events};
            streams[i++] = stream;
            if (stream->connecting) {
                uint64_t remaining = stream->connect_deadline > now ? stream->connect_deadline - now : 0;
                int ms = (int)MIN((remaining + 999) / 1000, 1000);
                timeout = MIN(timeout, ms);
            }
        }
    }
    int ret = poll(fds, count, timeout);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        perror("poll() failed");
        return -1;
    }
    *dns_revents = fds[0].revents;
    now = picoquic_current_time();
    for (i = 1; i < count; i++) {
        slipstream_server_stream_ctx_t* stream = streams[i];
        slipstream_server_ctx_t* ctx = stream->owner;
        short events = fds[i].revents;
        if (stream->connecting && now >= stream->connect_deadline) {
            fprintf(stderr, "Upstream connect timed out on stream %llu\n",
                (unsigned long long)stream->stream_id);
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
            continue;
        }
        if (events == 0) {
            continue;
        }
        if (events & POLLNVAL) {
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_INTERNAL_ERROR);
            continue;
        }
        if (stream->connecting) {
            int error = 0;
            socklen_t error_len = sizeof(error);
            if (getsockopt(stream->fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
                if (error != 0) {
                    errno = error;
                }
                slipstream_server_log_error(stream, "connect() failed");
                slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
                continue;
            }
            stream->connecting = false;
        }
        if (slipstream_server_flush(stream) != 0) {
            slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_FILE_CANCEL_ERROR);
            continue;
        }
        if (slipstream_server_stream_done(stream)) {
            slipstream_server_free_stream_context(ctx, stream);
            continue;
        }
        if (!stream->send_fin && (events & (POLLIN | POLLHUP | POLLERR))) {
            stream->read_wait = false;
            if (picoquic_mark_active_stream(ctx->cnx, stream->stream_id, 1, stream) != 0) {
                slipstream_server_abort_stream(ctx, stream, SLIPSTREAM_INTERNAL_ERROR);
            }
        }
    }
    return 0;
}

/* Without DNS queries, prepare_packet is never called and PicoQUIC's
 * sender-side idle check does not run. Reap abandoned connections here,
 * between batches, when no DNS slot retains a connection pointer.
 * These deadlines mirror the pinned PicoQUIC check_idle_timer(). */
static void slipstream_server_reap(picoquic_quic_t* quic) {
    uint64_t now = picoquic_current_time();
    picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic);
    while (cnx != NULL) {
        picoquic_cnx_t* next = picoquic_get_next_cnx(cnx);
        uint64_t deadline;
        if (cnx->nb_paths < 1 || cnx->path[0] == NULL) {
            /* Every path abandoned and deleted: nothing reaches it, and
             * the timer below would read path[0] (review). */
            deadline = 0;
        } else if (cnx->cnx_state >= picoquic_state_ready) {
            uint64_t rto = picoquic_current_retransmit_timer(cnx, cnx->path[0]);
            uint64_t interval = MAX(cnx->idle_timeout, 3 * rto);
            deadline = cnx->latest_receive_time + interval;
            if (deadline < interval) {
                deadline = UINT64_MAX;
            }
        } else {
            uint64_t interval = quic->default_handshake_timeout;
            if (interval == 0) {
                interval = cnx->local_parameters.max_idle_timeout > 0 ?
                    cnx->local_parameters.max_idle_timeout * 1000ULL : PICOQUIC_MICROSEC_HANDSHAKE_MAX;
            }
            deadline = cnx->start_time + interval;
        }
        if (cnx->cnx_state == picoquic_state_disconnected || now >= deadline) {
            cnx->local_error = PICOQUIC_ERROR_IDLE_TIMEOUT;
            picoquic_connection_disconnect(cnx);
            picoquic_delete_cnx(cnx);
        }
        cnx = next;
    }
}

int slipstream_server_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    slipstream_server_ctx_t* server_ctx = callback_ctx;
    slipstream_server_stream_ctx_t* stream_ctx = v_stream_ctx;
    slipstream_server_ctx_t* default_ctx = picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
    if (server_ctx == NULL || server_ctx == default_ctx) {
        if (default_ctx == NULL) {
            return -1;
        }
        server_ctx = calloc(1, sizeof(*server_ctx));
        if (server_ctx == NULL) {
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        server_ctx->upstream_addr = default_ctx->upstream_addr;
        server_ctx->cnx = cnx;
        server_ctx->next_ctx = default_ctx->next_ctx;
        server_ctx->prev_ctx = default_ctx;
        if (server_ctx->next_ctx != NULL) {
            server_ctx->next_ctx->prev_ctx = server_ctx;
        }
        default_ctx->next_ctx = server_ctx;
        picoquic_set_callback(cnx, slipstream_server_callback, server_ctx);
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (!PICOQUIC_IS_BIDIR_STREAM_ID(stream_id)) {
            /* The tunnel's streams are the client's bidirectional ones, and
             * the client opens no other: the connection goes. Refused one
             * by one, their records stayed until it ended (picoquic frees a
             * stream once what it sent is acked, and nothing is sent on
             * one), and opening them without end grew memory and CPU
             * (review). */
            (void)picoquic_close(cnx, SLIPSTREAM_INTERNAL_ERROR);
            return 0;
        }
        if (stream_ctx == NULL) {
            /* reset/stop_sending clear app_stream_ctx in this PicoQUIC revision.
             * Late peer data must not resurrect an aborted TCP connection. */
            picoquic_stream_head_t* quic_stream = picoquic_find_stream(cnx, stream_id);
            if (quic_stream == NULL || quic_stream->reset_requested || quic_stream->stop_sending_requested) {
                return 0;
            }
            stream_ctx = slipstream_server_create_stream_ctx(server_ctx, stream_id);
            if (stream_ctx == NULL) {
                (void)picoquic_stop_sending(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
            if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        if (stream_ctx->peer_fin) {
            return 0;
        }
        /* Flush older bytes first, then append without blocking the QUIC loop. */
        if (slipstream_server_flush(stream_ctx) != 0 ||
            slipstream_server_queue(stream_ctx, bytes, length) != 0) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
            return 0;
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            stream_ctx->peer_fin = true;
        }
        if (slipstream_server_flush(stream_ctx) != 0) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
        } else if (slipstream_server_stream_done(stream_ctx)) {
            slipstream_server_free_stream_context(server_ctx, stream_ctx);
        }
        break;
    case picoquic_callback_stop_sending:
    case picoquic_callback_stream_reset:
        if (stream_ctx != NULL) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
        } else {
            (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        /* No callback or worker can retain the connection after teardown. */
        picoquic_set_callback(cnx, NULL, NULL);
        slipstream_server_free_context(server_ctx);
        break;
    case picoquic_callback_prepare_to_send:
        if (stream_ctx == NULL || stream_ctx->connecting || stream_ctx->send_fin) {
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
            return 0;
        }
        if (length == 0) {
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
            return 0;
        }
        /* Read first and advertise only the bytes actually received. FIONREAD
         * followed by recv could previously advertise more than a short read. */
        uint8_t data[16384];
        ssize_t n;
        do {
            n = recv(stream_ctx->fd, data, MIN(length, sizeof(data)), 0);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            int error = errno;
            (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
            if (error == EAGAIN || error == EWOULDBLOCK) {
                stream_ctx->read_wait = true;
            } else {
                errno = error;
                slipstream_server_log_error(stream_ctx, "recv() failed");
                slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_FILE_CANCEL_ERROR);
            }
            return 0;
        }
        stream_ctx->tcp_received += (uint64_t)n;
        uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, (size_t)n, n == 0, n > 0);
        if (buffer == NULL) {
            slipstream_server_abort_stream(server_ctx, stream_ctx, SLIPSTREAM_INTERNAL_ERROR);
            return 0;
        }
        if (n > 0) {
            memcpy(buffer, data, (size_t)n);
        } else {
            /* TCP EOF closes only the server's sending direction. Keep the
             * context for peer data/FIN until its write direction also closes. */
            stream_ctx->send_fin = true;
            stream_ctx->read_wait = false;
            if (slipstream_server_stream_done(stream_ctx)) {
                slipstream_server_free_stream_context(server_ctx, stream_ctx);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

/* Where queries come from: a UDP socket, or a DNS front over a unix
 * SOCK_SEQPACKET socket (one front at a time; it reconnects). */
typedef struct st_server_io_t {
    int udp_fd;     /* UDP mode */
    int listen_fd;  /* front mode: the listening socket */
    int front_fd;   /* front mode: the front's connection, -1 while away */
    long front_uid;
    uint64_t accept_after; /* out of descriptors: no accept before this time */
} server_io_t;

static int server_open_udp(const slipstream_server_config_t* config) {
    struct sockaddr_storage addr = {0};
    socklen_t addr_len;
    if (config->listen_address != NULL) {
        addr = *config->listen_address;
    } else {
        addr.ss_family = config->listen_ipv6 ? AF_INET6 : AF_INET;
    }
    if (addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)&addr)->sin_port = htons((uint16_t)config->listen_port);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        ((struct sockaddr_in6*)&addr)->sin6_port = htons((uint16_t)config->listen_port);
        addr_len = sizeof(struct sockaddr_in6);
    }
    /* Non-blocking: a lone query is answered at once, not when nine more
     * come, and a signal ends the loop (review). */
    int fd = socket(addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd < 0) {
        perror("Unable to create DNS listen socket");
        return -1;
    }
    if (picoquic_socket_set_pkt_info(fd, addr.ss_family) != 0 ||
        bind(fd, (struct sockaddr*)&addr, addr_len) != 0) {
        perror("Unable to bind DNS listen socket");
        close(fd);
        return -1;
    }
    return fd;
}

static int server_open_front(const char* path) {
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Front socket path too long: %s\n", path);
        return -1;
    }
    strcpy(addr.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("Unable to create front socket");
        return -1;
    }
    /* A socket file left by an earlier run would fail the bind. */
    (void)unlink(path);
    /* Who may connect is the directory's business (the front's group) and
     * front_uid's; the socket itself is for owner and group. */
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 || chmod(path, 0660) != 0 || listen(fd, 4) != 0) {
        perror("Unable to listen on front socket");
        close(fd);
        return -1;
    }
    return fd;
}

/* server_accept takes the front's connection: only from front_uid, and only
 * one; a new one replaces the old (the front reconnected). */
static void server_accept(server_io_t* io) {
    int fd = accept4(io->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) {
        if (errno == EMFILE || errno == ENFILE) {
            /* The connection waits in the backlog: the listening socket
             * stays readable. Accepting pauses for 100 ms; the rest of
             * the loop goes on (review: a sleep here slowed every batch). */
            io->accept_after = picoquic_current_time() + 100 * 1000;
        }
        return;
    }
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 ||
        (io->front_uid >= 0 && (long)cred.uid != io->front_uid)) {
        fprintf(stderr, "Front socket: a peer with UID %ld refused\n", len == sizeof(cred) ? (long)cred.uid : -1L);
        close(fd);
        return;
    }
    int size = 4 << 20;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    if (io->front_fd >= 0) {
        close(io->front_fd);
    }
    io->front_fd = fd;
    fprintf(stderr, "Front connected\n");
}

static void server_front_gone(server_io_t* io) {
    if (io->front_fd >= 0) {
        close(io->front_fd);
        io->front_fd = -1;
        fprintf(stderr, "Front disconnected\n");
    }
}

/* server_receive reads one query without waiting: 1 with one, 0 with none,
 * -1 when the UDP socket fails (the front's going away is not an error). */
static int server_receive(server_io_t* io, uint8_t* buffer, size_t size, size_t* length,
                          server_slot_t* slot, struct sockaddr_storage* peer, struct sockaddr_storage* local) {
    memset(peer, 0, sizeof(*peer));
    memset(local, 0, sizeof(*local));
    if (io->front_fd < 0 && io->listen_fd >= 0) {
        return 0;
    }
    if (io->front_fd >= 0) {
        uint8_t message[FRONT_HEADER_LEN + SERVER_MAX_QUERY];
        ssize_t n = recv(io->front_fd, message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                server_front_gone(io);
            }
            return 0;
        }
        if (n == 0) {
            server_front_gone(io);
            return 0;
        }
        /* MSG_TRUNC gives the full length: a longer message was cut. */
        if ((size_t)n > sizeof(message) || (size_t)n <= FRONT_HEADER_LEN ||
            message[0] != 'N' || message[1] != 'U' || message[2] != 1 || (size_t)n - FRONT_HEADER_LEN > size) {
            *length = 0;
            return 1;
        }
        memcpy(slot->front_addrs, message + 3, FRONT_ADDRS_LEN);
        *length = (size_t)n - FRONT_HEADER_LEN;
        memcpy(buffer, message + FRONT_HEADER_LEN, *length);
        /* QUIC sees a dummy address either way (server_decode). */
        ((struct sockaddr_in*)peer)->sin_family = AF_INET;
        ((struct sockaddr_in*)local)->sin_family = AF_INET;
        return 1;
    }
    int if_index = 0;
    uint8_t ecn = 0;
    int n = picoquic_recvmsg(io->udp_fd, peer, local, &if_index, &ecn, buffer, (int)size);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0;
        }
        /* ICMP errors and the like come back on a UDP socket: not fatal. */
        if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH) {
            *length = 0;
            return 1;
        }
        perror("DNS socket receive failed");
        return -1;
    }
    *length = (size_t)n;
    return 1;
}

/* server_send sends one answer; a failure drops it. */
static void server_send(server_io_t* io, const server_slot_t* slot, const uint8_t* answer, size_t length,
                        struct sockaddr_storage* peer, struct sockaddr_storage* local) {
    if (io->listen_fd >= 0) {
        if (io->front_fd < 0 || length > SERVER_MAX_QUERY) {
            return;
        }
        uint8_t message[FRONT_HEADER_LEN + MAX_UDP_PACKET_SIZE];
        if (length > sizeof(message) - FRONT_HEADER_LEN) {
            return;
        }
        message[0] = 'N';
        message[1] = 'U';
        message[2] = 1;
        memcpy(message + 3, slot->front_addrs, FRONT_ADDRS_LEN);
        memcpy(message + FRONT_HEADER_LEN, answer, length);
        ssize_t n = send(io->front_fd, message, FRONT_HEADER_LEN + length, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ENOBUFS) {
            server_front_gone(io);
        }
        return;
    }
    int sock_err = 0;
    (void)picoquic_sendmsg(io->udp_fd, (struct sockaddr*)peer, (struct sockaddr*)local, 0,
        (const char*)answer, (int)length, 0, &sock_err);
}

/* Stateless packets (version negotiation, stateless resets) would go to the
 * dummy address and nowhere: the queue grew by one for every long header
 * of another version. They are dropped as they come. */
static void server_drop_stateless(picoquic_quic_t* quic) {
    picoquic_stateless_packet_t* sp;
    while ((sp = picoquic_dequeue_stateless_packet(quic)) != NULL) {
        picoquic_delete_stateless_packet(sp);
    }
}

/* server_loop answers queries until a signal: each query gets one answer
 * (the next QUIC packet of its connection, or none) or, when it does not
 * read, nothing. A bad datagram never ends it. */
/* How long the ranges of packet numbers received stay before the ACK
 * horizon takes them (µs): everything below the horizon counts as received.
 * picoquic leaves the delay at 0, and then deletes a range once the peer
 * has acknowledged the ACK that carried it: a copy of an older packet was
 * taken as new (review: replays of a device's query got the connection's
 * next packet). 10 s: a resolver's retries come within it. */
#define SERVER_ACK_HORIZON_US (10 * 1000000LL)

/* Keeps a sack list's received packet numbers: the horizon delay, and the
 * horizon raised to the lowest range kept. picoquic also moves the start of
 * the highest range up once the peer acknowledged the ACK that carried it,
 * whatever the delay: the numbers below it were received, and would be
 * taken again. Below the lowest range is what was received and forgotten,
 * or lost: a packet that comes later than that is dropped, and QUIC sends
 * its frames again. */
static void server_keep_sack(picoquic_sack_list_t* sack_list) {
    if (sack_list->horizon_delay == 0) {
        sack_list->horizon_delay = SERVER_ACK_HORIZON_US;
    }
    picoquic_sack_item_t* first = picoquic_sack_first_item(sack_list);
    if (first != NULL && first->start_of_sack_range > sack_list->ack_horizon) {
        sack_list->ack_horizon = first->start_of_sack_range;
    }
}

/* Keeps the received packet numbers of cnx's 1-RTT packets, those a copy
 * would carry once the handshake is done: its application context, and each
 * path's own in multipath (paths come and go). Initial and Handshake are left
 * as they are: a ClientHello in two packets may come in reversed. */
static void server_keep_horizon(picoquic_cnx_t* cnx) {
    server_keep_sack(&cnx->ack_ctx[picoquic_packet_context_application].sack_list);
    for (int k = 0; k < cnx->nb_paths; k++) {
        if (cnx->path[k] != NULL) {
            server_keep_sack(&cnx->path[k]->ack_ctx.sack_list);
        }
    }
}

/* The packets picoquic took, by a hash of their bytes, for 30 to 60 s: a
 * copy is the same bytes, and picoquic does not always know it for one
 * (once the peer has acknowledged an ACK, the highest range of received
 * numbers starts after it, and what was cut off counts as never received
 * until the horizon reaches it). A copy goes no further than this. Two
 * generations of open addressing, the older dropped every 30 s, or early
 * when the newer is half full (a heavy load: ~4000 packets a second). */
#define SEEN_SLOTS (1u << 18)
#define SEEN_GENERATION_US (30 * 1000000ULL)
typedef struct {
    uint64_t* gens[2]; /* SEEN_SLOTS each; 0 is a free slot */
    size_t count;      /* in gens[0] */
    uint64_t started;  /* gens[0]'s start */
    uint64_t seed;
} seen_packets_t;
static seen_packets_t seen_packets;

static uint64_t seen_hash(const uint8_t* bytes, size_t len) {
    uint64_t h = 1469598103934665603ULL ^ seen_packets.seed;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    h ^= h >> 29;
    return h != 0 ? h : 1;
}

static bool seen_in(const uint64_t* gen, uint64_t h) {
    for (uint32_t i = (uint32_t)h & (SEEN_SLOTS - 1);; i = (i + 1) & (SEEN_SLOTS - 1)) {
        if (gen[i] == 0) {
            return false;
        }
        if (gen[i] == h) {
            return true;
        }
    }
}

/* Whether a packet of this hash was taken in the last 30 to 60 s. */
static bool seen_packet(uint64_t h, uint64_t now) {
    if (seen_packets.gens[0] == NULL) {
        return false;
    }
    if (now - seen_packets.started >= SEEN_GENERATION_US) {
        uint64_t* old = seen_packets.gens[1];
        seen_packets.gens[1] = seen_packets.gens[0];
        memset(old, 0, SEEN_SLOTS * sizeof(*old));
        seen_packets.gens[0] = old;
        seen_packets.count = 0;
        seen_packets.started = now;
    }
    return seen_in(seen_packets.gens[0], h) || seen_in(seen_packets.gens[1], h);
}

/* Remembers a packet picoquic took. */
static void seen_take(uint64_t h, uint64_t now) {
    if (seen_packets.gens[0] == NULL) {
        return;
    }
    if (seen_packets.count >= SEEN_SLOTS / 2) {
        seen_packets.started = now - SEEN_GENERATION_US; /* the next look turns */
        (void)seen_packet(h, now);
    }
    uint32_t i = (uint32_t)h & (SEEN_SLOTS - 1);
    while (seen_packets.gens[0][i] != 0) {
        if (seen_packets.gens[0][i] == h) {
            return;
        }
        i = (i + 1) & (SEEN_SLOTS - 1);
    }
    seen_packets.gens[0][i] = h;
    seen_packets.count++;
}

/* A path a packet can go on: not demoted nor about to be (a failed
 * challenge: prepare demotes it and clears its connection ID before using
 * it, review), with the peer's connection ID. */
static bool server_path_usable(const picoquic_path_t* path) {
    return path != NULL && !path->path_is_demoted && !path->challenge_failed && path->p_remote_cnxid != NULL;
}

/* Whether a connection has a path a packet can go on. */
static bool server_has_path(const picoquic_cnx_t* cnx) {
    if (cnx->cnx_state == picoquic_state_disconnected) {
        return false;
    }
    for (int k = 0; k < cnx->nb_paths; k++) {
        if (server_path_usable(cnx->path[k])) {
            return true;
        }
    }
    return false;
}

/* The first path of cnx a packet can go on; there is one (server_has_path). */
static int server_first_path(const picoquic_cnx_t* cnx) {
    for (int k = 0; k < cnx->nb_paths; k++) {
        if (server_path_usable(cnx->path[k])) {
            return k;
        }
    }
    return 0;
}

static int server_loop(picoquic_quic_t* quic, slipstream_server_ctx_t* default_ctx, server_io_t* io) {
    static server_slot_t slots[PICOQUIC_PACKET_LOOP_RECV_MAX];
    uint8_t buffer[SERVER_MAX_QUERY];
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t last_receive_time = 0; /* strictly increasing: see the receive below */
    while (!should_shutdown) {
        slipstream_server_reap(quic);
        short revents = 0;
        int dns_fd = io->listen_fd < 0 ? io->udp_fd : (io->front_fd >= 0 ? io->front_fd : io->listen_fd);
        if (slipstream_server_poll(default_ctx, dns_fd, &revents) != 0) {
            return -1;
        }
        if (io->listen_fd >= 0) {
            const uint64_t now = picoquic_current_time();
            if (io->front_fd < 0) {
                if (revents & POLLIN) {
                    if (now < io->accept_after) {
                        /* No front, so no queries: waiting is all there is
                         * to do, and polling again would spin. */
                        usleep((useconds_t)(io->accept_after - now));
                    } else {
                        server_accept(io);
                    }
                }
                continue;
            }
            if ((revents & (POLLERR | POLLNVAL)) || ((revents & POLLHUP) && !(revents & POLLIN))) {
                server_front_gone(io);
                continue;
            }
            /* A front that reconnected while this one is up replaces it. */
            struct pollfd listen_poll = {.fd = io->listen_fd, .events = POLLIN};
            if (now >= io->accept_after && poll(&listen_poll, 1, 0) > 0 && (listen_poll.revents & POLLIN)) {
                server_accept(io);
            }
        } else if (revents & POLLNVAL) {
            fprintf(stderr, "DNS listen socket failed\n");
            return -1;
        }

        size_t nb_slots = 0;
        /* Datagrams that get no answer count too: a flood of them must not
         * keep the batch from its answers (review). */
        size_t nb_reads = 0;
        while (nb_slots < PICOQUIC_PACKET_LOOP_RECV_MAX && nb_reads < 8 * PICOQUIC_PACKET_LOOP_RECV_MAX && !should_shutdown) {
            nb_reads++;
            server_slot_t* slot = &slots[nb_slots];
            memset(slot, 0, sizeof(*slot));
            slot->s.path_id = -1;
            struct sockaddr_storage peer_addr;
            struct sockaddr_storage local_addr;
            size_t length = 0;
            int got = server_receive(io, buffer, sizeof(buffer), &length, slot, &peer_addr, &local_addr);
            if (got < 0) {
                return -1;
            }
            if (got == 0) {
                break;
            }
            if (length == 0) {
                continue; /* read, but nothing to answer */
            }
            unsigned char* decoded = NULL;
            ssize_t decoded_len = server_decode(slot, default_ctx, &decoded, buffer, length, &peer_addr, &local_addr);
            if (decoded_len < 0) {
                continue; /* no answer: not a query of this tunnel */
            }
            slot->answer = true;
            nb_slots++;
            if (decoded_len == 0) {
                continue;
            }
            picoquic_cnx_t* last_cnx = NULL;
            int last_path_id = -1;
            /* A time no earlier call had: picoquic sets the connection's
             * latest_receive_time to it only for a packet it took. A copy
             * of a packet it already had, or one it cannot open, still
             * names the connection (its DCID) with no error; bound to it,
             * the query took the connection's next packet to the copy's
             * address (review: replays of a device's query through the
             * front, slipstream-v1 §1 item 5). It is answered empty. */
            uint64_t receive_time = picoquic_current_time();
            if (receive_time <= last_receive_time) {
                receive_time = last_receive_time + 1;
            }
            last_receive_time = receive_time;
            const uint64_t packet_hash = seen_hash(decoded, (size_t)decoded_len);
            if (seen_packet(packet_hash, receive_time)) {
                free(decoded);
                continue; /* a copy: answered empty */
            }
            int ret = picoquic_incoming_packet_ex(quic, decoded, (size_t)decoded_len,
                (struct sockaddr*)&peer_addr, (struct sockaddr*)&local_addr, 0, 0,
                &last_cnx, &last_path_id, receive_time);
            free(decoded);
            if (last_cnx != NULL) {
                server_keep_horizon(last_cnx);
            }
            if (ret != 0 || last_cnx == NULL || last_cnx->latest_receive_time != receive_time) {
                continue; /* answered empty */
            }
            seen_take(packet_hash, receive_time);
            slot->s.cnx = last_cnx;
            slot->s.path_id = last_path_id;
            if (last_path_id >= 0 && last_path_id < last_cnx->nb_paths && last_cnx->path[last_path_id] != NULL) {
                slot->unique_path_id = last_cnx->path[last_path_id]->unique_path_id;
            } else {
                slot->s.path_id = -1;
            }
            last_cnx->no_ack_delay = 1;
        }
        server_drop_stateless(quic);

        /* Never before a receive time given out above (picoquic takes
         * the difference for the ACK delay). */
        uint64_t loop_time = picoquic_current_time();
        if (loop_time < last_receive_time) {
            loop_time = last_receive_time;
        }
        for (size_t i = 0; i < nb_slots; i++) {
            server_slot_t* slot = &slots[i];
            if (!slot->answer) {
                continue;
            }
            size_t send_length = 0;
            struct sockaddr_storage peer_addr = {0};
            struct sockaddr_storage local_addr = {0};
            int if_index = 0;
            if (slot->s.error == RCODE_OKAY && slot->s.cnx != NULL && !server_has_path(slot->s.cnx)) {
                /* Every path abandoned (the client's PATH_ABANDON, or a
                 * picoquic demotion): prepare would take one without a
                 * connection ID, or none at all once they are deleted, and
                 * crash (review: a client with two resolvers took the
                 * server down). The connection goes; the query is answered
                 * empty. */
                picoquic_connection_disconnect(slot->s.cnx);
                slot->s.cnx = NULL;
            }
            if (slot->s.error == RCODE_OKAY && slot->s.cnx != NULL) {
                /* prepare deletes abandoned paths first, which moves the
                 * indexes, then takes the one it was given: a path gone
                 * since the query (or by an earlier slot's prepare) was a
                 * NULL dereference (review). The same deletion here, for
                 * any slot, then the path by its unique ID, or none. */
                picoquic_cnx_t* cnx = slot->s.cnx;
                if (cnx->path_demotion_needed) {
                    uint64_t next_wake = UINT64_MAX;
                    picoquic_delete_abandoned_paths(cnx, loop_time, &next_wake);
                }
                if (slot->s.path_id >= 0) {
                    slot->s.path_id = picoquic_find_path_by_unique_id(cnx, slot->unique_path_id);
                }
                if (!server_has_path(cnx)) {
                    picoquic_connection_disconnect(cnx);
                    slot->s.cnx = NULL;
                }
            }
            if (slot->s.error == RCODE_OKAY && slot->s.cnx != NULL &&
                (slot->s.path_id < 0 || !server_path_usable(slot->s.cnx->path[slot->s.path_id]))) {
                /* The slot's path gone, abandoned, or never known: a path
                 * a packet can go on, named. Left to picoquic (-1), it may
                 * take one still waiting for the peer's connection ID
                 * (review). */
                slot->s.path_id = server_first_path(slot->s.cnx);
            }
            if (slot->s.error == RCODE_OKAY && slot->s.cnx != NULL &&
                picoquic_prepare_packet_ex(slot->s.cnx, slot->s.path_id, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, NULL) != 0) {
                send_length = 0;
            }
            unsigned char* encoded = NULL;
            size_t segment_len = send_length;
            ssize_t encoded_len = server_encode(slot, default_ctx, &encoded, send_buffer, send_length,
                &segment_len, &peer_addr, &local_addr);
            if (encoded_len <= 0 || encoded == NULL) {
                free(encoded);
                continue;
            }
            server_send(io, slot, encoded, (size_t)encoded_len, &peer_addr, &local_addr);
            free(encoded);
        }
        server_drop_stateless(quic);
    }
    return 0;
}

int picoquic_slipstream_server(const slipstream_server_config_t* cfg) {
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    uint64_t current_time = 0;
    slipstream_server_ctx_t default_context = {0};

    memcpy(&default_context.upstream_addr, &cfg->target, sizeof(struct sockaddr_storage));

    server_domain_name = strdup(cfg->domain);
    server_domain_name_len = strlen(cfg->domain);
    server_tag_len = cfg->tag_len;
    slipstream_pending_max = cfg->max_pending;
    slipstream_max_connections = cfg->max_connections;

    /* The packets taken, for copies (4 MiB). */
    seen_packets.gens[0] = calloc(SEEN_SLOTS, sizeof(uint64_t));
    seen_packets.gens[1] = calloc(SEEN_SLOTS, sizeof(uint64_t));
    if (seen_packets.gens[0] == NULL || seen_packets.gens[1] == NULL) {
        fprintf(stderr, "Could not allocate the memory of packets taken\n");
        return -1;
    }
    if (getrandom(&seen_packets.seed, sizeof(seen_packets.seed), 0) != (ssize_t)sizeof(seen_packets.seed)) {
        seen_packets.seed = picoquic_current_time();
    }
    seen_packets.started = picoquic_current_time();

    /* A target socket per stream: a connection may have about 1.5 times
     * --max-streams at once (picoquic opens the next ones before the
     * closed ones go). The soft limit goes up to the hard one, and a
     * limit below what the options allow is said (review: 1024 left
     * every stream past ~11 busy connections reset). */
    struct rlimit nofile;
    if (getrlimit(RLIMIT_NOFILE, &nofile) == 0) {
        if (nofile.rlim_cur < nofile.rlim_max) {
            nofile.rlim_cur = nofile.rlim_max;
            (void)setrlimit(RLIMIT_NOFILE, &nofile);
            (void)getrlimit(RLIMIT_NOFILE, &nofile);
        }
        const unsigned long long need = (unsigned long long)cfg->max_connections * cfg->max_streams * 3 / 2 + 64;
        if (nofile.rlim_cur != RLIM_INFINITY && (unsigned long long)nofile.rlim_cur < need) {
            fprintf(stderr, "Warning: %llu file descriptors, and --max-connections with --max-streams allow %llu target sockets: "
                "streams past the limit are reset (raise LimitNOFILE or lower the options)\n",
                (unsigned long long)nofile.rlim_cur, need);
        }
    }

    int mtu = 900;

    /* Create config */
    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = cfg->max_connections;
    config.server_cert_file = cfg->cert;
    config.server_key_file = cfg->key;
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = cfg->listen_port;
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.multipath_option = 1;
    config.use_long_log = 1;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    /* No key log: SSLKEYLOGFILE would write the session keys out. */
    config.enable_sslkeylog = 0;
    config.alpn = cfg->alpn;
    /* 0 left connections without a limit: a client that went away kept
     * its place until a restart. */
    config.idle_timeout = (int)cfg->idle_timeout_ms;

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    picoquic_quic_t* quic = picoquic_create_and_configure(&config, slipstream_server_callback, &default_context, current_time, NULL);
    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        free(server_domain_name);
        server_domain_name = NULL;
        return -1;
    }

    picoquic_set_cookie_mode(quic, 0);
    /* A connection that never finishes its handshake held its place for the
     * idle timeout (review): 10 s, as the reaper reads it too. */
    picoquic_set_default_handshake_timeout(quic, 10 * 1000000ULL);
    picoquic_set_default_priority(quic, 2);
#ifdef BUILD_LOGLIB
    picoquic_set_qlog(quic, config.qlog_dir);
    debug_printf_push_stream(stderr);
#endif
    picoquic_set_default_congestion_algorithm(quic, slipstream_server_cc_algorithm);
    picoquic_tp_t tp = *picoquic_get_default_tp(quic);
    tp.initial_max_stream_id_bidir = cfg->max_streams;
    /* 0 means no limit to picoquic: one frame on a far stream ID made it
     * allocate every stream below it (review). The client opens none; the
     * callback refuses one anyway. */
    tp.initial_max_stream_id_unidir = 1;
    picoquic_set_default_tp(quic, &tp);

    server_io_t io = {.udp_fd = -1, .listen_fd = -1, .front_fd = -1, .front_uid = cfg->front_uid};
    if (cfg->front_socket != NULL) {
        io.listen_fd = server_open_front(cfg->front_socket);
    } else {
        io.udp_fd = server_open_udp(cfg);
    }
    if (io.udp_fd < 0 && io.listen_fd < 0) {
        ret = -1;
    } else {
        /* Without SA_RESTART: a blocked call returns on a signal. */
        struct sigaction sa = {0};
        sa.sa_handler = server_sighandler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        signal(SIGPIPE, SIG_IGN);
        ret = server_loop(quic, &default_context, &io);
    }

    /* And finish. */
    DBG_PRINTF("Server exit, ret = %d", ret);

    if (io.front_fd >= 0) {
        close(io.front_fd);
    }
    if (io.listen_fd >= 0) {
        close(io.listen_fd);
        (void)unlink(cfg->front_socket);
    }
    if (io.udp_fd >= 0) {
        close(io.udp_fd);
    }
    /* Also cover packet-loop errors: PicoQUIC does not promise a close
     * callback for every connection when its entire context is freed. */
    while (default_context.next_ctx != NULL) {
        slipstream_server_ctx_t* ctx = default_context.next_ctx;
        picoquic_set_callback(ctx->cnx, NULL, NULL);
        slipstream_server_free_context(ctx);
    }
    free(default_context.poll_fds);
    free(default_context.poll_streams);
    picoquic_free(quic);
    free(server_domain_name);
    server_domain_name = NULL;

    return ret;
}
