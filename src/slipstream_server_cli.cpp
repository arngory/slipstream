#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <picosocks.h>
#include <sys/un.h>
#include "slipstream.h"
#include "quick_arg_parser.hpp"

struct ServerArgs : MainArguments<ServerArgs> {
    using MainArguments<ServerArgs>::MainArguments;

    int listen_port = option("dns-listen-port", 'l', "DNS listen port (default: 53)") = 53;
    std::string listen_address = option("dns-listen-address", 'b', "DNS listen IPv4/IPv6 literal (default: wildcard; overrides --dns-listen-ipv6)");
    bool listen_ipv6 = option("dns-listen-ipv6", '6', "DNS listen on IPv6 (default: false)") = false;
    std::string front_socket = option("front-socket", 'f', "Take queries from a DNS front on this unix SOCK_SEQPACKET socket instead of UDP");
    long front_uid = option("front-uid", 'u', "The DNS front's UID: other peers of --front-socket are refused (required with it)") = -1;
    std::string target_address = option("target-address", 'a', "Target server address (default: 127.0.0.1:5201)") = "127.0.0.1:5201";
    std::string target_unix = option("target-unix", 'x', "Target unix stream socket (instead of --target-address)");
    std::string cert = option("cert", 'c', "Certificate file path (required)");
    std::string key = option("key", 'k', "Private key file path (required)");
    std::string domain = option("domain", 'd', "Domain name this server is authoritative for (Required)");
    std::string alpn = option("alpn", 'n', "ALPN the clients must offer (required)");
    long idle_timeout = option("idle-timeout", 'i', "Seconds a connection may stay silent (default: 120)") = 120;
    long max_connections = option("max-connections", 'm', "Connections at once (default: 64)") = 64;
    long max_streams = option("max-streams", 's', "Streams at once per connection (default: 64)") = 64;
    long max_pending = option("max-pending-mib", 'p', "MiB queued towards the target, all streams together (default: 64)") = 64;
    long tag_len = option("tag-len", 't', "Bytes at the start of each query's data that the front checked (dnsauth-v2: 8; default: 0)") = 0;
    long max_device_connections = option("max-connections-per-device", '\0', "Connections at once of one device, as the front names it (IPC version 2): over it, the device's connection silent longest goes, or the new one (default: 0, no limit)") = 0;

    static std::string help(const std::string& program_name) {
        return "slipstream-server - A high-performance covert channel over DNS (server)\n\n" 
               "Usage: " + program_name + " [options]";
    }

    static const std::string version;
};

const std::string ServerArgs::version = "slipstream-server 0.1";

/* Preflight file access so a missing PEM does not become an unexplained -1. */
static bool check_readable_file(const std::string& path, const char* description) {
    FILE* file = std::fopen(path.c_str(), "rb");
    if (file == NULL) {
        const int error = errno;
        std::cerr << "Error: unable to open " << description << " file: "
                  << path << ": " << std::strerror(error) << std::endl;
        return false;
    }
    std::fclose(file);
    return true;
}

int main(int argc, char** argv) {
    int exit_code = 0;
    ServerArgs args(argc, argv);

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // Ensure output buffers are flushed immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory server arguments */
    if (args.domain.empty()) {
        std::cerr << "Server error: Missing required --domain option" << std::endl;
        exit(1);
    }
    if (args.domain.size() > 200) {
        std::cerr << "Server error: --domain is too long" << std::endl;
        return 1;
    }
    /* The ALPN goes in every Initial packet: no fixed default, so that
     * servers do not share one mark (docs/server-front.md). */
    if (args.alpn.empty() || args.alpn.size() > 255) {
        std::cerr << "Server error: --alpn is required (1-255 bytes)" << std::endl;
        return 1;
    }
    if (args.cert.empty() || args.key.empty()) {
        std::cerr << "Server error: --cert and --key are required (the public test key is not used)" << std::endl;
        return 1;
    }
    if (args.idle_timeout < 5 || args.idle_timeout > 3600 ||
        args.max_connections < 1 || args.max_connections > 4096 ||
        args.max_streams < 1 || args.max_streams > 4096 ||
        args.max_pending < 1 || args.max_pending > 4096 ||
        args.tag_len < 0 || args.tag_len > 64 ||
        args.front_uid < -1 || args.front_uid > 0x7fffffffL ||
        args.max_device_connections < 0 || args.max_device_connections > args.max_connections) {
        std::cerr << "Server error: --idle-timeout 5..3600, --max-connections and --max-streams 1..4096, "
                     "--max-pending-mib 1..4096, --tag-len 0..64, --front-uid -1 or a UID, "
                     "--max-connections-per-device 0..--max-connections" << std::endl;
        return 1;
    }

    if (args.listen_port <= 0 || args.listen_port > 65535) {
        std::cerr << "Invalid DNS listen port: " << args.listen_port << std::endl;
        return 1;
    }

    struct sockaddr_storage dns_listen_address = {};
    const struct sockaddr_storage* dns_listen_address_ptr = NULL;
    if (!args.listen_address.empty()) {
        struct sockaddr_in* v4 = (struct sockaddr_in*)&dns_listen_address;
        struct sockaddr_in6* v6 = (struct sockaddr_in6*)&dns_listen_address;
        if (inet_pton(AF_INET, args.listen_address.c_str(), &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
        } else if (inet_pton(AF_INET6, args.listen_address.c_str(), &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
        } else {
            std::cerr << "Invalid DNS listen address '" << args.listen_address
                      << "': expected an IPv4 or IPv6 literal (without a port)"
                      << std::endl;
            return 1;
        }
        dns_listen_address_ptr = &dns_listen_address;
    }
    /* Whoever reaches the socket would be the front, and the front checks
     * the device tags the server only skips (review). */
    if (!args.front_socket.empty() && args.front_uid < 0) {
        std::cerr << "Server error: --front-socket needs --front-uid, the front's UID" << std::endl;
        return 1;
    }
    if (!args.front_socket.empty() && args.front_socket.size() >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        std::cerr << "Server error: --front-socket path is too long" << std::endl;
        return 1;
    }

    const bool cert_readable = check_readable_file(args.cert, "certificate");
    const bool key_readable = check_readable_file(args.key, "private key");
    if (!cert_readable || !key_readable) {
        std::cerr << "Use --cert PATH and --key PATH to select readable PEM files."
                  << std::endl;
        return 1;
    }

    slipstream_server_config_t config = {};
    if (!args.target_unix.empty()) {
        struct sockaddr_un* un = (struct sockaddr_un*)&config.target;
        if (args.target_unix.size() >= sizeof(un->sun_path)) {
            std::cerr << "Server error: --target-unix path is too long" << std::endl;
            return 1;
        }
        un->sun_family = AF_UNIX;
        memcpy(un->sun_path, args.target_unix.c_str(), args.target_unix.size() + 1);
    } else {
        // Process target address
        char server_name[256];
        int server_port = 5201;

        if (sscanf(args.target_address.c_str(), "%255[^:]:%d", server_name, &server_port) < 1) {
            strncpy(server_name, args.target_address.c_str(), sizeof(server_name) - 1);
            server_name[sizeof(server_name) - 1] = '\0';
        }

        if (server_port <= 0 || server_port > 65535) {
            std::cerr << "Invalid port number in target address: " << args.target_address << std::endl;
            exit(1);
        }

        int is_name = 0;
        if (picoquic_get_server_address(server_name, server_port, &config.target, &is_name) != 0) {
            std::cerr << "Cannot resolve target address '" << server_name << "' port " << server_port << std::endl;
            exit(1);
        }
    }

    config.listen_port = args.listen_port;
    config.listen_ipv6 = args.listen_ipv6;
    config.listen_address = dns_listen_address_ptr;
    config.front_socket = args.front_socket.empty() ? NULL : args.front_socket.c_str();
    config.front_uid = args.front_uid;
    config.cert = args.cert.c_str();
    config.key = args.key.c_str();
    config.domain = args.domain.c_str();
    config.alpn = args.alpn.c_str();
    config.idle_timeout_ms = (uint64_t)args.idle_timeout * 1000;
    config.max_connections = (uint32_t)args.max_connections;
    config.max_streams = (uint32_t)args.max_streams;
    config.max_pending = (size_t)args.max_pending << 20;
    config.tag_len = (size_t)args.tag_len;
    config.max_device_connections = (uint32_t)args.max_device_connections;
    exit_code = picoquic_slipstream_server(&config);

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
