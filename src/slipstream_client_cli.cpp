#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <picosocks.h>
#include "slipstream.h"
#include "slipstream_dnsauth.h"
#include <openssl/crypto.h>
#include "quick_arg_parser.hpp"

struct ClientArgs : MainArguments<ClientArgs> {
    using MainArguments<ClientArgs>::MainArguments;

    int listen_port = option("tcp-listen-port", 'l', "Listen port (default: 5201)") = 5201;
    std::string listen_host = option("tcp-listen-host", '\0', "Listen address, IPv4 (default: 127.0.0.1)") = "127.0.0.1";
    std::vector<std::string> resolver = option("resolver", 'r', "Slipstream server resolver address (e.g., 1.1.1.1, 8.8.8.8:53, or [2001:db8::1]:53 for IPv6). Can be specified multiple times. (Required)");
    std::string congestion_control = option("congestion-control", 'c', "Congestion control algorithm (bbr, dcubic) (default: dcubic)") = "dcubic";
    bool gso = option('g', "GSO enabled (true/false) (default: false). Use --gso or --gso=true to enable.");
    std::string domain = option("domain", 'd', "Domain name used for the covert channel (Required)");
    int keep_alive_interval = option("keep-alive-interval", 't', "Send keep alive pings at this interval (default: 400, disabled: 0)") = 400;
    std::string alpn = option("alpn", '\0', "The ALPN the server takes (default: " SLIPSTREAM_ALPN ")") = SLIPSTREAM_ALPN;
    std::string sni = option("sni", '\0', "The server name the TLS ClientHello carries (default: " SLIPSTREAM_SNI ")") = SLIPSTREAM_SNI;
    std::string pin = option("pin", '\0', "The server's public key: base64url SHA-256 of its SubjectPublicKeyInfo (Required unless --insecure)");
    bool insecure = option("insecure", '\0', "Take any certificate the server shows (no --pin): the tunnel is open to whoever answers");
    bool dnsauth = option("dnsauth", '\0', "dnsauth-v2 on every query with the device's key from SLIPSTREAM_DNSAUTH_KEY (64 hex)");
    int clock_offset = option("clock-offset", '\0', "With --dnsauth: the node's clock less this one, in seconds (default: 0)") = 0;
    bool quiet = option("quiet", 'q', "Nothing on stdout (a line per stream event there); errors stay on stderr");

    static std::string help(const std::string& program_name) {
        return "slipstream-client - A high-performance covert channel over DNS (client)\n\n" 
               "Usage: " + program_name + " [options]";
    }

    static const std::string version;
};

const std::string ClientArgs::version = "slipstream-client 0.1";

int main(int argc, char** argv) {
    int exit_code = 0;
    ClientArgs args(argc, argv);

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // the stream events stay out of the log of whoever runs the client (Niko writes each line of it)
    if (args.quiet && freopen("/dev/null", "w", stdout) == NULL) {
        std::cerr << "Client error: --quiet: " << strerror(errno) << std::endl;
        exit(1);
    }
    // Ensure output buffers are flushed immediately (useful for debugging/logging)
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory client arguments */
    if (args.domain.empty()) {
        std::cerr << "Client error: Missing required --domain option" << std::endl;
        exit(1);
    }
    if (args.resolver.empty()) {
        std::cerr << "Client error: Missing required --resolver option (at least one required)" << std::endl;
        exit(1);
    }
    if (args.pin.empty() && !args.insecure) {
        std::cerr << "Client error: Missing required --pin option (or --insecure to take any certificate)" << std::endl;
        exit(1);
    }
    if (!args.pin.empty() && args.insecure) {
        std::cerr << "Client error: --pin and --insecure together" << std::endl;
        exit(1);
    }
    struct in_addr listen_in;
    if (inet_pton(AF_INET, args.listen_host.c_str(), &listen_in) != 1) {
        std::cerr << "Client error: --tcp-listen-host is not an IPv4 address: " << args.listen_host << std::endl;
        exit(1);
    }
    if (args.alpn.empty() || args.alpn.size() > 255 || args.sni.empty()) {
        std::cerr << "Client error: --alpn (1 to 255 bytes) and --sni cannot be empty" << std::endl;
        exit(1);
    }

    // Process resolver addresses
    std::vector<st_address_t> resolver_addresses;
    bool ipv4 = false;
    bool ipv6 = false;
    for (const auto& res_str : args.resolver) {
        st_address_t addr;
        char server_name[256];
        int server_port = 53;

        if (res_str[0] == '[') {
            const char* closing_bracket = strchr(res_str.c_str(), ']');
            if (closing_bracket != NULL) {
                size_t addr_len = closing_bracket - (res_str.c_str() + 1);
                if (addr_len < sizeof(server_name)) {
                    memcpy(server_name, res_str.c_str() + 1, addr_len);
                    server_name[addr_len] = '\0';
                    if (closing_bracket[1] == ':') {
                        server_port = atoi(closing_bracket + 2);
                    }
                    ipv6 = true;
                } else {
                    std::cerr << "Invalid IPv6 address in resolver: " << res_str << std::endl;
                    exit(1);
                }
            } else {
                std::cerr << "Invalid IPv6 address format (missing closing bracket): " << res_str << std::endl;
                exit(1);
            }
        } else {
            if (sscanf(res_str.c_str(), "%255[^:]:%d", server_name, &server_port) < 1) {
                strncpy(server_name, res_str.c_str(), sizeof(server_name) - 1);
                server_name[sizeof(server_name) - 1] = '\0';
                ipv4 = true;
            }
        }

        if (server_port <= 0 || server_port > 65535) {
            std::cerr << "Invalid port number in resolver address: " << res_str << std::endl;
            exit(1);
        }

        int is_name = 0;
        if (picoquic_get_server_address(server_name, server_port, &addr.server_address, &is_name) != 0) {
            std::cerr << "Cannot resolve resolver address '" << server_name << "' port " << server_port << std::endl;
            exit(1);
        }
        resolver_addresses.push_back(addr);
    }

    if (ipv4 && ipv6) {
        // due to single param.local_af in slipstream_client.c
        std::cerr << "Cannot mix IPv4 and IPv6 resolver addresses" << std::endl;
        exit(1);
    }

    /* the key from the environment, not the arguments (which other processes may read), then gone from it */
    slipstream_client_dnsauth_t dnsauth_conf;
    memset(&dnsauth_conf, 0, sizeof(dnsauth_conf));
    const char* dnsauth_key = getenv("SLIPSTREAM_DNSAUTH_KEY");
    if (args.dnsauth) {
        if (slipstream_dnsauth_parse_key(dnsauth_key, dnsauth_conf.key) != 0) {
            std::cerr << "Client error: --dnsauth needs SLIPSTREAM_DNSAUTH_KEY, 64 hex digits" << std::endl;
            exit(1);
        }
        dnsauth_conf.clock_offset = args.clock_offset;
    } else if (dnsauth_key != NULL) {
        std::cerr << "Client error: SLIPSTREAM_DNSAUTH_KEY without --dnsauth" << std::endl;
        exit(1);
    }
    if (dnsauth_key != NULL) {
        OPENSSL_cleanse((void*)dnsauth_key, strlen(dnsauth_key));
        unsetenv("SLIPSTREAM_DNSAUTH_KEY");
    }

    slipstream_client_tls_t tls;
    tls.alpn = args.alpn.c_str();
    tls.sni = args.sni.c_str();
    tls.pin = args.pin.empty() ? NULL : args.pin.c_str();

    exit_code = picoquic_slipstream_client(
        args.listen_host.c_str(),
        args.listen_port,
        resolver_addresses.data(),
        resolver_addresses.size(),
        (char*)args.domain.c_str(),
        (char*)args.congestion_control.c_str(),
        args.gso,
        args.keep_alive_interval,
        &tls,
        args.dnsauth ? &dnsauth_conf : NULL
    );
    OPENSSL_cleanse(&dnsauth_conf, sizeof(dnsauth_conf));

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
