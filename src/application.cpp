#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <cstring>
#include <cerrno>
#include <poll.h>
#include <ctime>
#include <unistd.h>

// Constructor
Application::Application()
    : has_start_seq(false),
      start_seq(0),
      max_messages(0),
      verbose(false) {
}

void Application::set_mode(const std::string& m) { mode = m; }
void Application::set_session_key(const std::string& k) { session_key = k; }
void Application::set_start_seq(uint64_t s) { has_start_seq = true; start_seq = s; }
void Application::set_max_messages(uint64_t n) { max_messages = n; }
void Application::set_verbose(bool v) { verbose = v; }
Filter& Application::get_filter() { return filter; }

// SoupBinTCP packet helpers
static uint16_t read_u16_be(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static void write_u16_be(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint64_t read_u64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void format_ascii_u64(char* dst, int width, uint64_t value) {
    std::memset(dst, ' ', (size_t)width);
    char tmp[32];
    int len = std::snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)value);
    if (len > width) len = width;
    std::memcpy(dst + (width - len), tmp, (size_t)len);
}

static uint64_t parse_ascii_u64(const char* src, int width) {
    int start = 0;
    while (start < width && src[start] == ' ') start++;
    uint64_t val = 0;
    for (int i = start; i < width; i++) {
        if (src[i] < '0' || src[i] > '9') break;
        val = val * 10 + (uint64_t)(src[i] - '0');
    }
    return val;
}

static void copy_padded(char* dst, int width, const std::string& src) {
    std::memset(dst, ' ', (size_t)width);
    size_t len = src.size();
    if (len > (size_t)width) len = (size_t)width;
    if (len > 0) std::memcpy(dst, src.data(), len);
}

// Send SoupBinTCP packets
static bool send_login(TcpSocket& sock,
                       const std::string& username,
                       const std::string& password,
                       uint64_t seq) {

    const int payload_len = 1 + LOGIN_REQUEST_PAYLOAD_LEN;
    uint8_t packet[2 + 1 + LOGIN_REQUEST_PAYLOAD_LEN];

    write_u16_be(packet, (uint16_t)payload_len);
    packet[2] = (uint8_t)SOUP_LOGIN_REQUEST;

    LoginRequestPayload* login = (LoginRequestPayload*)(packet + 3);
    copy_padded(login->username, 6, username);
    copy_padded(login->password, 10, password);
    copy_padded(login->requested_session, 10, "");
    format_ascii_u64(login->requested_sequence, 20, seq);

    return sock.send_bytes(packet, (int)sizeof(packet));
}

static bool send_heartbeat(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_CLIENT_HEARTBEAT;
    return sock.send_bytes(packet, 3);
}

static bool send_logout(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_LOGOUT_REQUEST;
    return sock.send_bytes(packet, 3);
}

// Connect + Login
//
// Returns true on Login Accepted.
// Sets session_id and next_seq on success.
static bool connect_and_login(TcpSocket& sock,
                              const SessionConfig& session,
                              uint64_t login_seq,
                              std::string& session_id,
                              uint64_t& next_seq) {

    std::printf("Connecting to %s:%u ...\n",
                session.server_ip.c_str(), (unsigned)session.server_port);

    if (!sock.connect_to(session.server_ip, session.server_port)) {
        std::printf("Failed to connect errno=%d\n", errno);
        return false;
    }

    sock.set_receive_buffer(4 * 1024 * 1024);
    sock.set_nodelay(true);
    std::printf("Connected\n");

    // Send login
    if (!send_login(sock, session.username, session.password, login_seq)) {
        std::printf("Failed to send Login Request\n");
        sock.close();
        return false;
    }

    std::printf("Login sent (seq=%llu)\n", (unsigned long long)login_seq);

    // Read login response
    uint8_t hdr[SOUP_HEADER_LEN];
    if (!sock.recv_exact(hdr, SOUP_HEADER_LEN)) {
        std::printf("Failed to read Login Response\n");
        sock.close();
        return false;
    }

    uint16_t pkt_len = read_u16_be(hdr);
    char pkt_type = (char)hdr[2];
    int payload_len = (int)(pkt_len - 1);

    // Accepted
    if (pkt_type == SOUP_LOGIN_ACCEPTED) {
        if (payload_len < LOGIN_ACCEPTED_PAYLOAD_LEN) {
            std::printf("Login Accepted too short\n");
            sock.close();
            return false;
        }

        uint8_t payload[LOGIN_ACCEPTED_PAYLOAD_LEN];
        if (!sock.recv_exact(payload, LOGIN_ACCEPTED_PAYLOAD_LEN)) {
            std::printf("Failed to read Login Accepted\n");
            sock.close();
            return false;
        }

        // Drain extra bytes
        int extra = payload_len - LOGIN_ACCEPTED_PAYLOAD_LEN;
        if (extra > 0) {
            uint8_t discard[256];
            while (extra > 0) {
                int chunk = extra > (int)sizeof(discard) ? (int)sizeof(discard) : extra;
                if (!sock.recv_exact(discard, chunk)) break;
                extra -= chunk;
            }
        }

        LoginAcceptedPayload* accepted = (LoginAcceptedPayload*)payload;
        session_id.assign(accepted->session, 10);
        next_seq = parse_ascii_u64(accepted->sequence_number, 20);

        std::printf(">> LOGIN_ACCEPTED Session='%s' NextSequence=%llu\n",
                    session_id.c_str(), (unsigned long long)next_seq);
        return true;
    }

    // Rejected
    if (pkt_type == SOUP_LOGIN_REJECTED) {
        uint8_t reason = 0;
        if (payload_len >= 1) sock.recv_exact(&reason, 1);

        int extra = payload_len - 1;
        if (extra > 0) {
            uint8_t discard[256];
            while (extra > 0) {
                int chunk = extra > (int)sizeof(discard) ? (int)sizeof(discard) : extra;
                if (!sock.recv_exact(discard, chunk)) break;
                extra -= chunk;
            }
        }

        const char* reason_str = "Unknown";
        if ((char)reason == 'A') reason_str = "Not Authorized";
        if ((char)reason == 'S') reason_str = "Session Not Available";

        std::printf(">> LOGIN_REJECTED Reason='%c' (%s)\n", (char)reason, reason_str);
        sock.close();
        return false;
    }

    std::printf("Unexpected login response: '%c'\n", pkt_type);
    sock.close();
    return false;
}

// Drain payload bytes (skip unknown/oversized data)
static bool drain_payload(TcpSocket& sock, uint8_t* buf,
                          int buf_size, int payload_len) {
    int remaining = payload_len;
    while (remaining > 0) {
        int chunk = remaining > buf_size ? buf_size : remaining;
        if (!sock.recv_exact(buf, chunk)) return false;
        remaining -= chunk;
    }
    return true;
}

// ITCH live mode
int Application::run_itch() {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    uint64_t login_seq = 1;
    if (has_start_seq) login_seq = start_seq;

    std::string session_id;
    uint64_t current_seq = 0;
    uint64_t decoded_count = 0;

    int max_attempts = proto.max_reconnect_attempts;
    int delay_sec = proto.reconnect_delay_sec;
    if (delay_sec <= 0) delay_sec = 5;
    int attempt = 0;

    while (1) {
        TcpSocket sock;

        if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
            attempt++;
            if (max_attempts > 0 && attempt >= max_attempts) {
                std::printf(">> MAX RECONNECT (%d)\n", max_attempts);
                return 1;
            }
            std::printf(">> RECONNECT %d/%d in %ds...\n", attempt, max_attempts, delay_sec);
            ::sleep((unsigned)delay_sec);
            continue;
        }

        // Login success
        attempt = 0;

        // Receive loop
        int heartbeat_ms = proto.heartbeat_interval_sec * 1000;
        if (heartbeat_ms <= 0) heartbeat_ms = 15000;
        int server_timeout_sec = (heartbeat_ms * 2) / 1000;

        time_t last_send_time = std::time(0);
        time_t last_recv_time = std::time(0);

        const int buf_capacity = 64 * 1024;
        uint8_t buf[64 * 1024];

        struct pollfd pfd;
        pfd.fd = sock.get_fd();
        pfd.events = POLLIN;

        std::printf("Listening... (Ctrl+C to stop)\n");

        bool should_reconnect = false;

        while (1) {
            int ret = ::poll(&pfd, 1, heartbeat_ms);
            time_t now = std::time(0);

            if (ret < 0) {
                if (errno == EINTR) continue;
                should_reconnect = true;
                break;
            }

            // Timeout: send heartbeat
            if (ret == 0) {
                if (!send_heartbeat(sock)) { should_reconnect = true; break; }
                last_send_time = now;

                if ((now - last_recv_time) > server_timeout_sec) {
                    std::printf(">> SERVER TIMEOUT\n");
                    should_reconnect = true;
                    break;
                }
                continue;
            }

            // Read packet header
            uint8_t hdr[SOUP_HEADER_LEN];
            if (!sock.recv_exact(hdr, SOUP_HEADER_LEN)) {
                std::printf(">> DISCONNECTED\n");
                should_reconnect = true;
                break;
            }

            last_recv_time = now;

            uint16_t pkt_len = read_u16_be(hdr);
            char pkt_type = (char)hdr[2];
            int payload_len = (pkt_len > 1) ? (int)(pkt_len - 1) : 0;

            // Sequenced Data
            if (pkt_type == SOUP_SEQUENCED_DATA) {
                if (payload_len == 0) {
                    current_seq++;
                    continue;
                }

                if (payload_len > buf_capacity) {
                    if (!drain_payload(sock, buf, buf_capacity, payload_len)) {
                        should_reconnect = true; break;
                    }
                    current_seq++;
                    continue;
                }

                if (!sock.recv_exact(buf, payload_len)) {
                    should_reconnect = true; break;
                }

                current_seq++;

                // Apply filters
                if (!filter.passes(buf, (uint16_t)payload_len, cfg)) {
                    decoded_count++;
                    continue;
                }

                // Build prefix: >> {'session', seq
                char prefix[128];
                std::snprintf(prefix, sizeof(prefix),
                              ">> {'%.*s', %llu",
                              (int)session_id.size(), session_id.c_str(),
                              (unsigned long long)current_seq);

                decode_itch_message(buf, (uint16_t)payload_len, cfg,
                                   std::string(prefix), verbose);

                decoded_count++;

                // Stop after N messages
                if (max_messages != 0 && decoded_count >= max_messages) {
                    std::printf(">> STOP decoded=%llu\n", (unsigned long long)decoded_count);
                    send_logout(sock);
                    sock.close();
                    return 0;
                }
                continue;
            }

            // Server Heartbeat
            if (pkt_type == SOUP_SERVER_HEARTBEAT) {
                if (payload_len > 0) {
                    if (!drain_payload(sock, buf, buf_capacity, payload_len)) {
                        should_reconnect = true; break;
                    }
                }
                if (verbose) std::printf(">> SERVER_HEARTBEAT\n");

                if ((now - last_send_time) >= (heartbeat_ms / 1000)) {
                    if (!send_heartbeat(sock)) { should_reconnect = true; break; }
                    last_send_time = now;
                }
                continue;
            }

            // End of Session
            if (pkt_type == SOUP_END_OF_SESSION) {
                if (payload_len > 0) {
                    drain_payload(sock, buf, buf_capacity, payload_len);
                }

                // Print: >> {'session', seq, 'Z'}
                std::printf(">> {'%.*s', %llu, 'Z'}\n",
                            (int)session_id.size(), session_id.c_str(),
                            (unsigned long long)current_seq);
                sock.close();
                return 0;
            }

            // Debug
            if (pkt_type == SOUP_DEBUG) {
                if (payload_len > 0 && payload_len <= buf_capacity) {
                    if (!sock.recv_exact(buf, payload_len)) {
                        should_reconnect = true; break;
                    }
                    if (verbose) {
                        std::printf(">> DEBUG '%.*s'\n", payload_len, (const char*)buf);
                    }
                } else if (payload_len > 0) {
                    if (!drain_payload(sock, buf, buf_capacity, payload_len)) {
                        should_reconnect = true; break;
                    }
                }
                continue;
            }

            // Unknown packet type
            if (payload_len > 0) {
                if (!drain_payload(sock, buf, buf_capacity, payload_len)) {
                    should_reconnect = true; break;
                }
            }

        }

        sock.close();

        if (!should_reconnect) {
            return 0;
        }

        // Reconnect from last known sequence
        login_seq = current_seq;
        attempt++;

        if (max_attempts > 0 && attempt >= max_attempts) {
            std::printf(">> MAX RECONNECT (%d) seq=%llu\n",
                        max_attempts, (unsigned long long)current_seq);
            return 1;
        }

        std::printf(">> RECONNECT %d/%d in %ds (seq=%llu)...\n",
                    attempt, max_attempts, delay_sec,
                    (unsigned long long)login_seq);
        ::sleep((unsigned)delay_sec);
    }
}

// Glimpse snapshot mode
int Application::run_glimpse() {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    // Glimpse always starts from sequence 1
    uint64_t login_seq = 1;

    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;
    uint64_t decoded_count = 0;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
        return 1;
    }

    // Receive snapshot
    int heartbeat_ms = proto.heartbeat_interval_sec * 1000;
    if (heartbeat_ms <= 0) heartbeat_ms = 15000;
    int server_timeout_sec = (heartbeat_ms * 2) / 1000;

    time_t last_send_time = std::time(0);
    time_t last_recv_time = std::time(0);

    const int buf_capacity = 64 * 1024;
    uint8_t buf[64 * 1024];

    struct pollfd pfd;
    pfd.fd = sock.get_fd();
    pfd.events = POLLIN;

    std::printf("Receiving snapshot...\n");

    while (1) {
        int ret = ::poll(&pfd, 1, heartbeat_ms);
        time_t now = std::time(0);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Timeout: send heartbeat
        if (ret == 0) {
            if (!send_heartbeat(sock)) break;
            last_send_time = now;

            if ((now - last_recv_time) > server_timeout_sec) {
                std::printf(">> SERVER TIMEOUT\n");
                break;
            }
            continue;
        }

        // Read packet header
        uint8_t hdr[SOUP_HEADER_LEN];
        if (!sock.recv_exact(hdr, SOUP_HEADER_LEN)) {
            std::printf(">> DISCONNECTED\n");
            break;
        }

        last_recv_time = now;

        uint16_t pkt_len = read_u16_be(hdr);
        char pkt_type = (char)hdr[2];
        int payload_len = (pkt_len > 1) ? (int)(pkt_len - 1) : 0;

        // Sequenced Data
        if (pkt_type == SOUP_SEQUENCED_DATA) {
            if (payload_len == 0) {
                continue;
            }

            if (payload_len > buf_capacity) {
                drain_payload(sock, buf, buf_capacity, payload_len);
                continue;
            }

            if (!sock.recv_exact(buf, payload_len)) {
                break;
            }

            // End of Snapshot (G)
            if (payload_len >= 1 && (char)buf[0] == 'G') {
                // Read next real-time sequence number
                // Layout varies: 9 bytes (MsgType+Seq) or 17 bytes (MsgType+Timestamp+Seq)
                uint64_t next_seq = 0;
                int seq_offset = (payload_len >= 17) ? 9 : 1;
                if (seq_offset + 8 <= payload_len) {
                    next_seq = read_u64_be(buf + seq_offset);
                }

                // Print: >> {pkt_len, 'S', 'G', next_seq}
                std::printf(">> {%u, 'S', 'G', %llu}\n",
                            (unsigned)pkt_len, (unsigned long long)next_seq);
                sock.close();
                return 0;
            }

            // Apply filters
            if (!filter.passes(buf, (uint16_t)payload_len, cfg)) {
                decoded_count++;
                continue;
            }

            // Build prefix: >> {pkt_len, 'S'
            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), ">> {%u, 'S'", (unsigned)pkt_len);

            decode_itch_message(buf, (uint16_t)payload_len, cfg,
                               std::string(prefix), verbose);

            decoded_count++;

            // Stop after N messages
            if (max_messages != 0 && decoded_count >= max_messages) {
                std::printf(">> STOP decoded=%llu\n", (unsigned long long)decoded_count);
                sock.close();
                return 0;
            }
            continue;
        }

        // Server Heartbeat
        if (pkt_type == SOUP_SERVER_HEARTBEAT) {
            if (payload_len > 0) {
                drain_payload(sock, buf, buf_capacity, payload_len);
            }
            if (verbose) std::printf(">> SERVER_HEARTBEAT\n");

            if ((now - last_send_time) >= (heartbeat_ms / 1000)) {
                if (!send_heartbeat(sock)) break;
                last_send_time = now;
            }
            continue;
        }

        // End of Session
        if (pkt_type == SOUP_END_OF_SESSION) {
            if (payload_len > 0) {
                drain_payload(sock, buf, buf_capacity, payload_len);
            }
            std::printf(">> END_OF_SESSION (no snapshot)\n");
            sock.close();
            return 0;
        }

        // Drain unknown
        if (payload_len > 0) {
            drain_payload(sock, buf, buf_capacity, payload_len);
        }

    }

    sock.close();
    return 1;
}

// Run — dispatch to mode handler
int Application::run() {
    const char* config_path = "config/config.yaml";
    if (!load_config(config_path, mode, session_key)) {
        return 1;
    }

    const AppConfig& cfg = config();
    if (verbose) {
        std::printf("mode=%s session=%s server=%s:%u spec=%s\n",
                    mode.c_str(),
                    session_key.c_str(),
                    cfg.session.server_ip.c_str(),
                    (unsigned)cfg.session.server_port,
                    cfg.protocol.protocol_spec.c_str());
    }

    // Dispatch based on mode
    if (mode == "itch") {
        return run_itch();
    }

    if (mode == "glimpse") {
        return run_glimpse();
    }

    // To do:
    // OUCH, API, DROP ... 
    std::printf("Unknown mode: %s\n", mode.c_str());
    return 1;
}
