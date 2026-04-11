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

// receive buffer size (64KB, max possible SoupBinTCP payload)
static const int RECV_BUF_CAPACITY = 64 * 1024;

// socket receive buffer size (OS level)
static const int SOCKET_RECV_BUF_SIZE = 4 * 1024 * 1024;

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

// copy string into fixed-width left-justified space-padded field
static void copy_padded(char* dst, int width, const std::string& src) {
    std::memset(dst, ' ', (size_t)width);
    size_t len = src.size();
    if (len > (size_t)width) len = (size_t)width;
    if (len > 0) std::memcpy(dst, src.data(), len);
}

// send SoupBinTCP Login Request
static bool send_login(TcpSocket& sock,
                       const std::string& username,
                       const std::string& password,
                       uint64_t requested_sequence) {

    const int login_payload_len = 1 + LOGIN_REQUEST_PAYLOAD_LEN;
    uint8_t packet[2 + 1 + LOGIN_REQUEST_PAYLOAD_LEN];

    write_u16_be(packet, (uint16_t)login_payload_len);
    packet[2] = (uint8_t)SOUP_LOGIN_REQUEST;

    LoginRequestPayload* login = (LoginRequestPayload*)(packet + 3);
    copy_padded(login->username, 6, username);
    copy_padded(login->password, 10, password);
    copy_padded(login->requested_session, 10, "");
    format_ascii_u64(login->requested_sequence, 20, requested_sequence);

    return sock.send_bytes(packet, (int)sizeof(packet));
}

// send SoupBinTCP Client Heartbeat
static bool send_heartbeat(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_CLIENT_HEARTBEAT;
    return sock.send_bytes(packet, 3);
}

// send SoupBinTCP Logout Request
static bool send_logout(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_LOGOUT_REQUEST;
    return sock.send_bytes(packet, 3);
}

// drain and discard payload bytes from socket
static bool drain_payload(TcpSocket& sock, uint8_t* recv_buf,
                          int recv_buf_capacity, int bytes_to_drain) {
    int remaining = bytes_to_drain;
    while (remaining > 0) {
        int chunk = remaining > recv_buf_capacity ? recv_buf_capacity : remaining;
        if (!sock.recv_exact(recv_buf, chunk)) return false;
        remaining -= chunk;
    }
    return true;
}

// connect to server, send login, handle response.
// on success: sets session_id and sequence_number.
// prints: "Connected to ip:port" and login accepted/rejected packet.
static bool connect_and_login(TcpSocket& sock,
                              const SessionConfig& session,
                              uint64_t requested_sequence,
                              std::string& session_id,
                              uint64_t& sequence_number) {

    if (!sock.connect_to(session.server_ip, session.server_port)) {
        return false;
    }

    sock.set_receive_buffer(SOCKET_RECV_BUF_SIZE);
    sock.set_nodelay(true);

    std::printf("Connected to %s:%u\n",
                session.server_ip.c_str(), (unsigned)session.server_port);

    // send login request
    if (!send_login(sock, session.username, session.password, requested_sequence)) {
        sock.close();
        return false;
    }

    // read login response header
    uint8_t header[SOUP_HEADER_LEN];
    if (!sock.recv_exact(header, SOUP_HEADER_LEN)) {
        sock.close();
        return false;
    }

    uint16_t packet_length = read_u16_be(header);
    char packet_type = (char)header[2];
    int payload_length = (int)(packet_length - 1);

    // Login Accepted
    if (packet_type == SOUP_LOGIN_ACCEPTED) {
        if (payload_length < LOGIN_ACCEPTED_PAYLOAD_LEN) {
            sock.close();
            return false;
        }

        uint8_t accepted_payload[LOGIN_ACCEPTED_PAYLOAD_LEN];
        if (!sock.recv_exact(accepted_payload, LOGIN_ACCEPTED_PAYLOAD_LEN)) {
            sock.close();
            return false;
        }

        // drain any trailing bytes beyond the standard payload
        int trailing_bytes = payload_length - LOGIN_ACCEPTED_PAYLOAD_LEN;
        if (trailing_bytes > 0) {
            uint8_t discard_buf[256];
            while (trailing_bytes > 0) {
                int chunk = trailing_bytes > (int)sizeof(discard_buf) ? (int)sizeof(discard_buf) : trailing_bytes;
                if (!sock.recv_exact(discard_buf, chunk)) break;
                trailing_bytes -= chunk;
            }
        }

        LoginAcceptedPayload* accepted = (LoginAcceptedPayload*)accepted_payload;
        session_id.assign(accepted->session, 10);

        // subtract 1 because sequence_number++ runs before printing
        uint64_t server_next_sequence = parse_ascii_u64(accepted->sequence_number, 20);
        sequence_number = server_next_sequence - 1;

        // print login accepted packet: >> {pkt_len, 'A', session, next_seq}
        std::printf(">> {%u, 'A', '%.*s', %llu}\n",
                    (unsigned)packet_length,
                    10, accepted->session,
                    (unsigned long long)server_next_sequence);
        return true;
    }

    // Login Rejected
    if (packet_type == SOUP_LOGIN_REJECTED) {
        uint8_t reject_reason = 0;
        if (payload_length >= 1) {
            sock.recv_exact(&reject_reason, 1);
        }

        // drain any trailing bytes beyond the reason byte
        int trailing_bytes = payload_length - 1;
        if (trailing_bytes > 0) {
            uint8_t discard_buf[256];
            while (trailing_bytes > 0) {
                int chunk = trailing_bytes > (int)sizeof(discard_buf) ? (int)sizeof(discard_buf) : trailing_bytes;
                if (!sock.recv_exact(discard_buf, chunk)) break;
                trailing_bytes -= chunk;
            }
        }

        const char* reject_description = "Unknown";
        if ((char)reject_reason == 'A') reject_description = "Not Authorized";
        if ((char)reject_reason == 'S') reject_description = "Session Not Available";

        // print login rejected packet: >> {pkt_len, 'J', reason, description}
        std::printf(">> {%u, 'J', '%c', '%s'}\n",
                    (unsigned)packet_length,
                    (char)reject_reason,
                    reject_description);
        sock.close();
        return false;
    }

    sock.close();
    return false;
}

// ITCH live mode
// output: >> {'session', seq, field1, field2, ...}
// end:    >> {'session', seq, 'Z'}
int Application::run_itch() {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    uint64_t login_seq = 1;
    if (has_start_seq) login_seq = start_seq;

    std::string session_id;
    uint64_t current_seq = 0;
    uint64_t decoded_count = 0;

    int max_reconnect_attempts = proto.max_reconnect_attempts;
    int reconnect_delay_sec = proto.reconnect_delay_sec;
    if (reconnect_delay_sec <= 0) reconnect_delay_sec = 5;
    int reconnect_attempt = 0;

    while (1) {
        TcpSocket sock;

        if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
            reconnect_attempt++;
            if (max_reconnect_attempts > 0 && reconnect_attempt >= max_reconnect_attempts) {
                return 1;
            }
            ::sleep((unsigned)reconnect_delay_sec);
            continue;
        }

        // login success, reset reconnect counter
        reconnect_attempt = 0;

        // heartbeat and timeout settings
        int heartbeat_interval_ms = proto.heartbeat_interval_sec * 1000;
        if (heartbeat_interval_ms <= 0) heartbeat_interval_ms = 15000;
        int server_timeout_sec = (heartbeat_interval_ms * 2) / 1000;

        time_t last_send_time = std::time(0);
        time_t last_recv_time = std::time(0);

        uint8_t recv_buf[RECV_BUF_CAPACITY];

        struct pollfd poll_fd;
        poll_fd.fd = sock.get_fd();
        poll_fd.events = POLLIN;

        bool needs_reconnect = false;

        while (1) {
            int poll_result = ::poll(&poll_fd, 1, heartbeat_interval_ms);
            time_t now = std::time(0);

            if (poll_result < 0) {
                if (errno == EINTR) continue;
                needs_reconnect = true;
                break;
            }

            // poll timeout: send client heartbeat
            if (poll_result == 0) {
                if (!send_heartbeat(sock)) { needs_reconnect = true; break; }
                last_send_time = now;

                if ((now - last_recv_time) > server_timeout_sec) {
                    needs_reconnect = true;
                    break;
                }
                continue;
            }

            // read packet header (2 bytes length + 1 byte type)
            uint8_t header[SOUP_HEADER_LEN];
            if (!sock.recv_exact(header, SOUP_HEADER_LEN)) {
                needs_reconnect = true;
                break;
            }

            last_recv_time = now;

            uint16_t packet_length = read_u16_be(header);
            char packet_type = (char)header[2];
            int payload_length = (packet_length > 1) ? (int)(packet_length - 1) : 0;

            // Sequenced Data — contains one ITCH message
            if (packet_type == SOUP_SEQUENCED_DATA) {
                if (payload_length == 0) {
                    current_seq++;
                    continue;
                }

                if (payload_length > RECV_BUF_CAPACITY) {
                    if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                        needs_reconnect = true; break;
                    }
                    current_seq++;
                    continue;
                }

                if (!sock.recv_exact(recv_buf, payload_length)) {
                    needs_reconnect = true; break;
                }

                current_seq++;
                decoded_count++;

                // apply message filters
                if (!filter.passes(recv_buf, (uint16_t)payload_length, cfg)) {
                    continue;
                }

                // build output prefix: >> {'session', seq
                char prefix[128];
                std::snprintf(prefix, sizeof(prefix),
                              ">> {'%.*s', %llu",
                              (int)session_id.size(), session_id.c_str(),
                              (unsigned long long)current_seq);

                decode_itch_message(recv_buf, (uint16_t)payload_length, cfg,
                                   std::string(prefix), verbose);

                // stop after N messages
                if (max_messages != 0 && decoded_count >= max_messages) {
                    send_logout(sock);
                    sock.close();
                    return 0;
                }
                continue;
            }

            // Server Heartbeat — print only in verbose mode
            if (packet_type == SOUP_SERVER_HEARTBEAT) {
                if (payload_length > 0) {
                    if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                        needs_reconnect = true; break;
                    }
                }

                if (verbose) {
                    std::printf(">> {%u, '0'}\n", (unsigned)packet_length);
                }

                if ((now - last_send_time) >= (heartbeat_interval_ms / 1000)) {
                    if (!send_heartbeat(sock)) { needs_reconnect = true; break; }
                    last_send_time = now;
                }
                continue;
            }

            // End of Session
            if (packet_type == SOUP_END_OF_SESSION) {
                if (payload_length > 0) {
                    drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
                }

                std::printf(">> {'%.*s', %llu, 'Z'}\n",
                            (int)session_id.size(), session_id.c_str(),
                            (unsigned long long)current_seq);
                sock.close();
                return 0;
            }

            // Debug — print only in verbose mode
            if (packet_type == SOUP_DEBUG) {
                if (payload_length > 0 && payload_length <= RECV_BUF_CAPACITY) {
                    if (!sock.recv_exact(recv_buf, payload_length)) {
                        needs_reconnect = true; break;
                    }
                    if (verbose) {
                        std::printf(">> {%u, '+', '%.*s'}\n",
                                    (unsigned)packet_length,
                                    payload_length, (const char*)recv_buf);
                    }
                } else if (payload_length > 0) {
                    if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                        needs_reconnect = true; break;
                    }
                }
                continue;
            }

            // unknown packet type — drain and skip
            if (payload_length > 0) {
                if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                    needs_reconnect = true; break;
                }
            }

        } // receive loop

        sock.close();

        if (!needs_reconnect) {
            return 0;
        }

        // reconnect from last known sequence
        login_seq = current_seq;
        reconnect_attempt++;

        if (max_reconnect_attempts > 0 && reconnect_attempt >= max_reconnect_attempts) {
            return 1;
        }

        ::sleep((unsigned)reconnect_delay_sec);

    } // reconnect loop
}

// Glimpse snapshot mode
// output: >> {pkt_len, 'S', field1, field2, ...}
// end:    >> {pkt_len, 'S', 'G', next_seq}
int Application::run_glimpse() {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    // glimpse always starts from sequence 1
    uint64_t login_seq = 1;

    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;
    uint64_t decoded_count = 0;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
        return 1;
    }

    // heartbeat and timeout settings
    int heartbeat_interval_ms = proto.heartbeat_interval_sec * 1000;
    if (heartbeat_interval_ms <= 0) heartbeat_interval_ms = 15000;
    int server_timeout_sec = (heartbeat_interval_ms * 2) / 1000;

    time_t last_send_time = std::time(0);
    time_t last_recv_time = std::time(0);

    uint8_t recv_buf[RECV_BUF_CAPACITY];

    struct pollfd poll_fd;
    poll_fd.fd = sock.get_fd();
    poll_fd.events = POLLIN;

    while (1) {
        int poll_result = ::poll(&poll_fd, 1, heartbeat_interval_ms);
        time_t now = std::time(0);

        if (poll_result < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // poll timeout: send client heartbeat
        if (poll_result == 0) {
            if (!send_heartbeat(sock)) break;
            last_send_time = now;

            if ((now - last_recv_time) > server_timeout_sec) {
                break;
            }
            continue;
        }

        // read packet header
        uint8_t header[SOUP_HEADER_LEN];
        if (!sock.recv_exact(header, SOUP_HEADER_LEN)) {
            break;
        }

        last_recv_time = now;

        uint16_t packet_length = read_u16_be(header);
        char packet_type = (char)header[2];
        int payload_length = (packet_length > 1) ? (int)(packet_length - 1) : 0;

        // Sequenced Data — contains one snapshot message
        if (packet_type == SOUP_SEQUENCED_DATA) {
            if (payload_length == 0) {
                continue;
            }

            if (payload_length > RECV_BUF_CAPACITY) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
                continue;
            }

            if (!sock.recv_exact(recv_buf, payload_length)) {
                break;
            }

            // End of Snapshot (message type 'G')
            if (payload_length >= 1 && (char)recv_buf[0] == 'G') {
                // sequence number offset varies by server:
                // 9 bytes: MessageType(1) + SequenceNumber(8)
                // 17 bytes: MessageType(1) + Timestamp(8) + SequenceNumber(8)
                uint64_t realtime_next_sequence = 0;
                int sequence_offset = (payload_length >= 17) ? 9 : 1;
                if (sequence_offset + 8 <= payload_length) {
                    realtime_next_sequence = read_u64_be(recv_buf + sequence_offset);
                }

                std::printf(">> {%u, 'S', 'G', %llu}\n",
                            (unsigned)packet_length,
                            (unsigned long long)realtime_next_sequence);
                sock.close();
                return 0;
            }

            decoded_count++;

            // apply message filters
            if (!filter.passes(recv_buf, (uint16_t)payload_length, cfg)) {
                continue;
            }

            // build output prefix: >> {pkt_len, 'S'
            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), ">> {%u, 'S'", (unsigned)packet_length);

            decode_itch_message(recv_buf, (uint16_t)payload_length, cfg,
                               std::string(prefix), verbose);

            // stop after N messages
            if (max_messages != 0 && decoded_count >= max_messages) {
                sock.close();
                return 0;
            }
            continue;
        }

        // Server Heartbeat — print only in verbose mode
        if (packet_type == SOUP_SERVER_HEARTBEAT) {
            if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }

            if (verbose) {
                std::printf(">> {%u, 'H'}\n", (unsigned)packet_length);
            }

            if ((now - last_send_time) >= (heartbeat_interval_ms / 1000)) {
                if (!send_heartbeat(sock)) break;
                last_send_time = now;
            }
            continue;
        }

        // End of Session
        if (packet_type == SOUP_END_OF_SESSION) {
            if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }
            sock.close();
            return 0;
        }

        // unknown packet type — drain and skip
        if (payload_length > 0) {
            drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
        }

    }

    sock.close();
    return 1;
}

int Application::run() {
    const char* config_path = "config/config.yaml";
    if (!load_config(config_path, mode, session_key)) {
        return 1;
    }

    if (mode == "itch") {
        return run_itch();
    }

    if (mode == "glimpse") {
        return run_glimpse();
    }

    std::printf("Unknown mode: %s\n", mode.c_str());
    return 1;
}
