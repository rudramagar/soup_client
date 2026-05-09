#include "soup_session.h"
#include "soupbintcp.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <poll.h>

uint16_t read_u16_be(const uint8_t* src) {
    return (uint16_t)((uint16_t)src[0] << 8 | (uint16_t)src[1]);
}

uint32_t read_u32_be(const uint8_t* src) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

uint64_t read_u64_be(const uint8_t* src) {
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  | ((uint64_t)src[7]);
}

void write_u16_be(uint8_t* dst, uint16_t value) {
    dst[0] = (uint8_t)(value >> 8);
    dst[1] = (uint8_t)(value & 0xFF);
}

void write_u32_be(uint8_t* dst, uint32_t value) {
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)(value & 0xFF);
}

void write_u64_be(uint8_t* dst, uint64_t value) {
    dst[0] = (uint8_t)(value >> 56);
    dst[1] = (uint8_t)(value >> 48);
    dst[2] = (uint8_t)(value >> 40);
    dst[3] = (uint8_t)(value >> 32);
    dst[4] = (uint8_t)(value >> 24);
    dst[5] = (uint8_t)(value >> 16);
    dst[6] = (uint8_t)(value >> 8);
    dst[7] = (uint8_t)(value & 0xFF);
}

// Space paded on the left for numeric field
static void write_padded_number(char* dst, int width, uint64_t value) {
    std::memset(dst, ' ', (size_t)width);
    char tmp[32];
    int len = std::snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)value);
    if (len > width) len = width;
    std::memcpy(dst + (width - len), tmp, (size_t)len);
}

// Read a fixed-width numeric field,
// ignoring leading spaces.
static uint64_t read_padded_number(const char* src, int width) {
    int start = 0;
    while (start < width && src[start] == ' ') start++;
    uint64_t result = 0;
    for (int i = start; i < width; i++) {
        if (src[i] < '0' || src[i] > '9') break;
        result = result * 10 + (uint64_t)(src[i] - '0');
    }
    return result;
}

// Copy a string into a fixed-width
// left-justified, space-paded field.
static void copy_padded(char* dst, int width, const std::string& src) {
    std::memset(dst, ' ', (size_t)width);
    size_t len = src.size();
    if (len > (size_t)width) len = (size_t)width;
    if (len > 0) std::memcpy(dst, src.data(), len);
}

// Login Request Packet
static bool send_login(TcpSocket& sock,
                       const std::string& username,
                       const std::string& password,
                       uint64_t requested_sequence) {
 
    const int login_payload_len = 1 + LOGIN_REQUEST_PAYLOAD_LEN;
    uint8_t packet[2 + 1 + LOGIN_REQUEST_PAYLOAD_LEN];
 
    write_u16_be(packet, (uint16_t)login_payload_len);
    packet[2] = (uint8_t)SOUP_LOGIN_REQUEST;
 
    LoginRequestPayload* login = (LoginRequestPayload*)(packet + 3);
    copy_padded(login->username,           6, username);
    copy_padded(login->password,          10, password);
    copy_padded(login->requested_session, 10, "");
    write_padded_number(login->requested_sequence, 20, requested_sequence);
 
    return sock.send_bytes(packet, (int)sizeof(packet));
}

// HB
bool send_heartbeat(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_CLIENT_HEARTBEAT;
    return sock.send_bytes(packet, 3);
}

// Logout
bool send_logout(TcpSocket& sock) {
    uint8_t packet[3];
    write_u16_be(packet, 1);
    packet[2] = (uint8_t)SOUP_LOGOUT_REQUEST;
    return sock.send_bytes(packet, 3);
}

// drain payload
bool drain_payload(TcpSocket& sock,
                   uint8_t* scratch_buf,
                   int scratch_buf_capacity,
                   int bytes_to_drain) {
    int remaining = bytes_to_drain;
    while (remaining > 0) {
        int chunk = remaining > scratch_buf_capacity ? scratch_buf_capacity : remaining;
        if (!sock.recv_exact(scratch_buf, chunk)) return false;
        remaining -= chunk;
    }
    return true;
}

bool connect_and_login(TcpSocket& sock,
                       const SessionConfig& session,
                       uint64_t requested_sequence,
                       std::string& session_id,
                       uint64_t& sequence_number,
                       bool is_ouch) {

    if (!sock.connect_to(session.server_ip, session.server_port)) {
        return false;
    }

    sock.set_receive_buffer(SOCKET_RECV_BUF_SIZE);
    sock.set_nodelay(true);

    const char* client_to_server = is_ouch ? ">>" : "<<";
    const char* server_to_client = is_ouch ? "<<" : ">>";

    std::printf("Connected to %s:%u\n",
                session.server_ip.c_str(), (unsigned)session.server_port);

    // Print Login Request before sending
    std::printf("%s (%u,'L','%s',%llu)\n",
                client_to_server,
                (unsigned)(1 + LOGIN_REQUEST_PAYLOAD_LEN),
                session.username.c_str(),
                (unsigned long long)requested_sequence);

    // Send Login Request
    if (!send_login(sock, session.username, session.password, requested_sequence)) {
        sock.close();
        return false;
    }

    // Read login response header
    uint8_t header[SOUP_HEADER_LEN];
    if (!sock.recv_exact(header, SOUP_HEADER_LEN)) {
        sock.close();
        return false;
    }

    uint16_t packet_length  = read_u16_be(header);
    char     packet_type    = (char)header[2];
    int      payload_length = (int)(packet_length - 1);

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

        // Drain trailing bytes beyond the standard payload, if any
        int trailing_bytes = payload_length - LOGIN_ACCEPTED_PAYLOAD_LEN;
        if (trailing_bytes > 0) {
            uint8_t discard_buf[256];
            drain_payload(sock, discard_buf, sizeof(discard_buf), trailing_bytes);
        }

        LoginAcceptedPayload* accepted = (LoginAcceptedPayload*)accepted_payload;
        session_id.assign(accepted->session, 10);

        // Subtract 1: caller increments sequence_number before printing
        uint64_t server_next_sequence =
            read_padded_number(accepted->sequence_number, 20);
        sequence_number = server_next_sequence - 1;

        std::printf("%s (%u,'A','%.*s',%llu)\n",
                    server_to_client,
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

        // Drain trailing bytes beyond the reason byte, if any
        int trailing_bytes = payload_length - 1;
        if (trailing_bytes > 0) {
            uint8_t discard_buf[256];
            drain_payload(sock, discard_buf, sizeof(discard_buf), trailing_bytes);
        }

        const char* reject_description = "Unknown";
        if ((char)reject_reason == 'A') reject_description = "Not Authorized";
        if ((char)reject_reason == 'S') reject_description = "Session Not Available";

        std::printf("%s (%u,'J','%c','%s')\n",
                    server_to_client,
                    (unsigned)packet_length,
                    (char)reject_reason,
                    reject_description);
        sock.close();
        return false;
    }

    sock.close();
    return false;
}

// =============================================================================
// run_session: shared receive loop
// =============================================================================
SessionExit run_session(TcpSocket& sock,
                        const SessionLoopOptions& opts,
                        OnSequencedFn on_sequenced,
                        OnIdleFn      on_idle) {

    const char* arrow_recv = opts.ouch_arrows ? "<<" : ">>";
    char open_b  = opts.ouch_arrows ? '(' : '{';
    char close_b = opts.ouch_arrows ? ')' : '}';

    // Heartbeat interval in ms (used as poll timeout). Default 1s if unset.
    int heartbeat_ms = opts.heartbeat_interval_sec * 1000;
    if (heartbeat_ms <= 0) heartbeat_ms = 1000;

    // If on_idle is supplied, wake more often than the heartbeat so callbacks
    // can react quickly (e.g. OUCH idle-exit at 1s).
    int poll_timeout_ms = on_idle ? 200 : heartbeat_ms;

    time_t last_send_time = std::time(0);
    time_t last_recv_time = std::time(0);

    uint8_t recv_buf[RECV_BUF_CAPACITY];

    struct pollfd poll_fd;
    poll_fd.fd = sock.get_fd();
    poll_fd.events = POLLIN;

    while (true) {
        int poll_result = ::poll(&poll_fd, 1, poll_timeout_ms);
        time_t now = std::time(0);

        if (poll_result < 0) {
            if (errno == EINTR) continue;
            return SESSION_SOCKET_ERROR;
        }

        // Caller-driven idle check (OUCH idle-exit, send pacing, etc.)
        if (on_idle && !on_idle(now)) {
            return SESSION_OK;
        }

        // No data this wake — maybe send heartbeat, maybe time out.
        if (poll_result == 0) {
            if ((now - last_send_time) >= opts.heartbeat_interval_sec) {
                if (!send_heartbeat(sock)) return SESSION_SOCKET_ERROR;
                last_send_time = now;
            }
            if (opts.server_timeout_sec > 0 &&
                (now - last_recv_time) > opts.server_timeout_sec) {
                return SESSION_SERVER_TIMEOUT;
            }
            continue;
        }

        // Read SoupBinTCP header
        uint8_t header[SOUP_HEADER_LEN];
        if (!sock.recv_exact(header, SOUP_HEADER_LEN)) {
            return SESSION_SOCKET_ERROR;
        }

        last_recv_time = now;

        uint16_t packet_length = read_u16_be(header);
        char     packet_type   = (char)header[2];
        int      payload_length = (packet_length > 1) ? (int)(packet_length - 1) : 0;

        // Sequenced Data — dispatch to caller
        if (packet_type == SOUP_SEQUENCED_DATA) {
            if (payload_length == 0) {
                if (!on_sequenced(0, 0, packet_length)) return SESSION_OK;
                continue;
            }
            if (payload_length > RECV_BUF_CAPACITY) {
                if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                    return SESSION_SOCKET_ERROR;
                }
                continue;
            }
            if (!sock.recv_exact(recv_buf, payload_length)) {
                return SESSION_SOCKET_ERROR;
            }
            if (!on_sequenced(recv_buf, (uint16_t)payload_length, packet_length)) {
                return SESSION_OK;
            }
            continue;
        }

        // Server Heartbeat — drain, optionally print
        if (packet_type == SOUP_SERVER_HEARTBEAT) {
            if (payload_length > 0) {
                if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                    return SESSION_SOCKET_ERROR;
                }
            }
            if (opts.verbose) {
                std::printf("%s %c%u,'H'%c\n",
                            arrow_recv, open_b, (unsigned)packet_length, close_b);
            }
            // If we've been silent too long, send our own heartbeat
            if ((now - last_send_time) >= opts.heartbeat_interval_sec) {
                if (!send_heartbeat(sock)) return SESSION_SOCKET_ERROR;
                last_send_time = now;
            }
            continue;
        }

        // End of Session
        if (packet_type == SOUP_END_OF_SESSION) {
            if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }
            return SESSION_END_OF_SESSION;
        }

        // Debug — drain, optionally print
        if (packet_type == SOUP_DEBUG) {
            if (payload_length > 0 && payload_length <= RECV_BUF_CAPACITY) {
                if (!sock.recv_exact(recv_buf, payload_length)) {
                    return SESSION_SOCKET_ERROR;
                }
                if (opts.verbose) {
                    std::printf("%s %c%u,'+','%.*s'%c\n",
                                arrow_recv,
                                open_b,
                                (unsigned)packet_length,
                                payload_length, (const char*)recv_buf,
                                close_b);
                }
            } else if (payload_length > 0) {
                if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                    return SESSION_SOCKET_ERROR;
                }
            }
            continue;
        }

        // Unknown packet type — drain and skip
        if (payload_length > 0) {
            if (!drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length)) {
                return SESSION_SOCKET_ERROR;
            }
        }
    }
}
