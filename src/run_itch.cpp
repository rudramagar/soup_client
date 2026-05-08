#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"
#include "soup_session.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <cerrno>
#include <poll.h>
#include <ctime>
#include <unistd.h>

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
