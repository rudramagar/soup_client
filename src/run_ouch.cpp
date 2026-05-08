#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"
#include "soup_session.h"
#include "scenario.h"
#include "token_store.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <cerrno>
#include <poll.h>
#include <ctime>
#include <vector>

int Application::run_ouch() {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    std::string scn_path = scenario_file;
    if (scn_path.empty()) {
        scn_path = "scenarios/ouch_message.txt";
    }

    std::vector<Message> messages;
    uint32_t token_count = 0;
    if (!load_scenario(scn_path, cfg, messages, token_count)) {
        return 1;
    }

    uint32_t base = 0;
    if (token_count > 0) {
        if (!next_tokens(sess.username, token_count, base)) {
            return 1;
        }
    }
    assign_tokens(messages, base);

    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;

    uint64_t login_seq = 0;
    if (has_start_seq) login_seq = start_seq;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq, /*is_ouch=*/true)) {
        return 1;
    }

    for (size_t i = 0; i < messages.size(); i++) {
        const std::vector<uint8_t>& bytes = messages[i].bytes;

        if (!sock.send_bytes(bytes.data(), (int)bytes.size())) {
            std::printf("Send failed on message %zu of %zu\n", i + 1, messages.size());
            break;
        }

        uint16_t pkt_len = (uint16_t)((bytes[0] << 8) | bytes[1]);
        char prefix[64];
        std::snprintf(prefix, sizeof(prefix), ">> (%u,'U'", (unsigned)pkt_len);

        const uint8_t* ouch_payload = &bytes[3];
        uint16_t ouch_len = (uint16_t)(bytes.size() - 3);
        decode_ouch_message(ouch_payload, ouch_len, cfg, std::string(prefix), verbose, true);
    }

    int heartbeat_interval_ms = proto.heartbeat_interval_sec * 1000;
    if (heartbeat_interval_ms <= 0) heartbeat_interval_ms = 1000;

    static const int IDLE_TIMEOUT_MS = 1000;
    static const int POLL_INTERVAL_MS = 200;

    time_t last_send_time = std::time(0);
    time_t last_data_time = std::time(0);

    uint8_t recv_buf[RECV_BUF_CAPACITY];

    struct pollfd poll_fd;
    poll_fd.fd = sock.get_fd();
    poll_fd.events = POLLIN;

    while (1) {
        int poll_result = ::poll(&poll_fd, 1, POLL_INTERVAL_MS);
        time_t now = std::time(0);

        if (poll_result < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if ((long)(now - last_data_time) * 1000 >= IDLE_TIMEOUT_MS) {
            send_logout(sock);
            sock.close();
            return 0;
        }

        if (poll_result == 0) {
            if ((now - last_send_time) >= proto.heartbeat_interval_sec) {
                if (!send_heartbeat(sock)) break;
                last_send_time = now;
            }
            continue;
        }

        uint8_t header[SOUP_HEADER_LEN];
        if (!sock.recv_exact(header, SOUP_HEADER_LEN)) break;

        uint16_t packet_length = read_u16_be(header);
        char packet_type = (char)header[2];
        int payload_length = (packet_length > 1) ? (int)(packet_length - 1) : 0;

        if (packet_type == SOUP_SEQUENCED_DATA) {
            if (payload_length == 0) {
                continue;
            }
            if (payload_length > RECV_BUF_CAPACITY) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
                continue;
            }
            if (!sock.recv_exact(recv_buf, payload_length)) break;

            last_data_time = now;

            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), "<< (%u,'S'",
                          (unsigned)packet_length);
            decode_ouch_message(recv_buf, (uint16_t)payload_length, cfg,
                                std::string(prefix), verbose);
            continue;
        }

        if (packet_type == SOUP_SERVER_HEARTBEAT) {
            if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }
            if (verbose) {
                std::printf("<< (%u,'H')\n", (unsigned)packet_length);
            }
            continue;
        }

        if (packet_type == SOUP_END_OF_SESSION) {
            if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }
            std::printf("<< (%u,'Z')\n", (unsigned)packet_length);
            sock.close();
            return 0;
        }

        if (packet_type == SOUP_DEBUG) {
            if (payload_length > 0 && payload_length <= RECV_BUF_CAPACITY) {
                if (!sock.recv_exact(recv_buf, payload_length)) break;
                if (verbose) {
                    std::printf("<< (%u,'+','%.*s')\n",
                                (unsigned)packet_length,
                                payload_length, (const char*)recv_buf);
                }
            } else if (payload_length > 0) {
                drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
            }
            continue;
        }

        if (payload_length > 0) {
            drain_payload(sock, recv_buf, RECV_BUF_CAPACITY, payload_length);
        }
    }

    sock.close();
    return 1;
}
