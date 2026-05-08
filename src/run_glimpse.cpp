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

                std::printf(">> {%u,'S','G', %llu}\n",
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
            std::snprintf(prefix, sizeof(prefix), ">> {%u,'S'", (unsigned)packet_length);

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
                std::printf(">> {%u,'H'}\n", (unsigned)packet_length);
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
