#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"
#include "soup_session.h"

#include <cstdio>
#include <cstdint>
#include <string>

int run_glimpse(const AppArgs& args) {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    uint64_t login_seq = 1;

    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
        return 1;
    }

    SessionLoopOptions opts;
    opts.heartbeat_interval_sec = proto.heartbeat_interval_sec;
    opts.server_timeout_sec     = proto.heartbeat_interval_sec * 15;
    if (opts.server_timeout_sec < 15) opts.server_timeout_sec = 15;
    opts.verbose                = args.verbose;
    opts.ouch_arrows            = false;

    uint64_t decoded_count = 0;

    SessionExit rc = run_session(sock, opts,
        [&](const uint8_t* payload, uint16_t payload_len, uint16_t pkt_len) {
            if (payload_len == 0) {
                return true;
            }

            if (payload_len >= 1 && (char)payload[0] == 'G') {
                uint64_t realtime_next_sequence = 0;
                int sequence_offset = (payload_len >= 17) ? 9 : 1;
                if (sequence_offset + 8 <= payload_len) {
                    realtime_next_sequence = read_u64_be(payload + sequence_offset);
                }

                std::printf(">> {%u,'S','G',%llu}\n",
                            (unsigned)pkt_len,
                            (unsigned long long)realtime_next_sequence);
                return false;
            }

            decoded_count++;

            if (!args.filter.passes(payload, payload_len, cfg)) {
                return true;
            }

            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), ">> {%u,'S'", (unsigned)pkt_len);

            decode_itch_message(payload, payload_len, cfg,
                                std::string(prefix), args.verbose);

            if (args.max_messages != 0 && decoded_count >= args.max_messages) {
                return false;
            }
            return true;
        });

    sock.close();

    if (rc == SESSION_OK || rc == SESSION_END_OF_SESSION) {
        return 0;
    }

    return 1;
}
