#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"
#include "soup_session.h"

#include <cstdio>
#include <cstdint>
#include <string>

// Glimpse snapshot mode
// output: >> {pkt_len,'S',field1,field2,...}
// end:    >> {pkt_len,'S','G',next_seq}
int run_glimpse(const AppArgs& args) {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    // glimpse always starts from sequence 1
    uint64_t login_seq = 1;

    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
        return 1;
    }

    SessionLoopOptions opts;
    opts.heartbeat_interval_sec = proto.heartbeat_interval_sec;
    opts.server_timeout_sec     = proto.heartbeat_interval_sec * 2;
    opts.verbose                = args.verbose;
    opts.ouch_arrows            = false;

    uint64_t decoded_count = 0;

    SessionExit rc = run_session(sock, opts,
        // on_sequenced — one snapshot message arrived
        [&](const uint8_t* payload, uint16_t payload_len, uint16_t pkt_len) {
            if (payload_len == 0) {
                return true;
            }

            // End of Snapshot — message type 'G'
            if (payload_len >= 1 && (char)payload[0] == 'G') {
                // sequence number offset varies by server:
                // 9 bytes:  MessageType(1) + SequenceNumber(8)
                // 17 bytes: MessageType(1) + Timestamp(8) + SequenceNumber(8)
                uint64_t realtime_next_sequence = 0;
                int sequence_offset = (payload_len >= 17) ? 9 : 1;
                if (sequence_offset + 8 <= payload_len) {
                    realtime_next_sequence = read_u64_be(payload + sequence_offset);
                }

                std::printf(">> {%u,'S','G',%llu}\n",
                            (unsigned)pkt_len,
                            (unsigned long long)realtime_next_sequence);
                return false;   // exit cleanly via SESSION_OK
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
                return false;   // exit cleanly via SESSION_OK
            }
            return true;
        });

    sock.close();

    if (rc == SESSION_OK || rc == SESSION_END_OF_SESSION) {
        return 0;
    }

    // SESSION_SOCKET_ERROR or SESSION_SERVER_TIMEOUT
    return 1;
}
