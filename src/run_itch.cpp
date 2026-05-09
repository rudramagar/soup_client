#include "application.h"
#include "config.h"
#include "tcp_socket.h"
#include "decoder.h"
#include "soupbintcp.h"
#include "soup_session.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <unistd.h>

// ITCH live mode
// output: >> {'session',seq,field1,field2,...}
// end:    >> {'session',seq,'Z'}
int run_itch(const AppArgs& args) {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    uint64_t login_seq = 1;
    if (args.has_start_seq) login_seq = args.start_seq;

    int reconnect_delay_sec = proto.reconnect_delay_sec;
    if (reconnect_delay_sec <= 0) reconnect_delay_sec = 5;
    int reconnect_attempt = 0;

    // Outer loop: each iteration is one connected session.
    while (true) {
        TcpSocket sock;
        std::string session_id;
        uint64_t current_seq = 0;

        if (!connect_and_login(sock, sess, login_seq, session_id, current_seq)) {
            reconnect_attempt++;
            if (proto.max_reconnect_attempts > 0 &&
                reconnect_attempt >= proto.max_reconnect_attempts) {
                return 1;
            }
            ::sleep((unsigned)reconnect_delay_sec);
            continue;
        }
        reconnect_attempt = 0;

        SessionLoopOptions opts;
        opts.heartbeat_interval_sec = proto.heartbeat_interval_sec;
        opts.server_timeout_sec     = proto.heartbeat_interval_sec * 2;
        opts.verbose                = args.verbose;
        opts.ouch_arrows            = false;

        uint64_t decoded_count = 0;

        SessionExit rc = run_session(sock, opts,
            // on_sequenced — one ITCH message arrived
            [&](const uint8_t* payload, uint16_t payload_len, uint16_t /*pkt_len*/) {
                if (payload_len == 0) {
                    current_seq++;
                    return true;
                }

                current_seq++;
                decoded_count++;

                if (!args.filter.passes(payload, payload_len, cfg)) {
                    return true;
                }

                char prefix[128];
                std::snprintf(prefix, sizeof(prefix),
                              ">> {'%.*s',%llu",
                              (int)session_id.size(), session_id.c_str(),
                              (unsigned long long)current_seq);

                decode_itch_message(payload, payload_len, cfg,
                                    std::string(prefix), args.verbose);

                if (args.max_messages != 0 && decoded_count >= args.max_messages) {
                    return false;   // exit cleanly via SESSION_OK
                }
                return true;
            });

        sock.close();

        if (rc == SESSION_OK) {
            // Caller-driven exit (max-msg reached). Done.
            return 0;
        }

        if (rc == SESSION_END_OF_SESSION) {
            std::printf(">> {'%.*s',%llu,'Z'}\n",
                        (int)session_id.size(), session_id.c_str(),
                        (unsigned long long)current_seq);
            return 0;
        }

        // SESSION_SOCKET_ERROR or SESSION_SERVER_TIMEOUT — try to reconnect
        login_seq = current_seq;
        reconnect_attempt++;
        if (proto.max_reconnect_attempts > 0 &&
            reconnect_attempt >= proto.max_reconnect_attempts) {
            return 1;
        }
        ::sleep((unsigned)reconnect_delay_sec);
    }
}
