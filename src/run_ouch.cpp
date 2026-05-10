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
#include <ctime>
#include <vector>

// OUCH order entry mode
// outbound (client -> server):  >> (pkt_len,'U',msg_type,...)
// inbound  (server -> client):  << (pkt_len,'S',msg_type,...)
int run_ouch(const AppArgs& args) {
    const AppConfig& cfg = config();
    const ProtocolConfig& proto = cfg.protocol;
    const SessionConfig& sess = cfg.session;

    // Load scenario file
    std::string scn_path = args.scenario_file;
    if (scn_path.empty()) {
        scn_path = "scenarios/ouch_message.txt";
    }

    std::vector<Message> messages;
    uint32_t token_count = 0;
    if (!args.sync_token) {
        if (!load_scenario(scn_path, cfg, messages, token_count)) {
            return 1;
        }
    }

    // Reserve and assign token wire values
    uint32_t base = 0;
    if (args.rate == 0 && token_count > 0) {
        if (!next_tokens(sess.username, token_count, base)) {
            return 1;
        }
        assign_tokens(messages, base);
    }

    // Connect and login
    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;

    uint64_t login_seq = 0;
    if (args.has_start_seq) login_seq = args.start_seq;
    if (args.sync_token) login_seq = 0;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq,
                           /*is_ouch=*/true)) {
        return 1;
    }

    // Send burst (finite path only - continuous mode sends from on_idle)
    if (args.rate == 0) {
        for (size_t i = 0; i < messages.size(); i++) {
            const std::vector<uint8_t>& bytes = messages[i].bytes;

            if (!sock.send_bytes(bytes.data(), (int)bytes.size())) {
                std::printf("Send failed on message %zu of %zu\n",
                            i + 1, messages.size());
                break;
            }

            uint16_t pkt_len = (uint16_t)((bytes[0] << 8) | bytes[1]);
            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), ">> (%u,'U'", (unsigned)pkt_len);

            const uint8_t* ouch_payload = &bytes[3];
            uint16_t ouch_len = (uint16_t)(bytes.size() - 3);
            decode_ouch_message(ouch_payload, ouch_len, cfg,
                                std::string(prefix), args.verbose, true);
        }
    }

    // Receive loop with idle-exit
    SessionLoopOptions opts;
    opts.heartbeat_interval_sec = proto.heartbeat_interval_sec;
    opts.server_timeout_sec     = 0;        // OUCH: no server timeout, idle-exit instead
    opts.verbose                = args.verbose;
    opts.ouch_arrows            = true;

    static const int IDLE_TIMEOUT_SEC = 1;
    time_t last_data_time = std::time(0);

    // Continuous mode state
    static const uint32_t TOKEN_CHUNK = 10000;
    uint32_t chunk_used = 0;
    uint32_t scn_idx    = 0;
    time_t   start_time = std::time(0);
    uint64_t sent       = 0;

    // Sync token
    uint32_t max_token = 0;

    if (args.rate > 0) {
        if (!next_tokens(sess.username, TOKEN_CHUNK, base)) return 1;
    }

    SessionExit rc = run_session(sock, opts,
        // on_sequenced — one OUCH server reply arrived
        [&](const uint8_t* payload, uint16_t payload_len, uint16_t pkt_len) {
            if (args.sync_token) {
                if (payload_len >= 13) {
                    uint32_t tok = read_u32_be(payload + 9);
                    if (tok > max_token) max_token = tok;
                }
                last_data_time = std::time(0);
                return true;
            }

            if (payload_len == 0) {
                last_data_time = std::time(0);
                return true;
            }

            char prefix[64];
            std::snprintf(prefix, sizeof(prefix), "<< (%u,'S'", (unsigned)pkt_len);
            decode_ouch_message(payload, payload_len, cfg,
                                std::string(prefix), args.verbose);

            last_data_time = std::time(0);
            return true;
        },
        // on_idle - rate mode sends paced messages;
        // otherwise idle-exit logic
        [&](time_t now) {
            if (args.rate > 0) {
                // How many messages should we have sent by elapsed time?
                long elapsed_sec = (long)(now - start_time);
                uint64_t target = (uint64_t)elapsed_sec * args.rate;

                while (sent < target) {
                    // Top up tokens if running low
                    if (chunk_used + token_count > TOKEN_CHUNK) {
                        if (!next_tokens(sess.username, TOKEN_CHUNK, base)) return false;
                        chunk_used = 0;
                    }
                    // Assign fresh tokens at start of each scenario iteration
                    if (scn_idx == 0) {
                        assign_tokens(messages, base + chunk_used);
                        chunk_used += token_count;
                    }

                    const std::vector<uint8_t>& bytes = messages[scn_idx].bytes;
                    if (!sock.send_bytes(bytes.data(), (int)bytes.size())) return false;

                    uint16_t pkt_len = (uint16_t)((bytes[0] << 8) | bytes[1]);
                    char prefix[64];
                    std::snprintf(prefix, sizeof(prefix), ">> (%u,'U'", (unsigned)pkt_len);
                    decode_ouch_message(&bytes[3], (uint16_t)(bytes.size() - 3),
                                        cfg, std::string(prefix), args.verbose, true);

                    sent++;
                    scn_idx++;
                    if (scn_idx >= messages.size()) scn_idx = 0;
                }
                return true;
            }

            // Original behavior (rate == 0)
            if (args.listen_mode) return true;
            return (now - last_data_time) < IDLE_TIMEOUT_SEC;
        });

    if (args.sync_token) {
        if (max_token > 0) {
            sync_next_token(sess.username, max_token);
            std::printf("[Synced: OrderToken=%u]\n", (unsigned)max_token);
        } else {
            std::printf("[]\n");
        }
        sock.close();
        return 0;
    }

    // Caller-driven exit (idle): send logout cleanly
    if (rc == SESSION_OK) {
        send_logout(sock);
        sock.close();
        return 0;
    }

    if (rc == SESSION_END_OF_SESSION) {
        std::printf("<< (1,'Z')\n");
        sock.close();
        return 0;
    }

    // SESSION_SOCKET_ERROR or SESSION_SERVER_TIMEOUT
    sock.close();
    return 1;
}
