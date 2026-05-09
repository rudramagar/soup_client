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
    if (!load_scenario(scn_path, cfg, messages, token_count)) {
        return 1;
    }

    // Reserve and assign token wire values
    uint32_t base = 0;
    if (token_count > 0) {
        if (!next_tokens(sess.username, token_count, base)) {
            return 1;
        }
    }
    assign_tokens(messages, base);

    // Connect and login
    TcpSocket sock;
    std::string session_id;
    uint64_t current_seq = 0;

    uint64_t login_seq = 0;
    if (args.has_start_seq) login_seq = args.start_seq;

    if (!connect_and_login(sock, sess, login_seq, session_id, current_seq,
                           /*is_ouch=*/true)) {
        return 1;
    }

    // Send burst — every scenario message in order, printing each as >> (...).
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

    // Receive loop with idle-exit
    SessionLoopOptions opts;
    opts.heartbeat_interval_sec = proto.heartbeat_interval_sec;
    opts.server_timeout_sec     = 0;        // OUCH: no server timeout, idle-exit instead
    opts.verbose                = args.verbose;
    opts.ouch_arrows            = true;

    static const int IDLE_TIMEOUT_SEC = 1;
    time_t last_data_time = std::time(0);

    SessionExit rc = run_session(sock, opts,
        // on_sequenced — one OUCH server reply arrived
        [&](const uint8_t* payload, uint16_t payload_len, uint16_t pkt_len) {
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
        // on_idle — exit when silent for IDLE_TIMEOUT_SEC
        [&](time_t now) {
            return (now - last_data_time) < IDLE_TIMEOUT_SEC;
        });

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
