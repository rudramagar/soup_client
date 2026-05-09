#ifndef SOUP_SESSION_H
#define SOUP_SESSION_H

#include <cstdint>
#include <ctime>
#include <functional>
#include <string>

#include "config.h"
#include "tcp_socket.h"

// Buffer constants used by
// all protocol's
// receive loop.
constexpr int RECV_BUF_CAPACITY    = 64 * 1024;
constexpr int SOCKET_RECV_BUF_SIZE = 4 * 1024 * 1024;

// Big-endian
// integer readers or writers.
uint16_t read_u16_be(const uint8_t* src);
uint32_t read_u32_be(const uint8_t* src);
uint64_t read_u64_be(const uint8_t* src);
void write_u16_be(uint8_t* dst, uint16_t value);
void write_u32_be(uint8_t* dst, uint32_t value);
void write_u64_be(uint8_t* dst, uint64_t value);

// SoupBinTCP framed msg
// connect and login
bool connect_and_login(TcpSocket& sock,
                       const SessionConfig& session,
                       uint64_t requested_sequence,
                       std::string& session_id,
                       uint64_t& sequence_number,
                       bool is_ouch = false);

// send HB packet (1-byte payload)
bool send_heartbeat(TcpSocket& sock);

// send a logout request packet (1-byte payload)
bool send_logout(TcpSocket& sock);

// Read and discard
bool drain_payload(TcpSocket& sock,
                   uint8_t* scratch_buf,
                   int scratch_buf_capacity,
                   int bytes_to_drain);

// =============================================================================
// run_session: shared receive loop used by all three protocols.
//
// Polls the socket, reads SoupBinTCP packets, and dispatches Sequenced Data
// to a caller-supplied callback. Server Heartbeats, End-of-Session, and
// Debug packets are handled internally.
// =============================================================================

struct SessionLoopOptions {
    int  heartbeat_interval_sec = 1;
    int  server_timeout_sec     = 0;     // 0 = never timeout
    bool ouch_arrows            = false; // true: << for received, false: >>
    bool verbose                = false; // print Heartbeat/Debug packets
};

// How run_session ended.
enum SessionExit {
    SESSION_OK,             // callback returned false (caller-driven exit)
    SESSION_END_OF_SESSION, // server sent 'Z'
    SESSION_SOCKET_ERROR,   // recv/send failed
    SESSION_SERVER_TIMEOUT, // no data for server_timeout_sec
};

// Called for each Sequenced Data packet (one OUCH/ITCH/Glimpse message).
// `payload`     - bytes inside the SoupBin envelope (the message itself)
// `payload_len` - size of payload in bytes
// `packet_len`  - the SoupBin length field (== payload_len + 1, includes type byte)
// Return true to keep going, false to exit cleanly with SESSION_OK.
using OnSequencedFn = std::function<bool(const uint8_t* payload,
                                          uint16_t payload_len,
                                          uint16_t packet_len)>;

// Called on every poll wake (timeout or after a packet). Use this for idle-
// timeout exits, send pacing, or other periodic checks. Pass nullptr to skip.
// Return true to keep going, false to exit cleanly with SESSION_OK.
using OnIdleFn = std::function<bool(time_t now)>;

SessionExit run_session(TcpSocket& sock,
                        const SessionLoopOptions& opts,
                        OnSequencedFn on_sequenced,
                        OnIdleFn      on_idle = nullptr);

#endif
