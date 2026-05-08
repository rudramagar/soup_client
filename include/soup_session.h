#ifndef SOUP_SESSION_H
#define SOUP_SESSION_H

#include <cstdint>
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
uint64_t read_u64_be(const uint8_t* src);
void write_u16_be(uint8_t* dst, uint16_t value);

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

#endif
