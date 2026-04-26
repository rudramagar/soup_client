#ifndef DECODER_H
#define DECODER_H

#include <cstdint>
#include <string>
#include "config.h"

// Decode and print a single ITCH message.
//
// For ITCH mode:
//   >> {session, seq, field1, field2, ...}
//
// For Glimpse mode:
//   >> {pkt_len, pkt_type, field1, field2, ...}
//
bool decode_itch_message(const uint8_t* msg,
                         uint16_t msg_len,
                         const AppConfig& cfg,
                         const std::string& prefix,
                         bool verbose);

// Decode and print a single OUCH message.
//
// Output format:
//   >> (pkt_len, pkt_type, field1, field2, ...)
//   << (pkt_len, pkt_type, field1, field2, ...)
//
bool decode_ouch_message(const uint8_t* msg,
                         uint16_t msg_len,
                         const AppConfig& cfg,
                         const std::string& prefix,
                         bool verbose);

#endif
