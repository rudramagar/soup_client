#ifndef FILTER_H
#define FILTER_H

#include <cstdint>
#include <string>
#include <vector>
#include "config.h"

struct Filter {
    // Message type filter
    bool has_type_filter;
    bool type_allowed[256];

    // Security filter (SecurityId / OrderbookId)
    bool has_security_filter;
    std::vector<std::string> securities;

    // Order number filter
    bool has_order_number_filter;
    std::vector<uint64_t> order_numbers;

    Filter();

    void add_type(char type);
    void add_security(const std::string& code);
    void add_order_number(uint64_t num);

    // Check if a message passes all filters.
    // msg = raw ITCH message payload
    // msg_len = payload length
    // cfg = config with field offsets
    bool passes(const uint8_t* msg, uint16_t msg_len,
                const AppConfig& cfg) const;
};

#endif
