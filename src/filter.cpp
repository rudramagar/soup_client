#include "filter.h"
#include <cstring>

// Big-endian reader for order number (uint64)
static uint64_t read_u64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

// Constructor
Filter::Filter()
    : has_type_filter(false),
      has_security_filter(false),
      has_order_number_filter(false) {
    std::memset(type_allowed, 0, sizeof(type_allowed));
}

void Filter::add_type(char type) {
    has_type_filter = true;
    type_allowed[(unsigned char)type] = true;
}

void Filter::add_security(const std::string& code) {
    has_security_filter = true;
    securities.push_back(code);
}

void Filter::add_order_number(uint64_t num) {
    has_order_number_filter = true;
    order_numbers.push_back(num);
}

// Check if a message passes all active filters
//
// All filters are AND logic:
//   --type P --security 9984
//   = only Trade messages for security 9984
bool Filter::passes(const uint8_t* msg, uint16_t msg_len,
                    const AppConfig& cfg) const {

    if (!msg || msg_len == 0) {
        return false;
    }

    // Type filter
    if (has_type_filter) {
        char msg_type = (char)msg[0];
        if (!type_allowed[(unsigned char)msg_type]) {
            return false;
        }
    }

    // Security filter (SecurityId / OrderbookId)
    if (has_security_filter && cfg.security_field_offset >= 0) {
        int offset = cfg.security_field_offset;
        int size = cfg.security_field_size;

        // Only apply if this message has the field
        if (offset + size <= (int)msg_len) {
            std::string msg_security((const char*)(msg + offset), (size_t)size);

            // Trim trailing spaces
            size_t end = msg_security.find_last_not_of(' ');
            if (end != std::string::npos) {
                msg_security = msg_security.substr(0, end + 1);
            }

            // Check if it matches any of the filter values
            bool match = false;
            for (const auto& sec : securities) {
                if (msg_security == sec) {
                    match = true;
                    break;
                }
            }

            if (!match) {
                return false;
            }
        }
    }

    // Order number filter
    if (has_order_number_filter && cfg.order_number_field_offset >= 0) {
        int offset = cfg.order_number_field_offset;
        int size = cfg.order_number_field_size;

        // Only apply if this message has the field
        if (offset + size <= (int)msg_len && size == 8) {
            uint64_t msg_order_num = read_u64_be(msg + offset);

            bool match = false;
            for (uint64_t num : order_numbers) {
                if (msg_order_num == num) {
                    match = true;
                    break;
                }
            }

            if (!match) {
                return false;
            }
        }
    }

    return true;
}
