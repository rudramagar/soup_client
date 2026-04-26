#include "decoder.h"

#include <cstdio>

static uint16_t read_u16_be(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static uint64_t read_u64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void print_field_value(FieldType type, const uint8_t* data, uint32_t size) {
    switch (type) {
        case FIELD_STRING:
            std::printf("%.*s", (int)size, (const char*)data);
            return;
        case FIELD_CHAR:
            std::printf("%c", (char)data[0]);
            return;
        case FIELD_UINT8:
            std::printf("%u", (unsigned)data[0]);
            return;
        case FIELD_UINT16:
            std::printf("%u", (unsigned)read_u16_be(data));
            return;
        case FIELD_UINT32:
            std::printf("%u", (unsigned)read_u32_be(data));
            return;
        case FIELD_UINT64:
            std::printf("%llu", (unsigned long long)read_u64_be(data));
            return;
        case FIELD_INT16:
            std::printf("%d", (int)(int16_t)read_u16_be(data));
            return;
        case FIELD_INT32:
            std::printf("%d", (int)(int32_t)read_u32_be(data));
            return;
        case FIELD_INT64:
            std::printf("%lld", (long long)(int64_t)read_u64_be(data));
            return;
        case FIELD_BINARY:
        default:
            for (uint32_t i = 0; i < size; i++) {
                std::printf("%02X", (unsigned)data[i]);
            }
            return;
    }
}

static bool unpack_message(const uint8_t* msg, uint16_t msg_len,
                           const AppConfig& cfg,
                           const std::string& prefix,
                           bool verbose,
                           char close_bracket) {

    if (!msg || msg_len == 0) {
        return false;
    }

    char msg_type = (char)msg[0];
    const MsgSpec* spec = cfg.outbound_spec_by_type[(unsigned char)msg_type];

    std::printf("%s", prefix.c_str());

    if (!spec) {
        std::printf(", 'Unknown(type=%c)'%c\n", msg_type, close_bracket);
        return false;
    }

    for (size_t i = 0; i < spec->fields.size(); i++) {
        const FieldSpec& field = spec->fields[i];

        if (field.offset + field.size > msg_len) {
            std::printf(", 'TRUNC'%c\n", close_bracket);
            return false;
        }

        const uint8_t* field_data = msg + field.offset;
        std::printf(", '");

        if (verbose) {
            std::printf("%s=", field.name.c_str());
        }

        print_field_value(field.type, field_data, field.size);
        std::printf("'");
    }

    std::printf("%c\n", close_bracket);
    return true;
}

bool decode_itch_message(const uint8_t* msg, uint16_t msg_len,
                         const AppConfig& cfg,
                         const std::string& prefix,
                         bool verbose) {
    return unpack_message(msg, msg_len, cfg, prefix, verbose, '}');
}

bool decode_ouch_message(const uint8_t* msg, uint16_t msg_len,
                         const AppConfig& cfg,
                         const std::string& prefix,
                         bool verbose) {
    return unpack_message(msg, msg_len, cfg, prefix, verbose, ')');
}
