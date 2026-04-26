#include "scenario.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

static void write_u16_be(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static void write_u64_be(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v & 0xFF);
}

static bool parse_uint(const std::string& s, uint64_t max_value, uint64_t& out) {
    if (s.empty()) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c < '0' || c > '9') return false;
        if (v > (uint64_t)~0ULL / 10) return false;
        v = v * 10 + (uint64_t)(c - '0');
        if (v > max_value) return false;
    }
    out = v;
    return true;
}

static bool is_token_placeholder(const std::string& s) {
    if (s.size() != 4) return false;
    if (s[0] != 'T' || s[1] != 'K') return false;
    if (s[2] < '0' || s[2] > '9') return false;
    if (s[3] < '0' || s[3] > '9') return false;
    return true;
}

static bool is_token_field(const FieldSpec& f) {
    if (f.type != FIELD_UINT32) return false;
    static const char* suffix = "Token";
    static const size_t slen = 5;
    if (f.name.size() < slen) return false;
    return f.name.compare(f.name.size() - slen, slen, suffix) == 0;
}

static std::vector<std::string> split_pipes(const std::string& line) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= line.size(); i++) {
        if (i == line.size() || line[i] == '|') {
            out.push_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

static void strip_eol(std::string& s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
}

static bool encode_field(const FieldSpec& field,
                         const std::string& value,
                         uint8_t* dst,
                         std::string& err) {

    uint8_t* p = dst + field.offset;

    switch (field.type) {

    case FIELD_CHAR: {
        if (value.empty()) { p[0] = (uint8_t)' '; return true; }
        if (value.size() != 1) {
            err = "field '" + field.name + "' expects single char, got '" + value + "'";
            return false;
        }
        p[0] = (uint8_t)value[0];
        return true;
    }

    case FIELD_STRING: {
        if (value.size() > field.size) {
            err = "field '" + field.name + "' value '" + value +
                  "' exceeds spec size " + std::to_string(field.size);
            return false;
        }
        std::memset(p, ' ', field.size);
        if (!value.empty()) std::memcpy(p, value.data(), value.size());
        return true;
    }

    case FIELD_UINT8: {
        uint64_t v;
        if (!parse_uint(value, 0xFFULL, v)) {
            err = "field '" + field.name + "' invalid uint8: '" + value + "'";
            return false;
        }
        p[0] = (uint8_t)v;
        return true;
    }

    case FIELD_UINT16: {
        uint64_t v;
        if (!parse_uint(value, 0xFFFFULL, v)) {
            err = "field '" + field.name + "' invalid uint16: '" + value + "'";
            return false;
        }
        write_u16_be(p, (uint16_t)v);
        return true;
    }

    case FIELD_UINT32: {
        uint64_t v;
        if (!parse_uint(value, 0xFFFFFFFFULL, v)) {
            err = "field '" + field.name + "' invalid uint32: '" + value + "'";
            return false;
        }
        write_u32_be(p, (uint32_t)v);
        return true;
    }

    case FIELD_UINT64: {
        uint64_t v;
        if (!parse_uint(value, 0xFFFFFFFFFFFFFFFFULL, v)) {
            err = "field '" + field.name + "' invalid uint64: '" + value + "'";
            return false;
        }
        write_u64_be(p, v);
        return true;
    }

    default:
        err = "field '" + field.name + "' has unsupported type for outbound encoding";
        return false;
    }
}

static uint32_t get_token_id(std::unordered_map<std::string, uint32_t>& table,
                             const std::string& name) {
    std::unordered_map<std::string, uint32_t>::iterator it = table.find(name);
    if (it != table.end()) return it->second;
    uint32_t id = (uint32_t)table.size();
    table[name] = id;
    return id;
}

static bool parse_line(const std::string& line,
                       const AppConfig& cfg,
                       std::unordered_map<std::string, uint32_t>& token_table,
                       Message& out,
                       std::string& err) {

    std::vector<std::string> tokens = split_pipes(line);
    if (tokens.size() < 3) {
        err = "expected at least 3 tokens (length|U|msg_type), got " +
              std::to_string(tokens.size());
        return false;
    }

    uint64_t declared_length;
    if (!parse_uint(tokens[0], 0xFFFFULL, declared_length)) {
        err = "invalid length token: '" + tokens[0] + "'";
        return false;
    }

    if (tokens[1].size() != 1 || tokens[1][0] != 'U') {
        err = "expected SoupBinTCP type 'U', got '" + tokens[1] + "'";
        return false;
    }

    if (tokens[2].size() != 1) {
        err = "expected single-char OUCH message type, got '" + tokens[2] + "'";
        return false;
    }
    char msg_type = tokens[2][0];

    const MsgSpec* spec = cfg.inbound_spec_by_type[(unsigned char)msg_type];
    if (!spec) {
        err = std::string("OUCH inbound message type '") + msg_type + "' not in spec";
        return false;
    }

    uint32_t expected_length = 1 + spec->total_length;
    if ((uint32_t)declared_length != expected_length) {
        err = "declared length " + std::to_string(declared_length) +
              " does not match spec-computed length " + std::to_string(expected_length) +
              " for message type '" + std::string(1, msg_type) + "'";
        return false;
    }

    size_t field_tokens = tokens.size() - 3;
    size_t spec_fields_excl_type = spec->fields.size() - 1;
    if (field_tokens != spec_fields_excl_type) {
        err = "expected " + std::to_string(spec_fields_excl_type) +
              " fields for OUCH '" + std::string(1, msg_type) + "', got " +
              std::to_string(field_tokens);
        return false;
    }

    uint32_t packet_size = 2 + 1 + spec->total_length;
    out.bytes.assign(packet_size, 0);
    out.tokens.clear();

    write_u16_be(&out.bytes[0], (uint16_t)expected_length);
    out.bytes[2] = (uint8_t)'U';
    out.bytes[3] = (uint8_t)msg_type;

    uint8_t* ouch_start = &out.bytes[3];
    const uint32_t ouch_offset_in_packet = 3;

    for (size_t i = 1; i < spec->fields.size(); i++) {
        const FieldSpec& field = spec->fields[i];
        const std::string& value = tokens[3 + (i - 1)];

        if (is_token_field(field)) {
            if (is_token_placeholder(value)) {
                uint32_t id = get_token_id(token_table, value);
                TokenRef ref;
                ref.offset = ouch_offset_in_packet + field.offset;
                ref.id = id;
                out.tokens.push_back(ref);
                continue;
            }
        }

        std::string field_err;
        if (!encode_field(field, value, ouch_start, field_err)) {
            err = field_err;
            return false;
        }
    }

    return true;
}

bool load_scenario(const std::string& path,
                   const AppConfig& cfg,
                   std::vector<Message>& out_messages,
                   uint32_t& out_token_count) {

    std::ifstream file(path.c_str());
    if (!file) {
        std::printf("Failed to open scenario file: %s\n", path.c_str());
        return false;
    }

    out_messages.clear();
    out_token_count = 0;

    std::unordered_map<std::string, uint32_t> token_table;

    std::string line;
    int line_no = 0;

    while (std::getline(file, line)) {
        line_no++;
        strip_eol(line);

        if (line.empty()) continue;
        if (line[0] == '#') continue;

        Message msg;
        std::string err;
        if (!parse_line(line, cfg, token_table, msg, err)) {
            std::printf("Scenario %s:%d: %s\n", path.c_str(), line_no, err.c_str());
            return false;
        }

        out_messages.push_back(msg);
    }

    if (out_messages.empty()) {
        std::printf("Scenario %s: no messages found\n", path.c_str());
        return false;
    }

    out_token_count = (uint32_t)token_table.size();
    return true;
}

void assign_tokens(std::vector<Message>& messages, uint32_t base) {
    for (size_t i = 0; i < messages.size(); i++) {
        Message& msg = messages[i];
        for (size_t j = 0; j < msg.tokens.size(); j++) {
            const TokenRef& ref = msg.tokens[j];
            uint32_t wire_value = base + ref.id + 1;
            write_u32_be(&msg.bytes[ref.offset], wire_value);
        }
    }
}
