#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

// ITCH message spec (loaded from JSON)
enum FieldType {
    FIELD_CHAR,
    FIELD_UINT8,
    FIELD_UINT16,
    FIELD_UINT32,
    FIELD_UINT64,
    FIELD_INT16,
    FIELD_INT32,
    FIELD_INT64,
    FIELD_STRING,
    FIELD_BINARY
};

struct FieldSpec {
    std::string name;
    FieldType type;
    uint32_t size;
    uint32_t offset;
};

struct MsgSpec {
    char msg_type;
    std::string name;
    uint32_t total_length;
    std::vector<FieldSpec> fields;

    MsgSpec() : msg_type(0), total_length(0) {}
};

// Session entry (one connection target)
struct SessionConfig {
    std::string key;
    std::string server_ip;
    uint16_t server_port;
    std::string username;
    std::string password;

    SessionConfig() : server_port(0) {}
};

// Protocol entry (itch, glimpse, etc.)
struct ProtocolConfig {
    std::string name;
    std::string protocol_spec;
    int heartbeat_interval_sec;
    int max_reconnect_attempts;
    int reconnect_delay_sec;
    std::vector<SessionConfig> sessions;

    ProtocolConfig()
        : heartbeat_interval_sec(15),
          max_reconnect_attempts(10),
          reconnect_delay_sec(5) {}
};

// Top-level app config
struct AppConfig {
    ProtocolConfig protocol;
    SessionConfig session;

    // Loaded message specs
    std::unordered_map<char, MsgSpec> msg_specs;
    const MsgSpec* spec_by_type[256];

    // Field index cache for filters
    // -1 = not found in spec
    int security_field_offset;
    int security_field_size;
    int order_number_field_offset;
    int order_number_field_size;

    AppConfig();
};

// Load config from YAML, resolve protocol + session,
// load the JSON spec file.
bool load_config(const char* config_path,
                 const std::string& mode,
                 const std::string& session_key);

const AppConfig& config();

#endif
