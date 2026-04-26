#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

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

struct SessionConfig {
    std::string key;
    std::string server_ip;
    uint16_t server_port;
    std::string username;
    std::string password;

    SessionConfig() : server_port(0) {}
};

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

struct AppConfig {
    ProtocolConfig protocol;
    SessionConfig session;

    std::unordered_map<char, MsgSpec> outbound_specs;
    std::unordered_map<char, MsgSpec> inbound_specs;
    const MsgSpec* outbound_spec_by_type[256];
    const MsgSpec* inbound_spec_by_type[256];

    int security_field_offset;
    int security_field_size;
    int order_number_field_offset;
    int order_number_field_size;

    AppConfig();
};

bool load_config(const char* config_path,
                 const std::string& mode,
                 const std::string& session_key);

const AppConfig& config();

#endif
