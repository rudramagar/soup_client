#include "config.h"
#include "yaml_parser.h"

#include <fstream>
#include <cstdio>
#include <cstring>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// AppConfig constructor
AppConfig::AppConfig()
    : security_field_offset(-1),
      security_field_size(0),
      order_number_field_offset(-1),
      order_number_field_size(0) {
    std::memset(spec_by_type, 0, sizeof(spec_by_type));
}

static AppConfig app_config;

// Resolve config path relative to config file
static std::string resolve_path(const char* config_path,
                                const std::string& relative_path) {
    if (relative_path.empty()) return "";
    if (relative_path[0] == '/') return relative_path;

    std::string config_file = config_path;
    size_t last_slash = config_file.find_last_of('/');
    if (last_slash == std::string::npos) return relative_path;

    return config_file.substr(0, last_slash) + "/" + relative_path;
}

// Parse field type from JSON spec string
static FieldType parse_field_type(const std::string& s) {
    if (s == "char")   return FIELD_CHAR;
    if (s == "uint8")  return FIELD_UINT8;
    if (s == "uint16") return FIELD_UINT16;
    if (s == "uint32") return FIELD_UINT32;
    if (s == "uint64") return FIELD_UINT64;
    if (s == "int16")  return FIELD_INT16;
    if (s == "int32")  return FIELD_INT32;
    if (s == "int64")  return FIELD_INT64;
    if (s == "string") return FIELD_STRING;
    if (s == "binary") return FIELD_BINARY;
    return FIELD_STRING;
}

// Load JSON message spec file
static bool load_spec(const std::string& spec_path, AppConfig* cfg) {
    std::ifstream file(spec_path.c_str());
    if (!file) {
        std::printf("Failed to open spec: %s\n", spec_path.c_str());
        return false;
    }

    json root;
    file >> root;

    cfg->msg_specs.clear();
    std::memset(cfg->spec_by_type, 0, sizeof(cfg->spec_by_type));

    for (json::iterator it = root.begin(); it != root.end(); ++it) {
        std::string msg_key = it.key();
        if (msg_key.size() != 1) continue;

        const json& obj = it.value();
        MsgSpec msg;
        msg.msg_type = msg_key[0];
        msg.name = obj.value("name", "");

        uint32_t offset = 0;
        const json& fields = obj["fields"];

        for (size_t i = 0; i < fields.size(); i++) {
            const json& fld = fields[i];
            FieldSpec field_spec;
            field_spec.name = fld.value("name", "");
            field_spec.type = parse_field_type(fld.value("type", "string"));
            field_spec.size = (uint32_t)fld.value("size", 0);
            field_spec.offset = offset;
            offset += field_spec.size;
            msg.fields.push_back(field_spec);
        }

        msg.total_length = offset;
        cfg->msg_specs[msg.msg_type] = msg;
        cfg->spec_by_type[(unsigned char)msg.msg_type] = &cfg->msg_specs[msg.msg_type];
    }

    return true;
}

// Build field index cache for filters
//
// Scans all message specs to find SecurityId,
// OrderbookId, and OrderNumber fields.

static void build_field_index(AppConfig* cfg) {
    cfg->security_field_offset = -1;
    cfg->security_field_size = 0;
    cfg->order_number_field_offset = -1;
    cfg->order_number_field_size = 0;

    // Find security field (SecurityId or OrderbookId)
    std::unordered_map<char, MsgSpec>::iterator it;
    for (it = cfg->msg_specs.begin(); it != cfg->msg_specs.end(); ++it) {
        std::vector<FieldSpec>& fields = it->second.fields;
        for (size_t i = 0; i < fields.size(); i++) {
            FieldSpec& field = fields[i];

            if (cfg->security_field_offset < 0) {
                if (field.name == "SecurityId" ||
                    field.name == "OrderbookId") {
                    cfg->security_field_offset = (int)field.offset;
                    cfg->security_field_size = (int)field.size;
                }
            }
            if (cfg->order_number_field_offset < 0) {
                if (field.name == "OrderNumber") {
                    cfg->order_number_field_offset = (int)field.offset;
                    cfg->order_number_field_size = (int)field.size;
                }
            }
        }
    }
}

// Load config from YAML
bool load_config(const char* config_path,
                 const std::string& mode,
                 const std::string& session_key) {

    YamlConfig yaml;
    if (!parse_yaml(config_path, yaml)) {
        std::printf("Failed to parse config: %s\n", config_path);
        return false;
    }

    std::string proto_prefix = "protocols." + mode;

    std::string spec_path = yaml.get(proto_prefix + ".protocol_spec");
    if (spec_path.empty()) {
        std::printf("Protocol '%s' not found or missing protocol_spec\n", mode.c_str());
        return false;
    }

    ProtocolConfig proto;
    proto.name = mode;
    proto.protocol_spec = spec_path;
    proto.heartbeat_interval_sec = yaml.get_int(proto_prefix + ".heartbeat_interval_sec", 15);
    proto.max_reconnect_attempts = yaml.get_int(proto_prefix + ".max_reconnect_attempts", 10);
    proto.reconnect_delay_sec = yaml.get_int(proto_prefix + ".reconnect_delay_sec", 5);

    bool session_found = false;
    SessionConfig session;
    std::string sessions_prefix = proto_prefix + ".sessions";

    for (int idx = 0; idx < 100; idx++) {
        char idx_str[16];
        std::snprintf(idx_str, sizeof(idx_str), "%d", idx);
        std::string item_prefix = sessions_prefix + "." + idx_str;

        std::string item_key = yaml.get(item_prefix + ".key");
        if (item_key.empty()) {
            break;  // no more sessions
        }

        if (item_key == session_key) {
            session.key = session_key;
            session.server_ip = yaml.get(item_prefix + ".server_ip");
            session.server_port = (uint16_t)yaml.get_int(item_prefix + ".server_port");
            session.username = yaml.get(item_prefix + ".username");
            session.password = yaml.get(item_prefix + ".password");
            session_found = true;
            break;
        }
    }

    if (!session_found) {
        std::printf("Session '%s' not found in protocol '%s'\n",
                    session_key.c_str(), mode.c_str());
        return false;
    }

    if (session.server_ip.empty()) {
        std::printf("Session '%s' missing server_ip\n", session_key.c_str());
        return false;
    }
    if (session.server_port == 0) {
        std::printf("Session '%s' missing server_port\n", session_key.c_str());
        return false;
    }

    proto.protocol_spec = resolve_path(config_path, proto.protocol_spec);

    AppConfig cfg;
    cfg.protocol = proto;
    cfg.session = session;
    app_config = cfg;

    if (!load_spec(app_config.protocol.protocol_spec, &app_config)) {
        return false;
    }

    build_field_index(&app_config);

    return true;
}

const AppConfig& config() {
    return app_config;
}
