#include "yaml_parser.h"
#include <fstream>
#include <cstdlib>

// YamlConfig accessors
std::string YamlConfig::get(const std::string& key,
                            const std::string& default_val) const {
    std::map<std::string, std::string>::const_iterator it = values.find(key);
    if (it != values.end()) {
        return it->second;
    }
    return default_val;
}

int YamlConfig::get_int(const std::string& key, int default_val) const {
    std::map<std::string, std::string>::const_iterator it = values.find(key);
    if (it != values.end()) {
        return std::atoi(it->second.c_str());
    }
    return default_val;
}

bool YamlConfig::has(const std::string& key) const {
    return values.find(key) != values.end();
}

// Helpers
// Count leading spaces
static int count_indent(const std::string& line) {
    int count = 0;
    for (size_t i = 0; i < line.size(); i++) {
        if (line[i] == ' ') count++;
        else break;
    }
    return count;
}

// Trim whitespace from both ends
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Remove surrounding quotes from a value
static std::string unquote(const std::string& s) {
    if (s.size() >= 2) {
        if ((s.front() == '"' && s.back() == '"') ||
            (s.front() == '\'' && s.back() == '\'')) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

// Split "key: value" into key and value parts.
// Returns false if no colon found.
static bool split_kv(const std::string& line,
                     std::string& key, std::string& value) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return false;
    key = trim(line.substr(0, colon));
    value = trim(line.substr(colon + 1));
    value = unquote(value);
    return true;
}

// Parser
// Reads our YAML structure and stores as flat
// dotted keys. Handles:
//   - Scalar values at any depth
//   - List items with "- key: value"
//   - Comments and blank lines

bool parse_yaml(const char* path, YamlConfig& out) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }

    // Read all lines
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }

    // Path stack tracks the current nested key prefix
    // at each indent level.
    // path_at_indent[2] = "protocols"
    // path_at_indent[4] = "protocols.itch"
    // etc.
    std::string path_at_indent[20];
    int list_index = -1;         // current list item index
    int list_indent = -1;        // indent level where list started
    std::string list_prefix;     // dotted prefix for list items

    for (size_t i = 0; i < lines.size(); i++) {
        std::string trimmed = trim(lines[i]);

        // Skip empty and comments
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        int indent = count_indent(lines[i]);

        // If we dropped below list indent, list is over
        if (list_indent >= 0 && indent <= list_indent) {
            list_index = -1;
            list_indent = -1;
            list_prefix.clear();
        }

        // List item: "- key: value"
        if (trimmed.size() >= 2 && trimmed[0] == '-' && trimmed[1] == ' ') {
            // Start new list item
            if (list_indent < 0) {
                // First list item — find the parent prefix
                // Parent is at indent - 2
                int parent_indent = indent - 2;
                if (parent_indent >= 0 && parent_indent < 20) {
                    list_prefix = path_at_indent[parent_indent];
                }
                list_indent = indent;
                list_index = 0;
            } else {
                list_index++;
            }

            // Parse "- key: value" first field
            std::string item_content = trim(trimmed.substr(2));
            std::string key, value;
            if (split_kv(item_content, key, value)) {
                char idx_str[16];
                std::snprintf(idx_str, sizeof(idx_str), "%d", list_index);
                std::string full_key = list_prefix + "." + idx_str + "." + key;
                out.values[full_key] = value;
            }

            // Set path for continuation fields
            if (indent + 2 < 20) {
                char idx_str[16];
                std::snprintf(idx_str, sizeof(idx_str), "%d", list_index);
                path_at_indent[indent + 2] = list_prefix + "." + idx_str;
            }

            continue;
        }

        // Inside a list item continuation (indent > list start)
        if (list_indent >= 0 && indent > list_indent && list_index >= 0) {
            std::string key, value;
            if (split_kv(trimmed, key, value) && !value.empty()) {
                char idx_str[16];
                std::snprintf(idx_str, sizeof(idx_str), "%d", list_index);
                std::string full_key = list_prefix + "." + idx_str + "." + key;
                out.values[full_key] = value;
            }
            continue;
        }

        // Regular "key: value" or "key:" (section)
        std::string key, value;
        if (!split_kv(trimmed, key, value)) {
            continue;
        }

        // Build dotted prefix for this indent level
        std::string prefix;
        if (indent >= 2) {
            // Find parent at indent - 2
            int parent_indent = indent - 2;
            if (parent_indent >= 0 && parent_indent < 20) {
                prefix = path_at_indent[parent_indent];
            }
        }

        std::string full_path = prefix.empty() ? key : (prefix + "." + key);

        if (value.empty()) {
            // Section header (e.g. "protocols:", "itch:")
            // Store the path for children to reference
            if (indent < 20) {
                path_at_indent[indent] = full_path;
            }
        } else {
            // Scalar value
            out.values[full_path] = value;
        }

        // Store path at this indent level
        if (indent < 20) {
            path_at_indent[indent] = full_path;
        }
    }

    return true;
}
