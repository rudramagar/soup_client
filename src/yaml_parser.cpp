#include "yaml_parser.h"
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <vector>

// YamlConfig accessors

std::string YamlConfig::get(const std::string& key,
                            const std::string& default_val) const {
    std::map<std::string, std::string>::const_iterator it = values.find(key);
    if (it != values.end()) return it->second;
    return default_val;
}

int YamlConfig::get_int(const std::string& key, int default_val) const {
    std::map<std::string, std::string>::const_iterator it = values.find(key);
    if (it != values.end()) return std::atoi(it->second.c_str());
    return default_val;
}

bool YamlConfig::has(const std::string& key) const {
    return values.find(key) != values.end();
}

static int count_indent(const std::string& line) {
    int n = 0;
    for (size_t i = 0; i < line.size(); i++) {
        if (line[i] == ' ' || line[i] == '\t') n++;
        else break;
    }
    return n;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string unquote(const std::string& s) {
    if (s.size() >= 2) {
        if ((s.front() == '"' && s.back() == '"') ||
            (s.front() == '\'' && s.back() == '\'')) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

static bool split_kv(const std::string& line,
                     std::string& key, std::string& value) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return false;
    key = trim(line.substr(0, colon));
    value = trim(line.substr(colon + 1));
    value = unquote(value);
    return true;
}

// Stack entry for tracking nesting
struct Level {
    int indent;
    std::string prefix;
};

bool parse_yaml(const char* path, YamlConfig& out) {
    std::ifstream file(path);
    if (!file) return false;

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }

    // Nesting stack
    std::vector<Level> stack;

    // List state
    int list_indent = -1;
    int list_index = -1;
    std::string list_prefix; // parent prefix of the list (e.g. "protocols.itch.sessions")

    for (size_t i = 0; i < lines.size(); i++) {
        std::string trimmed = trim(lines[i]);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        int indent = count_indent(lines[i]);

        // Check if we left the list
        if (list_indent >= 0 && indent < list_indent) {
            list_indent = -1;
            list_index = -1;
            list_prefix.clear();
        }

        // List item: starts with "- "
        if (trimmed.size() >= 2 && trimmed[0] == '-' && trimmed[1] == ' ') {
            if (list_indent < 0) {
                // Starting a new list
                list_indent = indent;
                list_index = 0;

                // Parent prefix is from the stack
                // (the "sessions:" entry that came before)
                list_prefix.clear();
                for (int s = (int)stack.size() - 1; s >= 0; s--) {
                    if (stack[s].indent < indent) {
                        list_prefix = stack[s].prefix;
                        break;
                    }
                }
            } else {
                list_index++;
            }

            // Parse first field: "- key: value"
            std::string content = trim(trimmed.substr(2));
            std::string key, value;
            if (split_kv(content, key, value)) {
                char idx[16];
                std::snprintf(idx, sizeof(idx), "%d", list_index);
                out.values[list_prefix + "." + idx + "." + key] = value;
            }
            continue;
        }

        // Continuation field inside a list item (indented deeper than "- ")
        if (list_indent >= 0 && indent > list_indent) {
            std::string key, value;
            if (split_kv(trimmed, key, value) && !value.empty()) {
                char idx[16];
                std::snprintf(idx, sizeof(idx), "%d", list_index);
                out.values[list_prefix + "." + idx + "." + key] = value;
            }
            continue;
        }

        while (!stack.empty() && stack.back().indent >= indent) {
            stack.pop_back();
        }

        std::string parent_prefix;
        if (!stack.empty()) {
            parent_prefix = stack.back().prefix;
        }

        std::string key, value;
        if (!split_kv(trimmed, key, value)) continue;

        std::string full_path = parent_prefix.empty() ? key : (parent_prefix + "." + key);

        if (value.empty()) {
            Level lv;
            lv.indent = indent;
            lv.prefix = full_path;
            stack.push_back(lv);
        } else {
            out.values[full_path] = value;
        }
    }

    return true;
}
