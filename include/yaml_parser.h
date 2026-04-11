#ifndef YAML_PARSER_H
#define YAML_PARSER_H

#include <string>
#include <vector>
#include <map>

// Lightweight YAML parser

struct YamlConfig {
    std::map<std::string, std::string> values;

    std::string get(const std::string& key,
                    const std::string& default_val = "") const;

    int get_int(const std::string& key, int default_val = 0) const;

    bool has(const std::string& key) const;
};

bool parse_yaml(const char* path, YamlConfig& out);

#endif
