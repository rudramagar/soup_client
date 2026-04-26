#ifndef SCENARIO_H
#define SCENARIO_H

#include <cstdint>
#include <string>
#include <vector>

#include "config.h"

struct TokenRef {
    uint32_t offset;
    uint32_t id;
};

struct Message {
    // Complete SoupBinTCP packet
    std::vector<uint8_t> bytes;

    // token fill via assign_tokens().
    std::vector<TokenRef> tokens;
};

bool load_scenario(const std::string& path,
                   const AppConfig& cfg,
                   std::vector<Message>& out_messages,
                   uint32_t& out_token_count);

void assign_tokens(std::vector<Message>& messages, uint32_t base);

#endif
