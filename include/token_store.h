#ifndef TOKEN_STORE_H
#define TOKEN_STORE_H

#include <cstdint>
#include <string>

bool next_tokens(const std::string& username,
                 uint32_t count,
                 uint32_t& out_base);

bool sync_next_token(const std::string& username, uint32_t value);

#endif
