#ifndef APPLICATION_H
#define APPLICATION_H

#include <cstdint>
#include <string>

#include "filter.h"

struct AppArgs {
    std::string mode;
    std::string session_key;
    std::string scenario_file;

    uint64_t start_seq     = 0;
    bool     has_start_seq = false;
    uint64_t max_messages  = 0;
    bool     verbose       = false;

    Filter   filter;
};

// Per protocol runners
int run_itch(const AppArgs& args);
int run_glimpse(const AppArgs& args);
int run_ouch(const AppArgs& args);

#endif
