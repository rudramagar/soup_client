#ifndef APPLICATION_H
#define APPLICATION_H

#include <cstdint>
#include <string>
#include "filter.h"

class Application {
public:
    Application();

    // Set from CLI args
    void set_mode(const std::string& mode);
    void set_session_key(const std::string& key);
    void set_start_seq(uint64_t seq);
    void set_max_messages(uint64_t count);
    void set_verbose(bool value);
    void set_scenario_file(const std::string& path);

    // Access filter for CLI setup
    Filter& get_filter();

    int run();

private:
    std::string mode;
    std::string session_key;
    std::string scenario_file;

    bool has_start_seq;
    uint64_t start_seq;

    uint64_t max_messages;
    bool verbose;

    Filter filter;

    // Run modes
    int run_itch();
    int run_glimpse();
    int run_ouch();
};

#endif
