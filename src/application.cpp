#include "application.h"
#include "config.h"

#include <cstdio>
#include <cstdint>
#include <string>

Application::Application()
    : has_start_seq(false),
      start_seq(0),
      max_messages(0),
      verbose(false) {
}

void Application::set_mode(const std::string& m)         { mode = m; }
void Application::set_session_key(const std::string& k)  { session_key = k; }
void Application::set_start_seq(uint64_t s)              { has_start_seq = true; start_seq = s; }
void Application::set_max_messages(uint64_t n)           { max_messages = n; }
void Application::set_verbose(bool v)                    { verbose = v; }
void Application::set_scenario_file(const std::string& p){ scenario_file = p; }
Filter& Application::get_filter()                        { return filter; }

int Application::run() {
    const char* config_path = "config/config.yaml";
    if (!load_config(config_path, mode, session_key)) {
        return 1;
    }

    if (mode == "itch") {
        return run_itch();
    }

    if (mode == "glimpse") {
        return run_glimpse();
    }

    if (mode == "ouch") {
        return run_ouch();
    }

    std::printf("Unknown mode: %s\n", mode.c_str());
    return 1;
}
