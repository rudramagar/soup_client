#include "application.h"
#include "config.h"

#include <cstdio>

int run_app(const AppArgs& args) {
    if (!load_config("config/config.yaml", args.mode, args.session_key)) {
        return 1;
    }

    if (args.mode == "itch")    return run_itch(args);
    if (args.mode == "glimpse") return run_glimpse(args);
    if (args.mode == "ouch")    return run_ouch(args);

    std::printf("Unknown mode: %s\n", args.mode.c_str());
    return 1;
}
