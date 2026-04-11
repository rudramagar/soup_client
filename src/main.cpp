#include "application.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <getopt.h>

static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s --mode <protocol> -u <session_key> [options]\n\n"
        "Required:\n"
        "  --mode <protocol>   protocols (itch, glimpse, ...)\n"
        "  -u <session_key>    sessions\n\n"
        "Options:\n"
        "  -s <seq>            start from sequence number\n"
        "  -n <count>          stop after N messages\n"
        "  -v                  verbose mode\n"
        "  --type <X>          filter by message type (repeatable)\n"
        "  --security <code>   filter by SecurityId/OrderbookId (repeatable)\n"
        "  --ordernum <num>    filter by OrderNumber (repeatable)\n"
        "  -h                  show help\n",
        prog);
}

int main(int argc, char** argv) {
    // Line-buffered stdout/stderr
    std::setvbuf(stdout, 0, _IOLBF, 0);
    std::setvbuf(stderr, 0, _IOLBF, 0);

    Application app;

    std::string mode_arg;
    std::string session_arg;

    static struct option long_options[] = {
        {"mode",     required_argument, 0, 1001},
        {"type",     required_argument, 0, 1002},
        {"security", required_argument, 0, 1003},
        {"ordernum", required_argument, 0, 1004},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;

    while ((opt = getopt_long(argc, argv, "u:s:n:vh", long_options, &long_index)) != -1) {
        switch (opt) {

        case 1001:
            mode_arg = optarg;
            break;

        case 1002:
            if (!optarg || std::strlen(optarg) != 1) {
                std::fprintf(stderr, "Invalid --type (expect single char): %s\n",
                        optarg ? optarg : "(null)");
                usage(argv[0]);
                return 1;
            }
            app.get_filter().add_type(optarg[0]);
            break;

        case 1003:
            if (!optarg || std::strlen(optarg) == 0) {
                std::fprintf(stderr, "Invalid --security\n");
                usage(argv[0]);
                return 1;
            }
            app.get_filter().add_security(optarg);
            break;

        case 1004: {
            if (!optarg) {
                std::fprintf(stderr, "Invalid --ordernum\n");
                usage(argv[0]);
                return 1;
            }
            char* end = 0;
            unsigned long long v = std::strtoull(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                std::fprintf(stderr, "Invalid --ordernum: %s\n", optarg);
                usage(argv[0]);
                return 1;
            }
            app.get_filter().add_order_number((uint64_t)v);
            break;
        }

        case 'u':
            session_arg = optarg;
            break;

        case 's': {
            char* end = 0;
            unsigned long long v = std::strtoull(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                std::fprintf(stderr, "Invalid -s: %s\n", optarg);
                usage(argv[0]);
                return 1;
            }
            app.set_start_seq((uint64_t)v);
            break;
        }

        case 'n': {
            char* end = 0;
            unsigned long long v = std::strtoull(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                std::fprintf(stderr, "Invalid -n: %s\n", optarg);
                usage(argv[0]);
                return 1;
            }
            app.set_max_messages((uint64_t)v);
            break;
        }

        case 'v':
            app.set_verbose(true);
            break;

        case 'h':
            usage(argv[0]);
            return 0;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (mode_arg.empty()) {
        std::fprintf(stderr, "Error: --mode is required\n\n");
        usage(argv[0]);
        return 1;
    }

    if (session_arg.empty()) {
        std::fprintf(stderr, "Error: -u is required\n\n");
        usage(argv[0]);
        return 1;
    }

    app.set_mode(mode_arg);
    app.set_session_key(session_arg);

    return app.run();
}
