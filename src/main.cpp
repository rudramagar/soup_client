#include "application.h"
#include "config.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <getopt.h>

static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s --mode <protocol> -u <session_key> [options]\n\n"
        "Options:\n"
        "  -s <seq>            start from sequence number\n"
        "  -n <count>          stop after N messages\n"
        "  -v                  verbose mode\n"
        "  --type <X>          filter by message type (repeatable)\n"
        "  --security <code>   filter by SecurityId/OrderbookId (repeatable)\n"
        "  --ordernum <num>    filter by OrderNumber (repeatable)\n"
        "  --scenario <path>   ouch scenario file\n"
        "  --listen            keep session open\n"
        "  --rate <n>          continuous send N msg/sec\n"              
        "  --sync-token        sync expected OrderToken number\n"
        "  -h                  show help\n",
        prog);
}

int main(int argc, char** argv) {
    static char stdout_buf[1 << 20];
    std::setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf));
    std::setvbuf(stderr, 0, _IOLBF, 0);

    AppArgs args;

    std::string mode_arg;
    std::string session_arg;

    static struct option long_options[] = {
        {"mode",        required_argument, 0, 1001},
        {"type",        required_argument, 0, 1002},
        {"security",    required_argument, 0, 1003},
        {"ordernum",    required_argument, 0, 1004},
        {"scenario",    required_argument, 0, 1005},
        {"listen",      no_argument,       0, 1006},
        {"rate",        required_argument, 0, 1007},
        {"sync-token",  required_argument, 0, 1008},
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
            args.filter.add_type(optarg[0]);
            break;

        case 1003:
            if (!optarg || std::strlen(optarg) == 0) {
                std::fprintf(stderr, "Invalid --security\n");
                usage(argv[0]);
                return 1;
            }
            args.filter.add_security(optarg);
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
            args.filter.add_order_number((uint64_t)v);
            break;
        }

        case 1005:
            if (!optarg || std::strlen(optarg) == 0) {
                std::fprintf(stderr, "Invalid --scenario\n");
                usage(argv[0]);
                return 1;
            }
            args.scenario_file = optarg;
            break;

        case 1006:
            args.listen_mode = true;
            break;

        case 1007: {
            if (!optarg) {
                std::fprintf(stderr, "Invalid --rate\n");
                usage(argv[0]);
                return 1;
            }

            char* end = 0;
            unsigned long v = std::strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v == 0) {
                std::fprintf(stderr, "Invalid --rate: %s\n", optarg);
                usage(argv[0]);
                return 1;
            }
            args.rate = (uint32_t)v;
            break;
        }

        case 1008:
            args.sync_token = true;
            break;

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
            args.start_seq = (uint64_t)v;
            args.has_start_seq = true;
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
            args.max_messages = (uint64_t)v;
            break;
        }

        case 'v':
            args.verbose = true;
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

    args.mode = mode_arg;
    args.session_key = session_arg;

    if (!load_config("config/config.yaml", args.mode, args.session_key)) {
        return 1;
    }

    if (args.mode == "itch")    return run_itch(args);
    if (args.mode == "glimpse") return run_glimpse(args);
    if (args.mode == "ouch")    return run_ouch(args);

    std::fprintf(stderr, "Unknown mode: %s\n", args.mode.c_str());
    return 1;
}
