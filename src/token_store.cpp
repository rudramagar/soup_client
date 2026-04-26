#include "token_store.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

static const char* TOKENS_DIR = "tokens";

static std::string today_date() {
    std::time_t now = std::time(0);
    std::tm tm_buf;
    std::tm* lt = ::localtime_r(&now, &tm_buf);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d",
                  lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
    return buf;
}

static bool ensure_tokens_dir() {
    struct stat st;
    if (::stat(TOKENS_DIR, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    if (errno != ENOENT) {
        std::printf("Failed to stat %s: %s\n", TOKENS_DIR, std::strerror(errno));
        return false;
    }
    if (::mkdir(TOKENS_DIR, 0755) != 0) {
        std::printf("Failed to create %s: %s\n", TOKENS_DIR, std::strerror(errno));
        return false;
    }
    return true;
}

static std::string token_file_path(const std::string& username) {
    return std::string(TOKENS_DIR) + "/" + username + "_" + today_date() + ".token";
}

static bool read_counter(const std::string& path, uint32_t& out_value) {
    std::ifstream f(path.c_str());
    if (!f) {
        out_value = 0;
        return true;
    }
    std::string line;
    if (!std::getline(f, line)) {
        out_value = 0;
        return true;
    }

    size_t start = 0;
    while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) start++;
    size_t end = line.size();
    while (end > start && (line[end-1] == ' ' || line[end-1] == '\t' ||
                           line[end-1] == '\r' || line[end-1] == '\n')) end--;
    line = line.substr(start, end - start);

    if (line.empty()) {
        out_value = 0;
        return true;
    }

    uint64_t v = 0;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c < '0' || c > '9') {
            std::printf("Token file %s contains non-numeric data: '%s'\n",
                        path.c_str(), line.c_str());
            return false;
        }
        v = v * 10 + (uint64_t)(c - '0');
        if (v > 0xFFFFFFFFULL) {
            std::printf("Token file %s value exceeds uint32 range\n", path.c_str());
            return false;
        }
    }
    out_value = (uint32_t)v;
    return true;
}

static bool write_counter(const std::string& path, uint32_t value) {
    std::ofstream f(path.c_str(), std::ios::trunc);
    if (!f) {
        std::printf("Failed to open token file for writing: %s\n", path.c_str());
        return false;
    }
    f << value << "\n";
    if (!f) {
        std::printf("Failed to write token file: %s\n", path.c_str());
        return false;
    }
    return true;
}

bool next_tokens(const std::string& username,
                 uint32_t count,
                 uint32_t& out_base) {

    if (count == 0) {
        out_base = 0;
        return true;
    }

    if (!ensure_tokens_dir()) return false;

    std::string path = token_file_path(username);

    uint32_t current = 0;
    if (!read_counter(path, current)) return false;

    if (count > 0xFFFFFFFFu - current) {
        std::printf("Token allocation would overflow uint32 (current=%u, count=%u)\n",
                    current, count);
        return false;
    }

    out_base = current;
    uint32_t new_high = current + count;

    if (!write_counter(path, new_high)) return false;
    return true;
}
