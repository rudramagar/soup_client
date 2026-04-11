#ifndef SOUPBINTCP_H
#define SOUPBINTCP_H

#include <cstdint>

// SoupBinTCP 3.0 Packet types
// Client -> Server
static const char SOUP_LOGIN_REQUEST    = 'L';
static const char SOUP_LOGOUT_REQUEST   = 'O';
static const char SOUP_CLIENT_HEARTBEAT = 'R';

// Server -> Client
static const char SOUP_LOGIN_ACCEPTED   = 'A';
static const char SOUP_LOGIN_REJECTED   = 'J';
static const char SOUP_SEQUENCED_DATA   = 'S';
static const char SOUP_SERVER_HEARTBEAT = 'H';
static const char SOUP_END_OF_SESSION   = 'Z';
static const char SOUP_DEBUG            = '+';

// SoupBinTCP packet header
//   2 bytes  Packet Length (big-endian, excludes itself)
//   1 byte   Packet Type
static const int SOUP_HEADER_LEN = 3;

// Login Request payload (after header)
//  6 bytes   Username
//  10 bytes   Password
//  10 bytes   Requested Session
//  20 bytes   Requested Sequence Number (ASCII)
#pragma pack(push, 1)
struct LoginRequestPayload {
    char username[6];
    char password[10];
    char requested_session[10];
    char requested_sequence[20];
};
#pragma pack(pop)

static const int LOGIN_REQUEST_PAYLOAD_LEN = 46;

// Login Accepted payload
//  10 bytes   Session
//  20 bytes   Sequence Number (ASCII)
#pragma pack(push, 1)
struct LoginAcceptedPayload {
    char session[10];
    char sequence_number[20];
};
#pragma pack(pop)

static const int LOGIN_ACCEPTED_PAYLOAD_LEN = 30;

#endif
