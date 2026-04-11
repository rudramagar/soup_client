#include "tcp_socket.h"
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>

TcpSocket::TcpSocket() : fd(-1) {}

TcpSocket::~TcpSocket() {
    close();
}

void TcpSocket::close() {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

bool TcpSocket::connect_to(const std::string& ip, uint16_t port) {
    if (fd >= 0) {
        close();
    }

    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close();
        return false;
    }

    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close();
        return false;
    }

    return true;
}

bool TcpSocket::send_bytes(const uint8_t* data, int len) {
    if (fd < 0 || !data || len <= 0) {
        return false;
    }

    int sent = 0;
    while (sent < len) {
        int n = (int)::send(fd, data + sent, (size_t)(len - sent), MSG_NOSIGNAL);
        if (n <= 0) {
            return false;
        }
        sent += n;
    }

    return true;
}

bool TcpSocket::recv_exact(uint8_t* buffer, int len) {
    if (fd < 0 || !buffer || len <= 0) {
        return false;
    }

    int received = 0;
    while (received < len) {
        int n = (int)::recv(fd, buffer + received, (size_t)(len - received), 0);
        if (n <= 0) {
            return false;
        }
        received += n;
    }

    return true;
}

bool TcpSocket::set_receive_buffer(int bytes) {
    if (fd < 0) return false;
    return ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) == 0;
}

bool TcpSocket::set_nodelay(bool enable) {
    if (fd < 0) return false;
    int flag = enable ? 1 : 0;
    return ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == 0;
}

int TcpSocket::get_fd() const {
    return fd;
}
