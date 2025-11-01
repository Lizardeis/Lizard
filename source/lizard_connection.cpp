#include "lizard_connection.h"
#include <netdb.h>
#include <cstring>
#include <iostream>

namespace lizard {

Connection::Connection(int socket)
    : socket_(socket), tlsConnection_(nullptr), state_(ConnectionState::IDLE),
      remoteHost_(""), remotePort_(0), keepAlive_(true),
      lastActivity_(std::chrono::steady_clock::now()) {}

Connection::Connection(const std::string& host, int port)
    : socket_(-1), tlsConnection_(nullptr), state_(ConnectionState::IDLE),
      remoteHost_(host), remotePort_(port), keepAlive_(true),
      lastActivity_(std::chrono::steady_clock::now()) {}

Connection::~Connection() {
    close();
}

bool Connection::connect(std::shared_ptr<TLSContext> tlsContext) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (socket_ < 0) {
        socket_ = SocketHelper::createSocket();
        if (socket_ < 0) {
            return false;
        }
    }

    state_ = ConnectionState::CONNECTING;

    if (!SocketHelper::connect(socket_, remoteHost_, remotePort_)) {
        state_ = ConnectionState::ERROR;
        return false;
    }

    tlsConnection_ = std::make_shared<TLSConnection>(tlsContext, socket_);
    if (!tlsConnection_->connect()) {
        state_ = ConnectionState::ERROR;
        return false;
    }

    state_ = ConnectionState::CONNECTED;
    updateActivity();
    return true;
}

bool Connection::accept(std::shared_ptr<TLSContext> tlsContext) {
    std::lock_guard<std::mutex> lock(mutex_);

    state_ = ConnectionState::CONNECTING;

    tlsConnection_ = std::make_shared<TLSConnection>(tlsContext, socket_);
    if (!tlsConnection_->accept()) {
        state_ = ConnectionState::ERROR;
        return false;
    }

    state_ = ConnectionState::CONNECTED;
    updateActivity();
    return true;
}

int Connection::send(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != ConnectionState::CONNECTED) {
        return -1;
    }

    state_ = ConnectionState::SENDING;
    int result = tlsConnection_->write(data);
    state_ = ConnectionState::CONNECTED;
    updateActivity();

    return result;
}

std::vector<uint8_t> Connection::receive(size_t maxLength) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != ConnectionState::CONNECTED) {
        return std::vector<uint8_t>();
    }

    state_ = ConnectionState::RECEIVING;
    std::vector<uint8_t> result = tlsConnection_->read(maxLength);
    state_ = ConnectionState::CONNECTED;
    updateActivity();

    return result;
}

std::shared_ptr<Response> Connection::sendRequest(const Request& request) {
    std::vector<uint8_t> data = request.serialize();
    if (send(data) < 0) {
        return nullptr;
    }

    return receiveResponse();
}

std::shared_ptr<Request> Connection::receiveRequest() {
    std::vector<uint8_t> buffer;
    const size_t chunkSize = 4096;
    bool headerComplete = false;
    size_t contentLength = 0;
    size_t headerEndPos = 0;

    while (!headerComplete) {
        std::vector<uint8_t> chunk = receive(chunkSize);
        if (chunk.empty()) {
            if (buffer.empty()) {
                return nullptr;
            }
            break;
        }

        buffer.insert(buffer.end(), chunk.begin(), chunk.end());

        std::string bufferStr(buffer.begin(), buffer.end());
        size_t pos = bufferStr.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headerComplete = true;
            headerEndPos = pos + 4;

            size_t clPos = bufferStr.find("Content-Length:");
            if (clPos != std::string::npos && clPos < pos) {
                size_t clStart = clPos + 15;
                size_t clEnd = bufferStr.find("\r\n", clStart);
                std::string clStr = bufferStr.substr(clStart, clEnd - clStart);
                clStr.erase(0, clStr.find_first_not_of(" \t"));
                contentLength = std::stoull(clStr);
            }
        }
    }

    while (buffer.size() < headerEndPos + contentLength) {
        std::vector<uint8_t> chunk = receive(chunkSize);
        if (chunk.empty()) {
            break;
        }
        buffer.insert(buffer.end(), chunk.begin(), chunk.end());
    }

    return Request::parse(buffer);
}

void Connection::sendResponse(const Response& response) {
    std::vector<uint8_t> data = response.serialize();
    send(data);
}

std::shared_ptr<Response> Connection::receiveResponse() {
    std::vector<uint8_t> buffer;
    const size_t chunkSize = 4096;
    bool headerComplete = false;
    size_t contentLength = 0;
    size_t headerEndPos = 0;
    bool chunked = false;

    while (!headerComplete) {
        std::vector<uint8_t> chunk = receive(chunkSize);
        if (chunk.empty()) {
            if (buffer.empty()) {
                return nullptr;
            }
            break;
        }

        buffer.insert(buffer.end(), chunk.begin(), chunk.end());

        std::string bufferStr(buffer.begin(), buffer.end());
        size_t pos = bufferStr.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headerComplete = true;
            headerEndPos = pos + 4;

            size_t clPos = bufferStr.find("Content-Length:");
            if (clPos != std::string::npos && clPos < pos) {
                size_t clStart = clPos + 15;
                size_t clEnd = bufferStr.find("\r\n", clStart);
                std::string clStr = bufferStr.substr(clStart, clEnd - clStart);
                clStr.erase(0, clStr.find_first_not_of(" \t"));
                contentLength = std::stoull(clStr);
            }

            size_t tePos = bufferStr.find("Transfer-Encoding:");
            if (tePos != std::string::npos && tePos < pos) {
                size_t teStart = tePos + 18;
                size_t teEnd = bufferStr.find("\r\n", teStart);
                std::string teStr = bufferStr.substr(teStart, teEnd - teStart);
                teStr.erase(0, teStr.find_first_not_of(" \t"));
                if (teStr.find("chunked") != std::string::npos) {
                    chunked = true;
                }
            }
        }
    }

    if (chunked) {
        while (true) {
            std::string bufferStr(buffer.begin() + headerEndPos, buffer.end());
            if (bufferStr.find("0\r\n\r\n") != std::string::npos) {
                break;
            }

            std::vector<uint8_t> chunk = receive(chunkSize);
            if (chunk.empty()) {
                break;
            }
            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
        }
    } else {
        while (buffer.size() < headerEndPos + contentLength) {
            std::vector<uint8_t> chunk = receive(chunkSize);
            if (chunk.empty()) {
                break;
            }
            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
        }
    }

    return Response::parse(buffer);
}

bool Connection::isConnected() const {
    return state_ == ConnectionState::CONNECTED ||
           state_ == ConnectionState::SENDING ||
           state_ == ConnectionState::RECEIVING;
}

ConnectionState Connection::getState() const {
    return state_;
}

void Connection::setState(ConnectionState state) {
    state_ = state;
}

void Connection::setKeepAlive(bool keepAlive) {
    keepAlive_ = keepAlive;
}

bool Connection::getKeepAlive() const {
    return keepAlive_;
}

void Connection::updateActivity() {
    lastActivity_ = std::chrono::steady_clock::now();
}

std::chrono::steady_clock::time_point Connection::getLastActivity() const {
    return lastActivity_;
}

void Connection::close() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == ConnectionState::CLOSED) {
        return;
    }

    state_ = ConnectionState::CLOSING;

    if (tlsConnection_) {
        tlsConnection_->close();
        tlsConnection_ = nullptr;
    }

    if (socket_ >= 0) {
        SocketHelper::closeSocket(socket_);
        socket_ = -1;
    }

    state_ = ConnectionState::CLOSED;
}

int Connection::getSocket() const {
    return socket_;
}

std::string Connection::getRemoteHost() const {
    return remoteHost_;
}

int Connection::getRemotePort() const {
    return remotePort_;
}

ConnectionPool::ConnectionPool(size_t maxConnections, std::chrono::seconds idleTimeout)
    : maxConnections_(maxConnections), idleTimeout_(idleTimeout), running_(true) {
    cleanupThread_ = std::thread(&ConnectionPool::cleanupIdleConnections, this);
}

ConnectionPool::~ConnectionPool() {
    running_ = false;
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    closeAll();
}

std::shared_ptr<Connection> ConnectionPool::acquire(const std::string& host, int port) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& pooled : connections_) {
        if (!pooled.inUse &&
            pooled.connection->getRemoteHost() == host &&
            pooled.connection->getRemotePort() == port &&
            pooled.connection->isConnected()) {
            pooled.inUse = true;
            pooled.lastUsed = std::chrono::steady_clock::now();
            return pooled.connection;
        }
    }

    if (connections_.size() >= maxConnections_) {
        return nullptr;
    }

    auto connection = std::make_shared<Connection>(host, port);
    connections_.push_back({connection, std::chrono::steady_clock::now(), true});

    return connection;
}

void ConnectionPool::release(std::shared_ptr<Connection> connection) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& pooled : connections_) {
        if (pooled.connection == connection) {
            pooled.inUse = false;
            pooled.lastUsed = std::chrono::steady_clock::now();
            break;
        }
    }
}

void ConnectionPool::closeAll() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& pooled : connections_) {
        pooled.connection->close();
    }
    connections_.clear();
}

size_t ConnectionPool::getActiveCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& pooled : connections_) {
        if (pooled.inUse) {
            count++;
        }
    }
    return count;
}

size_t ConnectionPool::getTotalCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

void ConnectionPool::cleanupIdleConnections() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();

        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [&](const PooledConnection& pooled) {
                    if (!pooled.inUse) {
                        auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                            now - pooled.lastUsed);
                        if (idle > idleTimeout_) {
                            pooled.connection->close();
                            return true;
                        }
                    }
                    return false;
                }),
            connections_.end()
        );
    }
}

int SocketHelper::createSocket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return -1;
    }
    return sock;
}

bool SocketHelper::setNonBlocking(int socket) {
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(socket, F_SETFL, flags | O_NONBLOCK) >= 0;
}

bool SocketHelper::setBlocking(int socket) {
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(socket, F_SETFL, flags & ~O_NONBLOCK) >= 0;
}

bool SocketHelper::setReuseAddr(int socket) {
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) >= 0;
}

bool SocketHelper::setKeepAlive(int socket, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) >= 0;
}

bool SocketHelper::setNoDelay(int socket, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) >= 0;
}

bool SocketHelper::setTimeout(int socket, int timeoutMs) {
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    bool recvOk = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) >= 0;
    bool sendOk = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) >= 0;

    return recvOk && sendOk;
}

bool SocketHelper::bind(int socket, const std::string& address, int port) {
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (address.empty() || address == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
            std::cerr << "Invalid address: " << address << std::endl;
            return false;
        }
    }

    if (::bind(socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return false;
    }

    return true;
}

bool SocketHelper::listen(int socket, int backlog) {
    if (::listen(socket, backlog) < 0) {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

int SocketHelper::accept(int socket, std::string& clientAddr, int& clientPort) {
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);

    int clientSocket = ::accept(socket, (struct sockaddr*)&addr, &addrLen);
    if (clientSocket < 0) {
        return -1;
    }

    char addrStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, addrStr, INET_ADDRSTRLEN);
    clientAddr = addrStr;
    clientPort = ntohs(addr.sin_port);

    return clientSocket;
}

bool SocketHelper::connect(int socket, const std::string& host, int port) {
    std::string ipAddr = getHostByName(host);
    if (ipAddr.empty()) {
        std::cerr << "Failed to resolve host: " << host << std::endl;
        return false;
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ipAddr.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << ipAddr << std::endl;
        return false;
    }

    if (::connect(socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Connect failed: " << strerror(errno) << std::endl;
        return false;
    }

    return true;
}

bool SocketHelper::isReadable(int socket, int timeoutMs) {
    struct pollfd pfd;
    pfd.fd = socket;
    pfd.events = POLLIN;

    int result = poll(&pfd, 1, timeoutMs);
    return result > 0 && (pfd.revents & POLLIN);
}

bool SocketHelper::isWritable(int socket, int timeoutMs) {
    struct pollfd pfd;
    pfd.fd = socket;
    pfd.events = POLLOUT;

    int result = poll(&pfd, 1, timeoutMs);
    return result > 0 && (pfd.revents & POLLOUT);
}

std::string SocketHelper::getHostByName(const std::string& hostname) {
    struct addrinfo hints, *result;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        return "";
    }

    char ipStr[INET_ADDRSTRLEN];
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);

    freeaddrinfo(result);
    return std::string(ipStr);
}

void SocketHelper::closeSocket(int socket) {
    if (socket >= 0) {
        ::close(socket);
    }
}

}
