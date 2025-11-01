#ifndef LIZARD_CONNECTION_H
#define LIZARD_CONNECTION_H

#include "lizard_protocol.h"
#include "lizard_tls.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <memory>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace lizard {

class Connection {
private:
    int socket_;
    std::shared_ptr<TLSConnection> tlsConnection_;
    ConnectionState state_;
    std::string remoteHost_;
    int remotePort_;
    bool keepAlive_;
    std::chrono::steady_clock::time_point lastActivity_;
    std::mutex mutex_;

public:
    Connection(int socket);
    Connection(const std::string& host, int port);
    ~Connection();

    bool connect(std::shared_ptr<TLSContext> tlsContext);
    bool accept(std::shared_ptr<TLSContext> tlsContext);

    int send(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receive(size_t maxLength);

    std::shared_ptr<Response> sendRequest(const Request& request);
    std::shared_ptr<Request> receiveRequest();

    void sendResponse(const Response& response);
    std::shared_ptr<Response> receiveResponse();

    bool isConnected() const;
    ConnectionState getState() const;
    void setState(ConnectionState state);

    void setKeepAlive(bool keepAlive);
    bool getKeepAlive() const;

    void updateActivity();
    std::chrono::steady_clock::time_point getLastActivity() const;

    void close();

    int getSocket() const;
    std::string getRemoteHost() const;
    int getRemotePort() const;
};

class ConnectionPool {
private:
    struct PooledConnection {
        std::shared_ptr<Connection> connection;
        std::chrono::steady_clock::time_point lastUsed;
        bool inUse;
    };

    std::vector<PooledConnection> connections_;
    std::mutex mutex_;
    size_t maxConnections_;
    std::chrono::seconds idleTimeout_;
    std::atomic<bool> running_;
    std::thread cleanupThread_;

    void cleanupIdleConnections();

public:
    ConnectionPool(size_t maxConnections = 100, std::chrono::seconds idleTimeout = std::chrono::seconds(60));
    ~ConnectionPool();

    std::shared_ptr<Connection> acquire(const std::string& host, int port);
    void release(std::shared_ptr<Connection> connection);

    void closeAll();
    size_t getActiveCount() const;
    size_t getTotalCount() const;
};

class SocketHelper {
public:
    static int createSocket();
    static bool setNonBlocking(int socket);
    static bool setBlocking(int socket);
    static bool setReuseAddr(int socket);
    static bool setKeepAlive(int socket, bool enable);
    static bool setNoDelay(int socket, bool enable);
    static bool setTimeout(int socket, int timeoutMs);

    static bool bind(int socket, const std::string& address, int port);
    static bool listen(int socket, int backlog = 128);
    static int accept(int socket, std::string& clientAddr, int& clientPort);

    static bool connect(int socket, const std::string& host, int port);
    static bool isReadable(int socket, int timeoutMs = 0);
    static bool isWritable(int socket, int timeoutMs = 0);

    static std::string getHostByName(const std::string& hostname);
    static void closeSocket(int socket);
};

}

#endif
