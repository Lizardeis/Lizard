#ifndef LIZARD_SERVER_H
#define LIZARD_SERVER_H

#include "lizard_protocol.h"
#include "lizard_connection.h"
#include "lizard_tls.h"
#include <functional>
#include <map>
#include <regex>
#include <thread>
#include <atomic>
#include <vector>

namespace lizard {

class RouteContext {
private:
    std::shared_ptr<Request> request_;
    std::shared_ptr<Response> response_;
    std::map<std::string, std::string> params_;

public:
    RouteContext(std::shared_ptr<Request> request);

    std::shared_ptr<Request> request() const;
    std::shared_ptr<Response> response() const;

    void setParam(const std::string& key, const std::string& value);
    std::string getParam(const std::string& key) const;

    void json(const std::string& body, StatusCode status = StatusCode::OK);
    void text(const std::string& body, StatusCode status = StatusCode::OK);
    void html(const std::string& body, StatusCode status = StatusCode::OK);
    void redirect(const std::string& location, StatusCode status = StatusCode::FOUND);
    void error(StatusCode status, const std::string& message = "");

    void setCookie(const Cookie& cookie);
    Cookie getCookie(const std::string& name) const;
};

using RouteHandler = std::function<void(RouteContext&)>;
using Middleware = std::function<bool(RouteContext&)>;

struct Route {
    Method method;
    std::string pattern;
    std::regex regex;
    std::vector<std::string> paramNames;
    RouteHandler handler;
};

class Router {
private:
    std::vector<Route> routes_;
    std::vector<Middleware> middlewares_;

    bool matchRoute(const Route& route, const std::string& path,
                   std::map<std::string, std::string>& params);

public:
    Router();

    void use(Middleware middleware);

    void get(const std::string& pattern, RouteHandler handler);
    void post(const std::string& pattern, RouteHandler handler);
    void put(const std::string& pattern, RouteHandler handler);
    void del(const std::string& pattern, RouteHandler handler);
    void patch(const std::string& pattern, RouteHandler handler);
    void head(const std::string& pattern, RouteHandler handler);
    void options(const std::string& pattern, RouteHandler handler);

    void route(Method method, const std::string& pattern, RouteHandler handler);

    bool handle(std::shared_ptr<Request> request, std::shared_ptr<Connection> connection);
};

class Server {
private:
    int serverSocket_;
    std::shared_ptr<TLSContext> tlsContext_;
    std::shared_ptr<Router> router_;
    std::atomic<bool> running_;
    std::vector<std::thread> workerThreads_;
    size_t numThreads_;
    std::string bindAddress_;
    int bindPort_;

    void acceptLoop();
    void handleClient(std::shared_ptr<Connection> connection);

public:
    Server(size_t numThreads = 4);
    ~Server();

    void setRouter(std::shared_ptr<Router> router);
    std::shared_ptr<Router> getRouter() const;

    bool loadCertificate(const std::string& certFile, const std::string& keyFile);
    bool generateSelfSignedCertificate(const std::string& commonName);

    bool start(const std::string& address, int port);
    void stop();

    bool isRunning() const;
};

Middleware loggerMiddleware();
Middleware corsMiddleware(const std::string& origin = "*");
Middleware rateLimitMiddleware(size_t maxRequests, std::chrono::seconds window);

}

#endif
