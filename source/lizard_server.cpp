#include "lizard_server.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <unordered_map>

namespace lizard {

RouteContext::RouteContext(std::shared_ptr<Request> request)
    : request_(request), response_(std::make_shared<Response>(StatusCode::OK)) {}

std::shared_ptr<Request> RouteContext::request() const {
    return request_;
}

std::shared_ptr<Response> RouteContext::response() const {
    return response_;
}

void RouteContext::setParam(const std::string& key, const std::string& value) {
    params_[key] = value;
}

std::string RouteContext::getParam(const std::string& key) const {
    auto it = params_.find(key);
    if (it != params_.end()) {
        return it->second;
    }
    return "";
}

void RouteContext::json(const std::string& body, StatusCode status) {
    response_->setStatus(status);
    response_->headers().set("Content-Type", "application/json");
    response_->setBody(body);
}

void RouteContext::text(const std::string& body, StatusCode status) {
    response_->setStatus(status);
    response_->headers().set("Content-Type", "text/plain");
    response_->setBody(body);
}

void RouteContext::html(const std::string& body, StatusCode status) {
    response_->setStatus(status);
    response_->headers().set("Content-Type", "text/html");
    response_->setBody(body);
}

void RouteContext::redirect(const std::string& location, StatusCode status) {
    response_->setStatus(status);
    response_->headers().set("Location", location);
}

void RouteContext::error(StatusCode status, const std::string& message) {
    response_->setStatus(status);
    response_->headers().set("Content-Type", "text/plain");

    std::string errorMsg = message;
    if (errorMsg.empty()) {
        errorMsg = statusCodeToString(status);
    }

    response_->setBody(errorMsg);
}

void RouteContext::setCookie(const Cookie& cookie) {
    response_->addCookie(cookie);
}

Cookie RouteContext::getCookie(const std::string& name) const {
    auto cookies = request_->getCookies();
    for (const auto& cookie : cookies) {
        if (cookie.name == name) {
            return cookie;
        }
    }
    return Cookie("", "");
}

Router::Router() {}

void Router::use(Middleware middleware) {
    middlewares_.push_back(middleware);
}

void Router::get(const std::string& pattern, RouteHandler handler) {
    route(Method::GET, pattern, handler);
}

void Router::post(const std::string& pattern, RouteHandler handler) {
    route(Method::POST, pattern, handler);
}

void Router::put(const std::string& pattern, RouteHandler handler) {
    route(Method::PUT, pattern, handler);
}

void Router::del(const std::string& pattern, RouteHandler handler) {
    route(Method::DELETE, pattern, handler);
}

void Router::patch(const std::string& pattern, RouteHandler handler) {
    route(Method::PATCH, pattern, handler);
}

void Router::head(const std::string& pattern, RouteHandler handler) {
    route(Method::HEAD, pattern, handler);
}

void Router::options(const std::string& pattern, RouteHandler handler) {
    route(Method::OPTIONS, pattern, handler);
}

void Router::route(Method method, const std::string& pattern, RouteHandler handler) {
    Route route;
    route.method = method;
    route.pattern = pattern;
    route.handler = handler;

    std::string regexPattern = pattern;
    std::regex paramRegex(":([a-zA-Z_][a-zA-Z0-9_]*)");
    std::smatch match;
    std::string::const_iterator searchStart(regexPattern.cbegin());

    while (std::regex_search(searchStart, regexPattern.cend(), match, paramRegex)) {
        route.paramNames.push_back(match[1].str());
        searchStart = match.suffix().first;
    }

    regexPattern = std::regex_replace(regexPattern, paramRegex, "([^/]+)");
    regexPattern = "^" + regexPattern + "$";
    route.regex = std::regex(regexPattern);

    routes_.push_back(route);
}

bool Router::matchRoute(const Route& route, const std::string& path,
                       std::map<std::string, std::string>& params) {
    std::smatch match;
    if (std::regex_match(path, match, route.regex)) {
        for (size_t i = 0; i < route.paramNames.size() && i < match.size() - 1; ++i) {
            params[route.paramNames[i]] = match[i + 1].str();
        }
        return true;
    }
    return false;
}

bool Router::handle(std::shared_ptr<Request> request, std::shared_ptr<Connection> connection) {
    RouteContext context(request);

    for (const auto& middleware : middlewares_) {
        if (!middleware(context)) {
            connection->sendResponse(*context.response());
            return true;
        }
    }

    std::string path = request->getURI().path;
    Method method = request->getMethod();

    for (const auto& route : routes_) {
        if (route.method == method) {
            std::map<std::string, std::string> params;
            if (matchRoute(route, path, params)) {
                for (const auto& pair : params) {
                    context.setParam(pair.first, pair.second);
                }
                route.handler(context);
                connection->sendResponse(*context.response());
                return true;
            }
        }
    }

    context.error(StatusCode::NOT_FOUND, "Route not found");
    connection->sendResponse(*context.response());
    return false;
}

Server::Server(size_t numThreads)
    : serverSocket_(-1), router_(std::make_shared<Router>()),
      running_(false), numThreads_(numThreads),
      bindAddress_("0.0.0.0"), bindPort_(0) {

    tlsContext_ = std::make_shared<TLSContext>(true);
}

Server::~Server() {
    stop();
}

void Server::setRouter(std::shared_ptr<Router> router) {
    router_ = router;
}

std::shared_ptr<Router> Server::getRouter() const {
    return router_;
}

bool Server::loadCertificate(const std::string& certFile, const std::string& keyFile) {
    if (!tlsContext_->loadCertificate(certFile)) {
        return false;
    }
    if (!tlsContext_->loadPrivateKey(keyFile)) {
        return false;
    }
    return true;
}

bool Server::generateSelfSignedCertificate(const std::string& commonName) {
    std::string certFile = "server_cert.pem";
    std::string keyFile = "server_key.pem";

    if (!CertificateGenerator::generateSelfSignedCertificate(
            certFile, keyFile, commonName, 365)) {
        return false;
    }

    return loadCertificate(certFile, keyFile);
}

bool Server::start(const std::string& address, int port) {
    if (running_) {
        return false;
    }

    bindAddress_ = address;
    bindPort_ = port;

    serverSocket_ = SocketHelper::createSocket();
    if (serverSocket_ < 0) {
        return false;
    }

    SocketHelper::setReuseAddr(serverSocket_);

    if (!SocketHelper::bind(serverSocket_, address, port)) {
        SocketHelper::closeSocket(serverSocket_);
        return false;
    }

    if (!SocketHelper::listen(serverSocket_, 128)) {
        SocketHelper::closeSocket(serverSocket_);
        return false;
    }

    running_ = true;

    std::cout << "Lizard server started on " << address << ":" << port << std::endl;
    std::cout << "Protocol: lizard://" << address << ":" << port << std::endl;

    for (size_t i = 0; i < numThreads_; ++i) {
        workerThreads_.emplace_back(&Server::acceptLoop, this);
    }

    return true;
}

void Server::stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    if (serverSocket_ >= 0) {
        SocketHelper::closeSocket(serverSocket_);
        serverSocket_ = -1;
    }

    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    workerThreads_.clear();

    std::cout << "Lizard server stopped" << std::endl;
}

bool Server::isRunning() const {
    return running_;
}

void Server::acceptLoop() {
    while (running_) {
        std::string clientAddr;
        int clientPort;

        int clientSocket = SocketHelper::accept(serverSocket_, clientAddr, clientPort);
        if (clientSocket < 0) {
            if (running_) {
                std::cerr << "Accept failed" << std::endl;
            }
            continue;
        }

        auto connection = std::make_shared<Connection>(clientSocket);

        std::thread clientThread(&Server::handleClient, this, connection);
        clientThread.detach();
    }
}

void Server::handleClient(std::shared_ptr<Connection> connection) {
    if (!connection->accept(tlsContext_)) {
        std::cerr << "TLS handshake failed" << std::endl;
        connection->close();
        return;
    }

    while (connection->isConnected()) {
        auto request = connection->receiveRequest();
        if (!request) {
            break;
        }

        router_->handle(request, connection);

        std::string connectionHeader = request->headers().get("Connection");
        std::transform(connectionHeader.begin(), connectionHeader.end(),
                      connectionHeader.begin(), ::tolower);

        if (connectionHeader != "keep-alive") {
            break;
        }
    }

    connection->close();
}

Middleware loggerMiddleware() {
    return [](RouteContext& ctx) {
        auto request = ctx.request();
        auto start = std::chrono::steady_clock::now();

        std::cout << "[" << methodToString(request->getMethod()) << "] "
                  << request->getURI().path;

        if (!request->getURI().query.empty()) {
            std::cout << "?" << request->getURI().query;
        }

        std::cout << std::endl;

        return true;
    };
}

Middleware corsMiddleware(const std::string& origin) {
    return [origin](RouteContext& ctx) {
        auto response = ctx.response();
        response->headers().set("Access-Control-Allow-Origin", origin);
        response->headers().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        response->headers().set("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if (ctx.request()->getMethod() == Method::OPTIONS) {
            ctx.text("", StatusCode::NO_CONTENT);
            return false;
        }

        return true;
    };
}

Middleware rateLimitMiddleware(size_t maxRequests, std::chrono::seconds window) {
    struct ClientInfo {
        size_t requests;
        std::chrono::steady_clock::time_point windowStart;
    };

    auto clientData = std::make_shared<std::unordered_map<std::string, ClientInfo>>();
    auto mutex = std::make_shared<std::mutex>();

    return [clientData, mutex, maxRequests, window](RouteContext& ctx) {
        std::lock_guard<std::mutex> lock(*mutex);

        std::string clientId = ctx.request()->getURI().host;
        auto now = std::chrono::steady_clock::now();

        auto it = clientData->find(clientId);
        if (it == clientData->end()) {
            (*clientData)[clientId] = {1, now};
            return true;
        }

        auto& info = it->second;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.windowStart);

        if (elapsed > window) {
            info.requests = 1;
            info.windowStart = now;
            return true;
        }

        if (info.requests >= maxRequests) {
            ctx.error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
            return false;
        }

        info.requests++;
        return true;
    };
}

}
