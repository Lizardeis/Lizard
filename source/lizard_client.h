#ifndef LIZARD_CLIENT_H
#define LIZARD_CLIENT_H

#include "lizard_protocol.h"
#include "lizard_connection.h"
#include "lizard_tls.h"
#include <memory>
#include <chrono>

namespace lizard {

struct ClientOptions {
    std::chrono::seconds timeout;
    bool followRedirects;
    size_t maxRedirects;
    bool verifySSL;
    std::string userAgent;
    bool keepAlive;
    CompressionType acceptEncoding;

    ClientOptions()
        : timeout(std::chrono::seconds(30)),
          followRedirects(true),
          maxRedirects(5),
          verifySSL(true),
          userAgent("LizardClient/1.0"),
          keepAlive(true),
          acceptEncoding(CompressionType::GZIP) {}
};

class Client {
private:
    std::shared_ptr<TLSContext> tlsContext_;
    std::shared_ptr<ConnectionPool> connectionPool_;
    ClientOptions options_;

    std::shared_ptr<Response> executeRequest(
        std::shared_ptr<Connection> connection,
        const Request& request
    );

    std::shared_ptr<Response> handleRedirect(
        const Response& response,
        const URI& originalUri,
        size_t redirectCount
    );

public:
    Client();
    Client(const ClientOptions& options);
    ~Client();

    void setOptions(const ClientOptions& options);
    ClientOptions getOptions() const;

    std::shared_ptr<Response> get(const std::string& url);
    std::shared_ptr<Response> post(const std::string& url, const std::string& body);
    std::shared_ptr<Response> put(const std::string& url, const std::string& body);
    std::shared_ptr<Response> del(const std::string& url);
    std::shared_ptr<Response> patch(const std::string& url, const std::string& body);
    std::shared_ptr<Response> head(const std::string& url);
    std::shared_ptr<Response> options(const std::string& url);

    std::shared_ptr<Response> request(const Request& request);

    std::shared_ptr<Response> get(const URI& uri);
    std::shared_ptr<Response> post(const URI& uri, const std::string& body);
    std::shared_ptr<Response> put(const URI& uri, const std::string& body);
    std::shared_ptr<Response> del(const URI& uri);
    std::shared_ptr<Response> patch(const URI& uri, const std::string& body);
    std::shared_ptr<Response> head(const URI& uri);
    std::shared_ptr<Response> options(const URI& uri);

    bool loadCertificate(const std::string& certFile);
    bool loadPrivateKey(const std::string& keyFile);
    bool loadCAFile(const std::string& caFile);
    void setVerifySSL(bool verify);
};

class RequestBuilder {
private:
    Request request_;

public:
    RequestBuilder(Method method, const std::string& url);
    RequestBuilder(Method method, const URI& uri);

    RequestBuilder& header(const std::string& key, const std::string& value);
    RequestBuilder& body(const std::string& body);
    RequestBuilder& body(const std::vector<uint8_t>& body);
    RequestBuilder& json(const std::string& json);
    RequestBuilder& form(const std::map<std::string, std::string>& data);
    RequestBuilder& cookie(const Cookie& cookie);
    RequestBuilder& userAgent(const std::string& userAgent);
    RequestBuilder& contentType(const std::string& contentType);
    RequestBuilder& authorization(const std::string& auth);
    RequestBuilder& bearerToken(const std::string& token);
    RequestBuilder& basicAuth(const std::string& username, const std::string& password);

    Request build() const;
};

}

#endif
