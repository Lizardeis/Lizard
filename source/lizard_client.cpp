#include "lizard_client.h"
#include <iostream>
#include <sstream>
#include <cstring>

namespace lizard {

Client::Client()
    : tlsContext_(std::make_shared<TLSContext>(false)),
      connectionPool_(std::make_shared<ConnectionPool>()) {
    tlsContext_->setVerifyMode(options_.verifySSL, false);
}

Client::Client(const ClientOptions& options)
    : tlsContext_(std::make_shared<TLSContext>(false)),
      connectionPool_(std::make_shared<ConnectionPool>()),
      options_(options) {
    tlsContext_->setVerifyMode(options_.verifySSL, false);
}

Client::~Client() {
    connectionPool_->closeAll();
}

void Client::setOptions(const ClientOptions& options) {
    options_ = options;
    tlsContext_->setVerifyMode(options_.verifySSL, false);
}

ClientOptions Client::getOptions() const {
    return options_;
}

std::shared_ptr<Response> Client::executeRequest(
    std::shared_ptr<Connection> connection,
    const Request& request
) {
    if (!connection->isConnected()) {
        if (!connection->connect(tlsContext_)) {
            std::cerr << "Failed to connect" << std::endl;
            return nullptr;
        }
    }

    return connection->sendRequest(request);
}

std::shared_ptr<Response> Client::handleRedirect(
    const Response& response,
    const URI& originalUri,
    size_t redirectCount
) {
    if (redirectCount >= options_.maxRedirects) {
        std::cerr << "Max redirects exceeded" << std::endl;
        return nullptr;
    }

    StatusCode status = response.getStatus();
    if (status != StatusCode::MOVED_PERMANENTLY &&
        status != StatusCode::FOUND &&
        status != StatusCode::SEE_OTHER &&
        status != StatusCode::TEMPORARY_REDIRECT &&
        status != StatusCode::PERMANENT_REDIRECT) {
        return nullptr;
    }

    std::string location = response.headers().get("Location");
    if (location.empty()) {
        return nullptr;
    }

    URI redirectUri;
    if (location[0] == '/') {
        redirectUri = originalUri;
        redirectUri.path = location;
    } else {
        redirectUri = parseURI(location);
    }

    Request redirectRequest(Method::GET, redirectUri);
    redirectRequest.headers().set("User-Agent", options_.userAgent);

    auto connection = connectionPool_->acquire(redirectUri.host, redirectUri.port);
    if (!connection) {
        return nullptr;
    }

    auto redirectResponse = executeRequest(connection, redirectRequest);
    connectionPool_->release(connection);

    if (redirectResponse && options_.followRedirects) {
        auto nextRedirect = handleRedirect(*redirectResponse, redirectUri, redirectCount + 1);
        if (nextRedirect) {
            return nextRedirect;
        }
    }

    return redirectResponse;
}

std::shared_ptr<Response> Client::request(const Request& req) {
    Request request = req;

    if (!request.headers().has("User-Agent")) {
        request.headers().set("User-Agent", options_.userAgent);
    }

    if (!request.headers().has("Accept-Encoding") && options_.acceptEncoding != CompressionType::NONE) {
        if (options_.acceptEncoding == CompressionType::GZIP) {
            request.headers().set("Accept-Encoding", "gzip");
        } else if (options_.acceptEncoding == CompressionType::DEFLATE) {
            request.headers().set("Accept-Encoding", "deflate");
        }
    }

    if (options_.keepAlive) {
        request.headers().set("Connection", "keep-alive");
    } else {
        request.headers().set("Connection", "close");
    }

    URI uri = request.getURI();
    auto connection = connectionPool_->acquire(uri.host, uri.port);
    if (!connection) {
        std::cerr << "Failed to acquire connection" << std::endl;
        return nullptr;
    }

    auto response = executeRequest(connection, request);
    connectionPool_->release(connection);

    if (response && options_.followRedirects) {
        auto redirect = handleRedirect(*response, uri, 0);
        if (redirect) {
            return redirect;
        }
    }

    return response;
}

std::shared_ptr<Response> Client::get(const std::string& url) {
    URI uri = parseURI(url);
    return get(uri);
}

std::shared_ptr<Response> Client::post(const std::string& url, const std::string& body) {
    URI uri = parseURI(url);
    return post(uri, body);
}

std::shared_ptr<Response> Client::put(const std::string& url, const std::string& body) {
    URI uri = parseURI(url);
    return put(uri, body);
}

std::shared_ptr<Response> Client::del(const std::string& url) {
    URI uri = parseURI(url);
    return del(uri);
}

std::shared_ptr<Response> Client::patch(const std::string& url, const std::string& body) {
    URI uri = parseURI(url);
    return patch(uri, body);
}

std::shared_ptr<Response> Client::head(const std::string& url) {
    URI uri = parseURI(url);
    return head(uri);
}

std::shared_ptr<Response> Client::options(const std::string& url) {
    URI uri = parseURI(url);
    return options(uri);
}

std::shared_ptr<Response> Client::get(const URI& uri) {
    Request request(Method::GET, uri);
    return this->request(request);
}

std::shared_ptr<Response> Client::post(const URI& uri, const std::string& body) {
    Request request(Method::POST, uri);
    request.setBody(body);
    if (!request.headers().has("Content-Type")) {
        request.headers().set("Content-Type", "application/x-www-form-urlencoded");
    }
    return this->request(request);
}

std::shared_ptr<Response> Client::put(const URI& uri, const std::string& body) {
    Request request(Method::PUT, uri);
    request.setBody(body);
    if (!request.headers().has("Content-Type")) {
        request.headers().set("Content-Type", "application/x-www-form-urlencoded");
    }
    return this->request(request);
}

std::shared_ptr<Response> Client::del(const URI& uri) {
    Request request(Method::DELETE, uri);
    return this->request(request);
}

std::shared_ptr<Response> Client::patch(const URI& uri, const std::string& body) {
    Request request(Method::PATCH, uri);
    request.setBody(body);
    if (!request.headers().has("Content-Type")) {
        request.headers().set("Content-Type", "application/x-www-form-urlencoded");
    }
    return this->request(request);
}

std::shared_ptr<Response> Client::head(const URI& uri) {
    Request request(Method::HEAD, uri);
    return this->request(request);
}

std::shared_ptr<Response> Client::options(const URI& uri) {
    Request request(Method::OPTIONS, uri);
    return this->request(request);
}

bool Client::loadCertificate(const std::string& certFile) {
    return tlsContext_->loadCertificate(certFile);
}

bool Client::loadPrivateKey(const std::string& keyFile) {
    return tlsContext_->loadPrivateKey(keyFile);
}

bool Client::loadCAFile(const std::string& caFile) {
    return tlsContext_->loadCAFile(caFile);
}

void Client::setVerifySSL(bool verify) {
    options_.verifySSL = verify;
    tlsContext_->setVerifyMode(verify, false);
}

RequestBuilder::RequestBuilder(Method method, const std::string& url)
    : request_(method, parseURI(url)) {}

RequestBuilder::RequestBuilder(Method method, const URI& uri)
    : request_(method, uri) {}

RequestBuilder& RequestBuilder::header(const std::string& key, const std::string& value) {
    request_.headers().set(key, value);
    return *this;
}

RequestBuilder& RequestBuilder::body(const std::string& body) {
    request_.setBody(body);
    return *this;
}

RequestBuilder& RequestBuilder::body(const std::vector<uint8_t>& body) {
    request_.setBody(body);
    return *this;
}

RequestBuilder& RequestBuilder::json(const std::string& json) {
    request_.setBody(json);
    request_.headers().set("Content-Type", "application/json");
    return *this;
}

RequestBuilder& RequestBuilder::form(const std::map<std::string, std::string>& data) {
    std::stringstream ss;
    bool first = true;
    for (const auto& pair : data) {
        if (!first) {
            ss << "&";
        }
        ss << pair.first << "=" << pair.second;
        first = false;
    }
    request_.setBody(ss.str());
    request_.headers().set("Content-Type", "application/x-www-form-urlencoded");
    return *this;
}

RequestBuilder& RequestBuilder::cookie(const Cookie& cookie) {
    request_.addCookie(cookie);
    return *this;
}

RequestBuilder& RequestBuilder::userAgent(const std::string& userAgent) {
    request_.headers().set("User-Agent", userAgent);
    return *this;
}

RequestBuilder& RequestBuilder::contentType(const std::string& contentType) {
    request_.headers().set("Content-Type", contentType);
    return *this;
}

RequestBuilder& RequestBuilder::authorization(const std::string& auth) {
    request_.headers().set("Authorization", auth);
    return *this;
}

RequestBuilder& RequestBuilder::bearerToken(const std::string& token) {
    request_.headers().set("Authorization", "Bearer " + token);
    return *this;
}

RequestBuilder& RequestBuilder::basicAuth(const std::string& username, const std::string& password) {
    std::string credentials = username + ":" + password;
    std::string encoded;

    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (char c : credentials) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while (i++ < 3)
            encoded += '=';
    }

    request_.headers().set("Authorization", "Basic " + encoded);
    return *this;
}

Request RequestBuilder::build() const {
    return request_;
}

}
