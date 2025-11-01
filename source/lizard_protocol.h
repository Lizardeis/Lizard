#ifndef LIZARD_PROTOCOL_H
#define LIZARD_PROTOCOL_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <cstdint>

namespace lizard {

enum class Protocol {
    LIZARD,
    LIZARD_LOCALHOST
};

enum class Method {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE
};

enum class Version {
    LIZARD_1_0,
    LIZARD_1_1,
    LIZARD_2_0
};

enum class StatusCode {
    CONTINUE = 100,
    SWITCHING_PROTOCOLS = 101,
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NO_CONTENT = 204,
    PARTIAL_CONTENT = 206,
    MOVED_PERMANENTLY = 301,
    FOUND = 302,
    SEE_OTHER = 303,
    NOT_MODIFIED = 304,
    TEMPORARY_REDIRECT = 307,
    PERMANENT_REDIRECT = 308,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    REQUEST_TIMEOUT = 408,
    CONFLICT = 409,
    GONE = 410,
    LENGTH_REQUIRED = 411,
    PAYLOAD_TOO_LARGE = 413,
    URI_TOO_LONG = 414,
    UNSUPPORTED_MEDIA_TYPE = 415,
    RANGE_NOT_SATISFIABLE = 416,
    EXPECTATION_FAILED = 417,
    IM_A_TEAPOT = 418,
    TOO_MANY_REQUESTS = 429,
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503,
    GATEWAY_TIMEOUT = 504,
    VERSION_NOT_SUPPORTED = 505
};

enum class ConnectionState {
    IDLE,
    CONNECTING,
    CONNECTED,
    SENDING,
    RECEIVING,
    CLOSING,
    CLOSED,
    ERROR
};

enum class CompressionType {
    NONE,
    GZIP,
    DEFLATE,
    BROTLI
};

struct URI {
    Protocol protocol;
    std::string scheme;
    std::string host;
    int port;
    std::string path;
    std::string query;
    std::string fragment;
    std::map<std::string, std::string> query_params;

    std::string toString() const;
};

class Headers {
private:
    std::map<std::string, std::vector<std::string>> headers_;

public:
    void add(const std::string& key, const std::string& value);
    void set(const std::string& key, const std::string& value);
    std::string get(const std::string& key) const;
    std::vector<std::string> getAll(const std::string& key) const;
    bool has(const std::string& key) const;
    void remove(const std::string& key);
    std::map<std::string, std::vector<std::string>> getAll() const;
    std::string serialize() const;
};

class Cookie {
public:
    std::string name;
    std::string value;
    std::string domain;
    std::string path;
    int64_t expires;
    int maxAge;
    bool secure;
    bool httpOnly;
    std::string sameSite;

    Cookie(const std::string& name, const std::string& value);
    std::string serialize() const;
    static Cookie parse(const std::string& cookieStr);
};

class Request {
private:
    Method method_;
    URI uri_;
    Version version_;
    Headers headers_;
    std::vector<uint8_t> body_;
    std::vector<Cookie> cookies_;

public:
    Request(Method method, const URI& uri, Version version = Version::LIZARD_1_1);

    void setMethod(Method method);
    Method getMethod() const;

    void setURI(const URI& uri);
    URI getURI() const;

    void setVersion(Version version);
    Version getVersion() const;

    Headers& headers();
    const Headers& headers() const;

    void setBody(const std::vector<uint8_t>& body);
    void setBody(const std::string& body);
    std::vector<uint8_t> getBody() const;
    std::string getBodyAsString() const;

    void addCookie(const Cookie& cookie);
    std::vector<Cookie> getCookies() const;

    std::vector<uint8_t> serialize() const;
    static std::shared_ptr<Request> parse(const std::vector<uint8_t>& data);
};

class Response {
private:
    Version version_;
    StatusCode status_;
    std::string reasonPhrase_;
    Headers headers_;
    std::vector<uint8_t> body_;
    std::vector<Cookie> cookies_;

public:
    Response(StatusCode status, Version version = Version::LIZARD_1_1);

    void setVersion(Version version);
    Version getVersion() const;

    void setStatus(StatusCode status);
    StatusCode getStatus() const;

    void setReasonPhrase(const std::string& phrase);
    std::string getReasonPhrase() const;

    Headers& headers();
    const Headers& headers() const;

    void setBody(const std::vector<uint8_t>& body);
    void setBody(const std::string& body);
    std::vector<uint8_t> getBody() const;
    std::string getBodyAsString() const;

    void addCookie(const Cookie& cookie);
    std::vector<Cookie> getCookies() const;

    std::vector<uint8_t> serialize() const;
    static std::shared_ptr<Response> parse(const std::vector<uint8_t>& data);
};

std::string methodToString(Method method);
Method stringToMethod(const std::string& str);

std::string versionToString(Version version);
Version stringToVersion(const std::string& str);

std::string statusCodeToString(StatusCode code);
int statusCodeToInt(StatusCode code);

URI parseURI(const std::string& uriStr);

}

#endif
