#include "lizard_protocol.h"
#include <sstream>
#include <algorithm>
#include <ctime>
#include <iomanip>

namespace lizard {

std::string URI::toString() const {
    std::stringstream ss;
    ss << scheme << "://";

    if (!host.empty()) {
        ss << host;
    }

    if (port > 0 && port != 443) {
        ss << ":" << port;
    }

    if (path.empty()) {
        ss << "/";
    } else {
        ss << path;
    }

    if (!query.empty()) {
        ss << "?" << query;
    }

    if (!fragment.empty()) {
        ss << "#" << fragment;
    }

    return ss.str();
}

void Headers::add(const std::string& key, const std::string& value) {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_[lowerKey].push_back(value);
}

void Headers::set(const std::string& key, const std::string& value) {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_[lowerKey].clear();
    headers_[lowerKey].push_back(value);
}

std::string Headers::get(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    auto it = headers_.find(lowerKey);
    if (it != headers_.end() && !it->second.empty()) {
        return it->second[0];
    }
    return "";
}

std::vector<std::string> Headers::getAll(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    auto it = headers_.find(lowerKey);
    if (it != headers_.end()) {
        return it->second;
    }
    return std::vector<std::string>();
}

bool Headers::has(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    return headers_.find(lowerKey) != headers_.end();
}

void Headers::remove(const std::string& key) {
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_.erase(lowerKey);
}

std::map<std::string, std::vector<std::string>> Headers::getAll() const {
    return headers_;
}

std::string Headers::serialize() const {
    std::stringstream ss;
    for (const auto& pair : headers_) {
        for (const auto& value : pair.second) {
            ss << pair.first << ": " << value << "\r\n";
        }
    }
    return ss.str();
}

Cookie::Cookie(const std::string& name, const std::string& value)
    : name(name), value(value), expires(0), maxAge(-1),
      secure(false), httpOnly(false), path("/") {}

std::string Cookie::serialize() const {
    std::stringstream ss;
    ss << name << "=" << value;

    if (!domain.empty()) {
        ss << "; Domain=" << domain;
    }

    if (!path.empty()) {
        ss << "; Path=" << path;
    }

    if (expires > 0) {
        std::time_t t = expires;
        ss << "; Expires=" << std::put_time(std::gmtime(&t), "%a, %d %b %Y %H:%M:%S GMT");
    }

    if (maxAge >= 0) {
        ss << "; Max-Age=" << maxAge;
    }

    if (secure) {
        ss << "; Secure";
    }

    if (httpOnly) {
        ss << "; HttpOnly";
    }

    if (!sameSite.empty()) {
        ss << "; SameSite=" << sameSite;
    }

    return ss.str();
}

Cookie Cookie::parse(const std::string& cookieStr) {
    size_t pos = cookieStr.find('=');
    if (pos == std::string::npos) {
        return Cookie("", "");
    }

    std::string name = cookieStr.substr(0, pos);
    std::string rest = cookieStr.substr(pos + 1);

    size_t semicolon = rest.find(';');
    std::string value = (semicolon != std::string::npos) ? rest.substr(0, semicolon) : rest;

    Cookie cookie(name, value);

    if (semicolon != std::string::npos) {
        std::string attributes = rest.substr(semicolon + 1);
        std::istringstream iss(attributes);
        std::string attr;

        while (std::getline(iss, attr, ';')) {
            size_t eqPos = attr.find('=');
            std::string attrName = (eqPos != std::string::npos) ? attr.substr(0, eqPos) : attr;
            std::string attrValue = (eqPos != std::string::npos) ? attr.substr(eqPos + 1) : "";

            attrName.erase(0, attrName.find_first_not_of(" \t"));
            attrName.erase(attrName.find_last_not_of(" \t") + 1);

            std::transform(attrName.begin(), attrName.end(), attrName.begin(), ::tolower);

            if (attrName == "domain") {
                cookie.domain = attrValue;
            } else if (attrName == "path") {
                cookie.path = attrValue;
            } else if (attrName == "max-age") {
                cookie.maxAge = std::stoi(attrValue);
            } else if (attrName == "secure") {
                cookie.secure = true;
            } else if (attrName == "httponly") {
                cookie.httpOnly = true;
            } else if (attrName == "samesite") {
                cookie.sameSite = attrValue;
            }
        }
    }

    return cookie;
}

Request::Request(Method method, const URI& uri, Version version)
    : method_(method), uri_(uri), version_(version) {}

void Request::setMethod(Method method) {
    method_ = method;
}

Method Request::getMethod() const {
    return method_;
}

void Request::setURI(const URI& uri) {
    uri_ = uri;
}

URI Request::getURI() const {
    return uri_;
}

void Request::setVersion(Version version) {
    version_ = version;
}

Version Request::getVersion() const {
    return version_;
}

Headers& Request::headers() {
    return headers_;
}

const Headers& Request::headers() const {
    return headers_;
}

void Request::setBody(const std::vector<uint8_t>& body) {
    body_ = body;
}

void Request::setBody(const std::string& body) {
    body_.assign(body.begin(), body.end());
}

std::vector<uint8_t> Request::getBody() const {
    return body_;
}

std::string Request::getBodyAsString() const {
    return std::string(body_.begin(), body_.end());
}

void Request::addCookie(const Cookie& cookie) {
    cookies_.push_back(cookie);
}

std::vector<Cookie> Request::getCookies() const {
    return cookies_;
}

std::vector<uint8_t> Request::serialize() const {
    std::stringstream ss;

    ss << methodToString(method_) << " " << uri_.path;
    if (!uri_.query.empty()) {
        ss << "?" << uri_.query;
    }
    ss << " " << versionToString(version_) << "\r\n";

    ss << "Host: " << uri_.host;
    if (uri_.port > 0 && uri_.port != 443) {
        ss << ":" << uri_.port;
    }
    ss << "\r\n";

    ss << headers_.serialize();

    if (!cookies_.empty()) {
        ss << "Cookie: ";
        for (size_t i = 0; i < cookies_.size(); ++i) {
            if (i > 0) ss << "; ";
            ss << cookies_[i].name << "=" << cookies_[i].value;
        }
        ss << "\r\n";
    }

    if (!body_.empty()) {
        ss << "Content-Length: " << body_.size() << "\r\n";
    }

    ss << "\r\n";

    std::string header = ss.str();
    std::vector<uint8_t> result(header.begin(), header.end());
    result.insert(result.end(), body_.begin(), body_.end());

    return result;
}

std::shared_ptr<Request> Request::parse(const std::vector<uint8_t>& data) {
    std::string str(data.begin(), data.end());
    std::istringstream iss(str);
    std::string line;

    if (!std::getline(iss, line)) {
        return nullptr;
    }

    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::istringstream requestLine(line);
    std::string methodStr, path, versionStr;
    requestLine >> methodStr >> path >> versionStr;

    Method method = stringToMethod(methodStr);
    Version version = stringToVersion(versionStr);

    URI uri;
    uri.path = path;
    size_t queryPos = path.find('?');
    if (queryPos != std::string::npos) {
        uri.path = path.substr(0, queryPos);
        uri.query = path.substr(queryPos + 1);
    }

    auto request = std::make_shared<Request>(method, uri, version);

    while (std::getline(iss, line) && line != "\r" && !line.empty()) {
        if (line.back() == '\r') {
            line.pop_back();
        }

        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);

            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            if (key == "Host") {
                size_t portPos = value.find(':');
                if (portPos != std::string::npos) {
                    uri.host = value.substr(0, portPos);
                    uri.port = std::stoi(value.substr(portPos + 1));
                } else {
                    uri.host = value;
                    uri.port = 443;
                }
                request->setURI(uri);
            } else if (key == "Cookie") {
                std::istringstream cookieStream(value);
                std::string cookiePair;
                while (std::getline(cookieStream, cookiePair, ';')) {
                    cookiePair.erase(0, cookiePair.find_first_not_of(" \t"));
                    size_t eqPos = cookiePair.find('=');
                    if (eqPos != std::string::npos) {
                        std::string name = cookiePair.substr(0, eqPos);
                        std::string val = cookiePair.substr(eqPos + 1);
                        request->addCookie(Cookie(name, val));
                    }
                }
            } else {
                request->headers().add(key, value);
            }
        }
    }

    std::string remaining((std::istreambuf_iterator<char>(iss)), std::istreambuf_iterator<char>());
    if (!remaining.empty()) {
        request->setBody(remaining);
    }

    return request;
}

Response::Response(StatusCode status, Version version)
    : version_(version), status_(status) {
    reasonPhrase_ = statusCodeToString(status);
}

void Response::setVersion(Version version) {
    version_ = version;
}

Version Response::getVersion() const {
    return version_;
}

void Response::setStatus(StatusCode status) {
    status_ = status;
}

StatusCode Response::getStatus() const {
    return status_;
}

void Response::setReasonPhrase(const std::string& phrase) {
    reasonPhrase_ = phrase;
}

std::string Response::getReasonPhrase() const {
    return reasonPhrase_;
}

Headers& Response::headers() {
    return headers_;
}

const Headers& Response::headers() const {
    return headers_;
}

void Response::setBody(const std::vector<uint8_t>& body) {
    body_ = body;
}

void Response::setBody(const std::string& body) {
    body_.assign(body.begin(), body.end());
}

std::vector<uint8_t> Response::getBody() const {
    return body_;
}

std::string Response::getBodyAsString() const {
    return std::string(body_.begin(), body_.end());
}

void Response::addCookie(const Cookie& cookie) {
    cookies_.push_back(cookie);
}

std::vector<Cookie> Response::getCookies() const {
    return cookies_;
}

std::vector<uint8_t> Response::serialize() const {
    std::stringstream ss;

    ss << versionToString(version_) << " "
       << statusCodeToInt(status_) << " "
       << reasonPhrase_ << "\r\n";

    ss << headers_.serialize();

    for (const auto& cookie : cookies_) {
        ss << "Set-Cookie: " << cookie.serialize() << "\r\n";
    }

    if (!body_.empty()) {
        ss << "Content-Length: " << body_.size() << "\r\n";
    }

    ss << "\r\n";

    std::string header = ss.str();
    std::vector<uint8_t> result(header.begin(), header.end());
    result.insert(result.end(), body_.begin(), body_.end());

    return result;
}

std::shared_ptr<Response> Response::parse(const std::vector<uint8_t>& data) {
    std::string str(data.begin(), data.end());
    std::istringstream iss(str);
    std::string line;

    if (!std::getline(iss, line)) {
        return nullptr;
    }

    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::istringstream statusLine(line);
    std::string versionStr;
    int statusCode;
    std::string reasonPhrase;

    statusLine >> versionStr >> statusCode;
    std::getline(statusLine, reasonPhrase);
    if (!reasonPhrase.empty() && reasonPhrase[0] == ' ') {
        reasonPhrase = reasonPhrase.substr(1);
    }

    Version version = stringToVersion(versionStr);
    StatusCode status = static_cast<StatusCode>(statusCode);

    auto response = std::make_shared<Response>(status, version);
    response->setReasonPhrase(reasonPhrase);

    while (std::getline(iss, line) && line != "\r" && !line.empty()) {
        if (line.back() == '\r') {
            line.pop_back();
        }

        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);

            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            if (key == "Set-Cookie") {
                response->addCookie(Cookie::parse(value));
            } else {
                response->headers().add(key, value);
            }
        }
    }

    std::string remaining((std::istreambuf_iterator<char>(iss)), std::istreambuf_iterator<char>());
    if (!remaining.empty()) {
        response->setBody(remaining);
    }

    return response;
}

std::string methodToString(Method method) {
    switch (method) {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        case Method::PATCH: return "PATCH";
        case Method::HEAD: return "HEAD";
        case Method::OPTIONS: return "OPTIONS";
        case Method::CONNECT: return "CONNECT";
        case Method::TRACE: return "TRACE";
        default: return "GET";
    }
}

Method stringToMethod(const std::string& str) {
    if (str == "GET") return Method::GET;
    if (str == "POST") return Method::POST;
    if (str == "PUT") return Method::PUT;
    if (str == "DELETE") return Method::DELETE;
    if (str == "PATCH") return Method::PATCH;
    if (str == "HEAD") return Method::HEAD;
    if (str == "OPTIONS") return Method::OPTIONS;
    if (str == "CONNECT") return Method::CONNECT;
    if (str == "TRACE") return Method::TRACE;
    return Method::GET;
}

std::string versionToString(Version version) {
    switch (version) {
        case Version::LIZARD_1_0: return "LIZARD/1.0";
        case Version::LIZARD_1_1: return "LIZARD/1.1";
        case Version::LIZARD_2_0: return "LIZARD/2.0";
        default: return "LIZARD/1.1";
    }
}

Version stringToVersion(const std::string& str) {
    if (str == "LIZARD/1.0") return Version::LIZARD_1_0;
    if (str == "LIZARD/1.1") return Version::LIZARD_1_1;
    if (str == "LIZARD/2.0") return Version::LIZARD_2_0;
    return Version::LIZARD_1_1;
}

std::string statusCodeToString(StatusCode code) {
    switch (code) {
        case StatusCode::CONTINUE: return "Continue";
        case StatusCode::SWITCHING_PROTOCOLS: return "Switching Protocols";
        case StatusCode::OK: return "OK";
        case StatusCode::CREATED: return "Created";
        case StatusCode::ACCEPTED: return "Accepted";
        case StatusCode::NO_CONTENT: return "No Content";
        case StatusCode::PARTIAL_CONTENT: return "Partial Content";
        case StatusCode::MOVED_PERMANENTLY: return "Moved Permanently";
        case StatusCode::FOUND: return "Found";
        case StatusCode::SEE_OTHER: return "See Other";
        case StatusCode::NOT_MODIFIED: return "Not Modified";
        case StatusCode::TEMPORARY_REDIRECT: return "Temporary Redirect";
        case StatusCode::PERMANENT_REDIRECT: return "Permanent Redirect";
        case StatusCode::BAD_REQUEST: return "Bad Request";
        case StatusCode::UNAUTHORIZED: return "Unauthorized";
        case StatusCode::FORBIDDEN: return "Forbidden";
        case StatusCode::NOT_FOUND: return "Not Found";
        case StatusCode::METHOD_NOT_ALLOWED: return "Method Not Allowed";
        case StatusCode::REQUEST_TIMEOUT: return "Request Timeout";
        case StatusCode::CONFLICT: return "Conflict";
        case StatusCode::GONE: return "Gone";
        case StatusCode::LENGTH_REQUIRED: return "Length Required";
        case StatusCode::PAYLOAD_TOO_LARGE: return "Payload Too Large";
        case StatusCode::URI_TOO_LONG: return "URI Too Long";
        case StatusCode::UNSUPPORTED_MEDIA_TYPE: return "Unsupported Media Type";
        case StatusCode::RANGE_NOT_SATISFIABLE: return "Range Not Satisfiable";
        case StatusCode::EXPECTATION_FAILED: return "Expectation Failed";
        case StatusCode::IM_A_TEAPOT: return "I'm a teapot";
        case StatusCode::TOO_MANY_REQUESTS: return "Too Many Requests";
        case StatusCode::INTERNAL_SERVER_ERROR: return "Internal Server Error";
        case StatusCode::NOT_IMPLEMENTED: return "Not Implemented";
        case StatusCode::BAD_GATEWAY: return "Bad Gateway";
        case StatusCode::SERVICE_UNAVAILABLE: return "Service Unavailable";
        case StatusCode::GATEWAY_TIMEOUT: return "Gateway Timeout";
        case StatusCode::VERSION_NOT_SUPPORTED: return "Version Not Supported";
        default: return "Unknown";
    }
}

int statusCodeToInt(StatusCode code) {
    return static_cast<int>(code);
}

URI parseURI(const std::string& uriStr) {
    URI uri;

    size_t schemeEnd = uriStr.find("://");
    if (schemeEnd == std::string::npos) {
        return uri;
    }

    uri.scheme = uriStr.substr(0, schemeEnd);

    if (uri.scheme == "lizard") {
        uri.protocol = Protocol::LIZARD;
    } else if (uri.scheme.find("lizard+") == 0) {
        uri.protocol = Protocol::LIZARD_LOCALHOST;
    }

    size_t hostStart = schemeEnd + 3;
    size_t pathStart = uriStr.find('/', hostStart);
    size_t queryStart = uriStr.find('?', hostStart);
    size_t fragmentStart = uriStr.find('#', hostStart);

    size_t hostEnd = std::min({pathStart, queryStart, fragmentStart});
    if (hostEnd == std::string::npos) {
        hostEnd = uriStr.length();
    }

    std::string hostPort = uriStr.substr(hostStart, hostEnd - hostStart);
    size_t portPos = hostPort.find(':');

    if (portPos != std::string::npos) {
        uri.host = hostPort.substr(0, portPos);
        uri.port = std::stoi(hostPort.substr(portPos + 1));
    } else {
        uri.host = hostPort;
        uri.port = 443;
    }

    if (pathStart != std::string::npos) {
        size_t pathEnd = std::min(queryStart, fragmentStart);
        if (pathEnd == std::string::npos) {
            pathEnd = uriStr.length();
        }
        uri.path = uriStr.substr(pathStart, pathEnd - pathStart);
    } else {
        uri.path = "/";
    }

    if (queryStart != std::string::npos) {
        size_t queryEnd = (fragmentStart != std::string::npos) ? fragmentStart : uriStr.length();
        uri.query = uriStr.substr(queryStart + 1, queryEnd - queryStart - 1);

        std::istringstream queryStream(uri.query);
        std::string param;
        while (std::getline(queryStream, param, '&')) {
            size_t eqPos = param.find('=');
            if (eqPos != std::string::npos) {
                std::string key = param.substr(0, eqPos);
                std::string value = param.substr(eqPos + 1);
                uri.query_params[key] = value;
            }
        }
    }

    if (fragmentStart != std::string::npos) {
        uri.fragment = uriStr.substr(fragmentStart + 1);
    }

    return uri;
}

}
