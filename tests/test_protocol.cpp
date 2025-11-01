#include "../lizard_protocol.h"
#include "../lizard_compression.h"
#include "../lizard_cache.h"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace lizard;

void testURIParsing() {
    std::cout << "Testing URI parsing..." << std::endl;

    URI uri1 = parseURI("lizard://example.com:8443/path/to/resource?key=value&foo=bar#section");
    assert(uri1.scheme == "lizard");
    assert(uri1.host == "example.com");
    assert(uri1.port == 8443);
    assert(uri1.path == "/path/to/resource");
    assert(uri1.query == "key=value&foo=bar");
    assert(uri1.fragment == "section");
    assert(uri1.query_params["key"] == "value");
    assert(uri1.query_params["foo"] == "bar");

    URI uri2 = parseURI("lizard+localhost:9000/api/test");
    assert(uri2.scheme == "lizard+localhost");
    assert(uri2.host == "localhost");
    assert(uri2.port == 9000);
    assert(uri2.path == "/api/test");

    std::cout << "  ✓ URI parsing tests passed" << std::endl;
}

void testHeaders() {
    std::cout << "Testing headers..." << std::endl;

    Headers headers;
    headers.set("Content-Type", "application/json");
    headers.set("Authorization", "Bearer token123");
    headers.add("Set-Cookie", "session=abc123");
    headers.add("Set-Cookie", "user=john");

    assert(headers.get("content-type") == "application/json");
    assert(headers.has("authorization"));

    auto cookies = headers.getAll("set-cookie");
    assert(cookies.size() == 2);
    assert(cookies[0] == "session=abc123");
    assert(cookies[1] == "user=john");

    std::cout << "  ✓ Headers tests passed" << std::endl;
}

void testRequest() {
    std::cout << "Testing request..." << std::endl;

    URI uri = parseURI("lizard://api.example.com/users/123");
    Request request(Method::GET, uri);

    request.headers().set("User-Agent", "LizardClient/1.0");
    request.headers().set("Accept", "application/json");
    request.addCookie(Cookie("session", "xyz789"));

    assert(request.getMethod() == Method::GET);
    assert(request.getURI().path == "/users/123");
    assert(request.headers().get("user-agent") == "LizardClient/1.0");

    auto serialized = request.serialize();
    auto parsed = Request::parse(serialized);

    assert(parsed != nullptr);
    assert(parsed->getMethod() == Method::GET);
    assert(parsed->getURI().path == "/users/123");

    std::cout << "  ✓ Request tests passed" << std::endl;
}

void testResponse() {
    std::cout << "Testing response..." << std::endl;

    Response response(StatusCode::OK);
    response.headers().set("Content-Type", "application/json");
    response.setBody(R"({"status": "success"})");
    response.addCookie(Cookie("session", "abc123"));

    assert(response.getStatus() == StatusCode::OK);
    assert(response.getBodyAsString() == R"({"status": "success"})");

    auto serialized = response.serialize();
    auto parsed = Response::parse(serialized);

    assert(parsed != nullptr);
    assert(parsed->getStatus() == StatusCode::OK);
    assert(parsed->getBodyAsString() == R"({"status": "success"})");

    std::cout << "  ✓ Response tests passed" << std::endl;
}

void testCookie() {
    std::cout << "Testing cookies..." << std::endl;

    Cookie cookie("user_id", "12345");
    cookie.domain = "example.com";
    cookie.path = "/api";
    cookie.maxAge = 3600;
    cookie.secure = true;
    cookie.httpOnly = true;
    cookie.sameSite = "Strict";

    std::string serialized = cookie.serialize();
    assert(serialized.find("user_id=12345") != std::string::npos);
    assert(serialized.find("Domain=example.com") != std::string::npos);
    assert(serialized.find("Secure") != std::string::npos);
    assert(serialized.find("HttpOnly") != std::string::npos);

    Cookie parsed = Cookie::parse("session=xyz; Domain=test.com; Max-Age=7200; Secure");
    assert(parsed.name == "session");
    assert(parsed.value == "xyz");
    assert(parsed.domain == "test.com");
    assert(parsed.maxAge == 7200);
    assert(parsed.secure);

    std::cout << "  ✓ Cookie tests passed" << std::endl;
}

void testCompression() {
    std::cout << "Testing compression..." << std::endl;

    std::string original = "This is a test string that will be compressed using gzip and deflate algorithms. ";
    for (int i = 0; i < 10; ++i) {
        original += original;
    }

    std::vector<uint8_t> data(original.begin(), original.end());

    auto gzipCompressed = Compressor::gzipCompress(data);
    assert(gzipCompressed.size() < data.size());
    assert(Compressor::isCompressed(gzipCompressed, CompressionType::GZIP));

    auto gzipDecompressed = Compressor::gzipDecompress(gzipCompressed);
    assert(gzipDecompressed.size() == data.size());
    assert(std::memcmp(gzipDecompressed.data(), data.data(), data.size()) == 0);

    auto deflateCompressed = Compressor::deflateCompress(data);
    assert(deflateCompressed.size() < data.size());

    auto deflateDecompressed = Compressor::deflateDecompress(deflateCompressed);
    assert(deflateDecompressed.size() == data.size());
    assert(std::memcmp(deflateDecompressed.data(), data.data(), data.size()) == 0);

    std::cout << "  ✓ Compression tests passed" << std::endl;
}

void testChunkedEncoding() {
    std::cout << "Testing chunked encoding..." << std::endl;

    std::string data = "Hello, World! This is a test of chunked transfer encoding.";
    std::vector<uint8_t> bytes(data.begin(), data.end());

    auto encoded = ChunkedEncoder::encode(bytes, 10);
    assert(encoded.size() > bytes.size());

    auto decoded = ChunkedEncoder::decode(encoded);
    assert(decoded.size() == bytes.size());
    assert(std::memcmp(decoded.data(), bytes.data(), bytes.size()) == 0);

    std::cout << "  ✓ Chunked encoding tests passed" << std::endl;
}

void testCache() {
    std::cout << "Testing cache..." << std::endl;

    Cache cache(10);

    URI uri = parseURI("lizard://api.example.com/data");
    Request request(Method::GET, uri);

    auto response = std::make_shared<Response>(StatusCode::OK);
    response->headers().set("Cache-Control", "max-age=3600");
    response->setBody("cached data");

    cache.put(request, response);
    assert(cache.has(request));

    auto cached = cache.get(request);
    assert(cached != nullptr);
    assert(cached->getBodyAsString() == "cached data");

    cache.remove(request);
    assert(!cache.has(request));

    std::cout << "  ✓ Cache tests passed" << std::endl;
}

void testStatusCodes() {
    std::cout << "Testing status codes..." << std::endl;

    assert(statusCodeToInt(StatusCode::OK) == 200);
    assert(statusCodeToInt(StatusCode::NOT_FOUND) == 404);
    assert(statusCodeToInt(StatusCode::INTERNAL_SERVER_ERROR) == 500);

    assert(statusCodeToString(StatusCode::OK) == "OK");
    assert(statusCodeToString(StatusCode::NOT_FOUND) == "Not Found");
    assert(statusCodeToString(StatusCode::CREATED) == "Created");

    std::cout << "  ✓ Status code tests passed" << std::endl;
}

void testMethods() {
    std::cout << "Testing methods..." << std::endl;

    assert(methodToString(Method::GET) == "GET");
    assert(methodToString(Method::POST) == "POST");
    assert(methodToString(Method::DELETE) == "DELETE");

    assert(stringToMethod("GET") == Method::GET);
    assert(stringToMethod("POST") == Method::POST);
    assert(stringToMethod("PUT") == Method::PUT);

    std::cout << "  ✓ Method tests passed" << std::endl;
}

void testVersions() {
    std::cout << "Testing versions..." << std::endl;

    assert(versionToString(Version::LIZARD_1_0) == "LIZARD/1.0");
    assert(versionToString(Version::LIZARD_1_1) == "LIZARD/1.1");
    assert(versionToString(Version::LIZARD_2_0) == "LIZARD/2.0");

    assert(stringToVersion("LIZARD/1.0") == Version::LIZARD_1_0);
    assert(stringToVersion("LIZARD/1.1") == Version::LIZARD_1_1);
    assert(stringToVersion("LIZARD/2.0") == Version::LIZARD_2_0);

    std::cout << "  ✓ Version tests passed" << std::endl;
}

int main() {
    std::cout << "\n==================================" << std::endl;
    std::cout << "  Lizard Protocol Tests" << std::endl;
    std::cout << "==================================" << std::endl;

    try {
        testURIParsing();
        testHeaders();
        testRequest();
        testResponse();
        testCookie();
        testCompression();
        testChunkedEncoding();
        testCache();
        testStatusCodes();
        testMethods();
        testVersions();

        std::cout << "\n==================================" << std::endl;
        std::cout << "  All tests passed! ✓" << std::endl;
        std::cout << "==================================" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest failed: " << e.what() << std::endl;
        return 1;
    }
}
