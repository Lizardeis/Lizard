#include "../lizard_client.h"
#include "../lizard_protocol.h"
#include <iostream>

using namespace lizard;

void printResponse(const std::string& title, std::shared_ptr<Response> response) {
    std::cout << "\n=== " << title << " ===" << std::endl;

    if (!response) {
        std::cout << "Error: No response received" << std::endl;
        return;
    }

    std::cout << "Status: " << statusCodeToInt(response->getStatus())
              << " " << response->getReasonPhrase() << std::endl;

    std::cout << "\nHeaders:" << std::endl;
    auto headers = response->headers().getAll();
    for (const auto& pair : headers) {
        for (const auto& value : pair.second) {
            std::cout << "  " << pair.first << ": " << value << std::endl;
        }
    }

    std::cout << "\nBody:" << std::endl;
    std::cout << response->getBodyAsString() << std::endl;

    auto cookies = response->getCookies();
    if (!cookies.empty()) {
        std::cout << "\nCookies:" << std::endl;
        for (const auto& cookie : cookies) {
            std::cout << "  " << cookie.name << " = " << cookie.value << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    TLSContext::initialize();

    std::string host = "localhost";
    int port = 8443;

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = std::stoi(argv[2]);
    }

    ClientOptions options;
    options.verifySSL = false;
    options.followRedirects = true;
    options.keepAlive = true;

    Client client(options);

    std::cout << "==================================" << std::endl;
    std::cout << "  Lizard Protocol Client Demo" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "Connecting to: lizard://" << host << ":" << port << std::endl;

    std::string baseUrl = "lizard://" + host + ":" + std::to_string(port);

    {
        std::cout << "\n[1] Testing GET request to /api/hello" << std::endl;
        auto response = client.get(baseUrl + "/api/hello");
        printResponse("GET /api/hello", response);
    }

    {
        std::cout << "\n[2] Testing GET request with path parameter" << std::endl;
        auto response = client.get(baseUrl + "/api/echo/HelloLizard");
        printResponse("GET /api/echo/HelloLizard", response);
    }

    {
        std::cout << "\n[3] Testing POST request with JSON body" << std::endl;
        RequestBuilder builder(Method::POST, baseUrl + "/api/data");
        builder.json(R"({"name": "Lizard", "type": "Protocol", "version": 1.0})");
        auto request = builder.build();

        auto response = client.request(request);
        printResponse("POST /api/data", response);
    }

    {
        std::cout << "\n[4] Testing GET request to view headers" << std::endl;
        RequestBuilder builder(Method::GET, baseUrl + "/api/headers");
        builder.header("X-Custom-Header", "LizardClient")
               .header("X-Request-ID", "12345")
               .userAgent("LizardClient/1.0 Demo");
        auto request = builder.build();

        auto response = client.request(request);
        printResponse("GET /api/headers", response);
    }

    {
        std::cout << "\n[5] Testing cookie handling" << std::endl;
        auto response = client.get(baseUrl + "/api/cookies");
        printResponse("GET /api/cookies", response);
    }

    {
        std::cout << "\n[6] Testing redirect following" << std::endl;
        auto response = client.get(baseUrl + "/api/redirect");
        printResponse("GET /api/redirect (with redirect)", response);
    }

    {
        std::cout << "\n[7] Testing Basic Authentication" << std::endl;
        RequestBuilder builder(Method::GET, baseUrl + "/api/headers");
        builder.basicAuth("lizard", "password123");
        auto request = builder.build();

        auto response = client.request(request);
        printResponse("GET /api/headers (with auth)", response);
    }

    {
        std::cout << "\n[8] Testing Bearer Token Authentication" << std::endl;
        RequestBuilder builder(Method::GET, baseUrl + "/api/headers");
        builder.bearerToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        auto request = builder.build();

        auto response = client.request(request);
        printResponse("GET /api/headers (with bearer)", response);
    }

    {
        std::cout << "\n[9] Testing error handling" << std::endl;
        auto response = client.get(baseUrl + "/api/error");
        printResponse("GET /api/error", response);
    }

    {
        std::cout << "\n[10] Testing 404 Not Found" << std::endl;
        auto response = client.get(baseUrl + "/api/nonexistent");
        printResponse("GET /api/nonexistent", response);
    }

    std::cout << "\n==================================" << std::endl;
    std::cout << "  All tests completed!" << std::endl;
    std::cout << "==================================" << std::endl;

    TLSContext::cleanup();
    return 0;
}
