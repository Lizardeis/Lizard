#include "../lizard_server.h"
#include "../lizard_protocol.h"
#include <iostream>
#include <signal.h>

using namespace lizard;

Server* globalServer = nullptr;

void signalHandler(int signum) {
    std::cout << "\nShutting down server..." << std::endl;
    if (globalServer) {
        globalServer->stop();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    TLSContext::initialize();

    int port = 8443;
    std::string host = "localhost";

    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    Server server(4);
    globalServer = &server;

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!server.generateSelfSignedCertificate("localhost")) {
        std::cerr << "Failed to generate self-signed certificate" << std::endl;
        return 1;
    }

    auto router = server.getRouter();

    router->use(loggerMiddleware());
    router->use(corsMiddleware());

    router->get("/", [](RouteContext& ctx) {
        std::string html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Lizard Protocol Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        h1 { margin-top: 0; }
        .endpoint {
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        code {
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦎 Lizard Protocol Server</h1>
        <p>Welcome to the Lizard Protocol demonstration server!</p>

        <h2>Available Endpoints:</h2>

        <div class="endpoint">
            <strong>GET /</strong> - This page
        </div>

        <div class="endpoint">
            <strong>GET /api/hello</strong> - Simple JSON response
        </div>

        <div class="endpoint">
            <strong>GET /api/echo/:message</strong> - Echo back a message
        </div>

        <div class="endpoint">
            <strong>POST /api/data</strong> - Submit data (JSON)
        </div>

        <div class="endpoint">
            <strong>GET /api/headers</strong> - View request headers
        </div>

        <div class="endpoint">
            <strong>GET /api/cookies</strong> - Test cookies
        </div>

        <h2>Protocol Information:</h2>
        <p>This server uses the <code>lizard://</code> protocol.</p>
        <p>Access via: <code>lizard://localhost:8443</code></p>
        <p>Or for local development: <code>lizard+localhost:8443</code></p>
    </div>
</body>
</html>
        )";
        ctx.html(html);
    });

    router->get("/api/hello", [](RouteContext& ctx) {
        ctx.json(R"({"message": "Hello from Lizard Protocol!", "version": "1.0", "protocol": "lizard"})");
    });

    router->get("/api/echo/:message", [](RouteContext& ctx) {
        std::string message = ctx.getParam("message");
        std::string response = "{\"echo\": \"" + message + "\"}";
        ctx.json(response);
    });

    router->post("/api/data", [](RouteContext& ctx) {
        auto request = ctx.request();
        std::string body = request->getBodyAsString();

        std::string response = "{\"received\": \"" + body + "\", \"status\": \"success\"}";
        ctx.json(response, StatusCode::CREATED);
    });

    router->get("/api/headers", [](RouteContext& ctx) {
        auto request = ctx.request();
        auto headers = request->headers().getAll();

        std::string json = "{\"headers\": {";
        bool first = true;
        for (const auto& pair : headers) {
            for (const auto& value : pair.second) {
                if (!first) json += ",";
                json += "\"" + pair.first + "\": \"" + value + "\"";
                first = false;
            }
        }
        json += "}}";

        ctx.json(json);
    });

    router->get("/api/cookies", [](RouteContext& ctx) {
        Cookie sessionCookie("session_id", "lizard_123456");
        sessionCookie.httpOnly = true;
        sessionCookie.secure = true;
        sessionCookie.maxAge = 3600;
        sessionCookie.path = "/";

        ctx.setCookie(sessionCookie);

        Cookie preferencesCookie("preferences", "theme=dark");
        preferencesCookie.maxAge = 86400;
        ctx.setCookie(preferencesCookie);

        ctx.json(R"({"message": "Cookies have been set!", "cookies": ["session_id", "preferences"]})");
    });

    router->get("/api/redirect", [](RouteContext& ctx) {
        ctx.redirect("/api/hello");
    });

    router->get("/api/error", [](RouteContext& ctx) {
        ctx.error(StatusCode::INTERNAL_SERVER_ERROR, "Simulated error for testing");
    });

    if (!server.start(host, port)) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    std::cout << "\n==================================" << std::endl;
    std::cout << "  Lizard Protocol Server Running" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "Protocol: lizard://" << host << ":" << port << std::endl;
    std::cout << "Alt URL:  lizard+" << host << ":" << port << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << "==================================" << std::endl;

    while (server.isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    TLSContext::cleanup();
    return 0;
}
