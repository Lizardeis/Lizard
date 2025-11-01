#include "../lizard_client.h"
#include "../lizard_server.h"
#include "../lizard_protocol.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>

using namespace lizard;

std::atomic<bool> serverReady(false);
std::atomic<size_t> requestCount(0);
std::atomic<size_t> successCount(0);
std::atomic<size_t> errorCount(0);

void runServer() {
    TLSContext::initialize();

    Server server(8);
    server.generateSelfSignedCertificate("localhost");

    auto router = server.getRouter();

    router->get("/benchmark", [](RouteContext& ctx) {
        ctx.json(R"({"status": "ok", "message": "Benchmark response"})");
    });

    router->post("/benchmark", [](RouteContext& ctx) {
        auto request = ctx.request();
        std::string body = request->getBodyAsString();
        ctx.json(R"({"status": "ok", "received": true})", StatusCode::CREATED);
    });

    server.start("127.0.0.1", 9443);
    serverReady = true;

    std::cout << "Benchmark server started on port 9443" << std::endl;

    while (server.isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    TLSContext::cleanup();
}

void runBenchmark(int numRequests, int concurrency) {
    std::vector<std::thread> threads;

    auto startTime = std::chrono::high_resolution_clock::now();

    for (int t = 0; t < concurrency; ++t) {
        threads.emplace_back([numRequests, concurrency]() {
            TLSContext::initialize();

            ClientOptions options;
            options.verifySSL = false;
            options.keepAlive = true;

            Client client(options);

            int requestsPerThread = numRequests / concurrency;

            for (int i = 0; i < requestsPerThread; ++i) {
                requestCount++;

                auto response = client.get("lizard://127.0.0.1:9443/benchmark");

                if (response && response->getStatus() == StatusCode::OK) {
                    successCount++;
                } else {
                    errorCount++;
                }

                if ((requestCount % 100) == 0) {
                    std::cout << "\rRequests: " << requestCount << " / " << numRequests
                              << " (Success: " << successCount << ", Errors: " << errorCount << ")"
                              << std::flush;
                }
            }

            TLSContext::cleanup();
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    std::cout << "\n\n==================================" << std::endl;
    std::cout << "  Benchmark Results" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "Total Requests:    " << requestCount << std::endl;
    std::cout << "Successful:        " << successCount << std::endl;
    std::cout << "Errors:            " << errorCount << std::endl;
    std::cout << "Concurrency:       " << concurrency << std::endl;
    std::cout << "Total Time:        " << duration.count() << " ms" << std::endl;

    if (duration.count() > 0) {
        double rps = (static_cast<double>(requestCount) / duration.count()) * 1000.0;
        std::cout << "Requests/Second:   " << static_cast<int>(rps) << std::endl;
        std::cout << "Avg Latency:       " << (duration.count() / static_cast<double>(requestCount))
                  << " ms" << std::endl;
    }

    std::cout << "==================================" << std::endl;
}

int main(int argc, char* argv[]) {
    int numRequests = 1000;
    int concurrency = 10;

    if (argc > 1) {
        numRequests = std::stoi(argv[1]);
    }
    if (argc > 2) {
        concurrency = std::stoi(argv[2]);
    }

    std::cout << "==================================" << std::endl;
    std::cout << "  Lizard Protocol Benchmark" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "Requests:     " << numRequests << std::endl;
    std::cout << "Concurrency:  " << concurrency << std::endl;
    std::cout << "==================================" << std::endl;

    std::thread serverThread(runServer);

    while (!serverReady) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "\nStarting benchmark...\n" << std::endl;

    runBenchmark(numRequests, concurrency);

    std::cout << "\nBenchmark complete. Press Ctrl+C to stop the server." << std::endl;

    serverThread.join();

    return 0;
}
