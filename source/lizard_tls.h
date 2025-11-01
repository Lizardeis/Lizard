#ifndef LIZARD_TLS_H
#define LIZARD_TLS_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

namespace lizard {

enum class TLSVersion {
    TLS_1_0,
    TLS_1_1,
    TLS_1_2,
    TLS_1_3
};

class TLSContext {
private:
    SSL_CTX* ctx_;
    bool isServer_;
    TLSVersion minVersion_;
    TLSVersion maxVersion_;

public:
    TLSContext(bool isServer = false);
    ~TLSContext();

    bool loadCertificate(const std::string& certFile);
    bool loadPrivateKey(const std::string& keyFile);
    bool loadCertificateChain(const std::string& chainFile);
    bool loadCAFile(const std::string& caFile);
    bool loadCAPath(const std::string& caPath);

    void setMinVersion(TLSVersion version);
    void setMaxVersion(TLSVersion version);

    void setCipherList(const std::string& ciphers);
    void setCipherSuites(const std::string& suites);

    void setVerifyMode(bool verify, bool verifyPeer);
    void setVerifyDepth(int depth);

    SSL_CTX* getContext() const;

    static bool initialize();
    static void cleanup();
};

class TLSConnection {
private:
    SSL* ssl_;
    int socket_;
    bool connected_;
    bool handshakeComplete_;
    std::shared_ptr<TLSContext> context_;

public:
    TLSConnection(std::shared_ptr<TLSContext> context, int socket);
    ~TLSConnection();

    bool connect();
    bool accept();

    int write(const std::vector<uint8_t>& data);
    int write(const void* data, size_t length);

    std::vector<uint8_t> read(size_t maxLength);
    int read(void* buffer, size_t length);

    bool shutdown();
    void close();

    bool isConnected() const;
    bool isHandshakeComplete() const;

    std::string getPeerCertificateInfo() const;
    std::string getCipherName() const;
    std::string getProtocolVersion() const;

    bool verifyPeerCertificate();

    SSL* getSSL() const;
};

class CertificateGenerator {
public:
    static bool generateSelfSignedCertificate(
        const std::string& certFile,
        const std::string& keyFile,
        const std::string& commonName,
        int validDays = 365
    );

    static bool generateCSR(
        const std::string& csrFile,
        const std::string& keyFile,
        const std::string& commonName,
        const std::string& organization = "",
        const std::string& country = ""
    );
};

std::string getOpenSSLError();
std::string tlsVersionToString(TLSVersion version);

}

#endif
