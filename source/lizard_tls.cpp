#include "lizard_tls.h"
#include <cstring>
#include <iostream>

namespace lizard {

bool TLSContext::initialize() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return true;
}

void TLSContext::cleanup() {
    EVP_cleanup();
    ERR_free_strings();
}

TLSContext::TLSContext(bool isServer)
    : ctx_(nullptr), isServer_(isServer),
      minVersion_(TLSVersion::TLS_1_2), maxVersion_(TLSVersion::TLS_1_3) {

    const SSL_METHOD* method;
    if (isServer_) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }

    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        std::cerr << "Failed to create SSL context: " << getOpenSSLError() << std::endl;
        return;
    }

    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

    SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (isServer_) {
        SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_SERVER);
    }
}

TLSContext::~TLSContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

bool TLSContext::loadCertificate(const std::string& certFile) {
    if (SSL_CTX_use_certificate_file(ctx_, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load certificate: " << getOpenSSLError() << std::endl;
        return false;
    }
    return true;
}

bool TLSContext::loadPrivateKey(const std::string& keyFile) {
    if (SSL_CTX_use_PrivateKey_file(ctx_, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load private key: " << getOpenSSLError() << std::endl;
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx_)) {
        std::cerr << "Private key does not match certificate" << std::endl;
        return false;
    }

    return true;
}

bool TLSContext::loadCertificateChain(const std::string& chainFile) {
    if (SSL_CTX_use_certificate_chain_file(ctx_, chainFile.c_str()) <= 0) {
        std::cerr << "Failed to load certificate chain: " << getOpenSSLError() << std::endl;
        return false;
    }
    return true;
}

bool TLSContext::loadCAFile(const std::string& caFile) {
    if (SSL_CTX_load_verify_locations(ctx_, caFile.c_str(), nullptr) != 1) {
        std::cerr << "Failed to load CA file: " << getOpenSSLError() << std::endl;
        return false;
    }
    return true;
}

bool TLSContext::loadCAPath(const std::string& caPath) {
    if (SSL_CTX_load_verify_locations(ctx_, nullptr, caPath.c_str()) != 1) {
        std::cerr << "Failed to load CA path: " << getOpenSSLError() << std::endl;
        return false;
    }
    return true;
}

void TLSContext::setMinVersion(TLSVersion version) {
    minVersion_ = version;
    int v = TLS1_2_VERSION;
    switch (version) {
        case TLSVersion::TLS_1_0: v = TLS1_VERSION; break;
        case TLSVersion::TLS_1_1: v = TLS1_1_VERSION; break;
        case TLSVersion::TLS_1_2: v = TLS1_2_VERSION; break;
        case TLSVersion::TLS_1_3: v = TLS1_3_VERSION; break;
    }
    SSL_CTX_set_min_proto_version(ctx_, v);
}

void TLSContext::setMaxVersion(TLSVersion version) {
    maxVersion_ = version;
    int v = TLS1_3_VERSION;
    switch (version) {
        case TLSVersion::TLS_1_0: v = TLS1_VERSION; break;
        case TLSVersion::TLS_1_1: v = TLS1_1_VERSION; break;
        case TLSVersion::TLS_1_2: v = TLS1_2_VERSION; break;
        case TLSVersion::TLS_1_3: v = TLS1_3_VERSION; break;
    }
    SSL_CTX_set_max_proto_version(ctx_, v);
}

void TLSContext::setCipherList(const std::string& ciphers) {
    SSL_CTX_set_cipher_list(ctx_, ciphers.c_str());
}

void TLSContext::setCipherSuites(const std::string& suites) {
    SSL_CTX_set_ciphersuites(ctx_, suites.c_str());
}

void TLSContext::setVerifyMode(bool verify, bool verifyPeer) {
    int mode = SSL_VERIFY_NONE;
    if (verify) {
        mode = SSL_VERIFY_PEER;
        if (verifyPeer) {
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
    }
    SSL_CTX_set_verify(ctx_, mode, nullptr);
}

void TLSContext::setVerifyDepth(int depth) {
    SSL_CTX_set_verify_depth(ctx_, depth);
}

SSL_CTX* TLSContext::getContext() const {
    return ctx_;
}

TLSConnection::TLSConnection(std::shared_ptr<TLSContext> context, int socket)
    : ssl_(nullptr), socket_(socket), connected_(false),
      handshakeComplete_(false), context_(context) {

    ssl_ = SSL_new(context_->getContext());
    if (!ssl_) {
        std::cerr << "Failed to create SSL object: " << getOpenSSLError() << std::endl;
        return;
    }

    SSL_set_fd(ssl_, socket_);
}

TLSConnection::~TLSConnection() {
    close();
}

bool TLSConnection::connect() {
    if (!ssl_) {
        return false;
    }

    int result = SSL_connect(ssl_);
    if (result != 1) {
        int error = SSL_get_error(ssl_, result);
        std::cerr << "SSL connect failed: " << error << " - " << getOpenSSLError() << std::endl;
        return false;
    }

    connected_ = true;
    handshakeComplete_ = true;
    return true;
}

bool TLSConnection::accept() {
    if (!ssl_) {
        return false;
    }

    int result = SSL_accept(ssl_);
    if (result != 1) {
        int error = SSL_get_error(ssl_, result);
        std::cerr << "SSL accept failed: " << error << " - " << getOpenSSLError() << std::endl;
        return false;
    }

    connected_ = true;
    handshakeComplete_ = true;
    return true;
}

int TLSConnection::write(const std::vector<uint8_t>& data) {
    return write(data.data(), data.size());
}

int TLSConnection::write(const void* data, size_t length) {
    if (!ssl_ || !connected_) {
        return -1;
    }

    int result = SSL_write(ssl_, data, length);
    if (result <= 0) {
        int error = SSL_get_error(ssl_, result);
        std::cerr << "SSL write failed: " << error << " - " << getOpenSSLError() << std::endl;
        return -1;
    }

    return result;
}

std::vector<uint8_t> TLSConnection::read(size_t maxLength) {
    std::vector<uint8_t> buffer(maxLength);
    int bytesRead = read(buffer.data(), maxLength);
    if (bytesRead > 0) {
        buffer.resize(bytesRead);
        return buffer;
    }
    return std::vector<uint8_t>();
}

int TLSConnection::read(void* buffer, size_t length) {
    if (!ssl_ || !connected_) {
        return -1;
    }

    int result = SSL_read(ssl_, buffer, length);
    if (result <= 0) {
        int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        if (error != SSL_ERROR_ZERO_RETURN) {
            std::cerr << "SSL read failed: " << error << " - " << getOpenSSLError() << std::endl;
        }
        return -1;
    }

    return result;
}

bool TLSConnection::shutdown() {
    if (!ssl_ || !connected_) {
        return false;
    }

    int result = SSL_shutdown(ssl_);
    if (result == 0) {
        result = SSL_shutdown(ssl_);
    }

    connected_ = false;
    return result >= 0;
}

void TLSConnection::close() {
    if (ssl_) {
        if (connected_) {
            shutdown();
        }
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
}

bool TLSConnection::isConnected() const {
    return connected_;
}

bool TLSConnection::isHandshakeComplete() const {
    return handshakeComplete_;
}

std::string TLSConnection::getPeerCertificateInfo() const {
    if (!ssl_) {
        return "";
    }

    X509* cert = SSL_get_peer_certificate(ssl_);
    if (!cert) {
        return "No peer certificate";
    }

    char* line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    std::string info = line;
    OPENSSL_free(line);
    X509_free(cert);

    return info;
}

std::string TLSConnection::getCipherName() const {
    if (!ssl_) {
        return "";
    }

    const char* cipher = SSL_get_cipher_name(ssl_);
    return cipher ? std::string(cipher) : "";
}

std::string TLSConnection::getProtocolVersion() const {
    if (!ssl_) {
        return "";
    }

    const char* version = SSL_get_version(ssl_);
    return version ? std::string(version) : "";
}

bool TLSConnection::verifyPeerCertificate() {
    if (!ssl_) {
        return false;
    }

    long result = SSL_get_verify_result(ssl_);
    return result == X509_V_OK;
}

SSL* TLSConnection::getSSL() const {
    return ssl_;
}

bool CertificateGenerator::generateSelfSignedCertificate(
    const std::string& certFile,
    const std::string& keyFile,
    const std::string& commonName,
    int validDays
) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();

    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validDays * 24 * 3600);

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)commonName.c_str(), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_sign(x509, pkey, EVP_sha256());

    FILE* certFp = fopen(certFile.c_str(), "wb");
    if (!certFp) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_X509(certFp, x509);
    fclose(certFp);

    FILE* keyFp = fopen(keyFile.c_str(), "wb");
    if (!keyFp) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PrivateKey(keyFp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(keyFp);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return true;
}

bool CertificateGenerator::generateCSR(
    const std::string& csrFile,
    const std::string& keyFile,
    const std::string& commonName,
    const std::string& organization,
    const std::string& country
) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();

    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);

    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)commonName.c_str(), -1, -1, 0);

    if (!organization.empty()) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   (unsigned char*)organization.c_str(), -1, -1, 0);
    }

    if (!country.empty()) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                   (unsigned char*)country.c_str(), -1, -1, 0);
    }

    X509_REQ_sign(req, pkey, EVP_sha256());

    FILE* csrFp = fopen(csrFile.c_str(), "wb");
    if (!csrFp) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_X509_REQ(csrFp, req);
    fclose(csrFp);

    FILE* keyFp = fopen(keyFile.c_str(), "wb");
    if (!keyFp) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PrivateKey(keyFp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(keyFp);

    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return true;
}

std::string getOpenSSLError() {
    char buffer[256];
    ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string tlsVersionToString(TLSVersion version) {
    switch (version) {
        case TLSVersion::TLS_1_0: return "TLS 1.0";
        case TLSVersion::TLS_1_1: return "TLS 1.1";
        case TLSVersion::TLS_1_2: return "TLS 1.2";
        case TLSVersion::TLS_1_3: return "TLS 1.3";
        default: return "Unknown";
    }
}

}
