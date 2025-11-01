#include "lizard_compression.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace lizard {

std::vector<uint8_t> Compressor::compress(const std::vector<uint8_t>& data, CompressionType type) {
    switch (type) {
        case CompressionType::GZIP:
            return gzipCompress(data);
        case CompressionType::DEFLATE:
            return deflateCompress(data);
        case CompressionType::NONE:
        default:
            return data;
    }
}

std::vector<uint8_t> Compressor::decompress(const std::vector<uint8_t>& data, CompressionType type) {
    switch (type) {
        case CompressionType::GZIP:
            return gzipDecompress(data);
        case CompressionType::DEFLATE:
            return deflateDecompress(data);
        case CompressionType::NONE:
        default:
            return data;
    }
}

std::vector<uint8_t> Compressor::gzipCompress(const std::vector<uint8_t>& data) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        std::cerr << "Failed to initialize gzip compression" << std::endl;
        return std::vector<uint8_t>();
    }

    stream.avail_in = data.size();
    stream.next_in = const_cast<uint8_t*>(data.data());

    std::vector<uint8_t> compressed;
    const size_t bufferSize = 32768;
    uint8_t buffer[bufferSize];

    int result;
    do {
        stream.avail_out = bufferSize;
        stream.next_out = buffer;

        result = deflate(&stream, Z_FINISH);
        if (result == Z_STREAM_ERROR) {
            deflateEnd(&stream);
            std::cerr << "Gzip compression error" << std::endl;
            return std::vector<uint8_t>();
        }

        size_t have = bufferSize - stream.avail_out;
        compressed.insert(compressed.end(), buffer, buffer + have);

    } while (stream.avail_out == 0);

    deflateEnd(&stream);
    return compressed;
}

std::vector<uint8_t> Compressor::gzipDecompress(const std::vector<uint8_t>& data) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));

    if (inflateInit2(&stream, 15 + 16) != Z_OK) {
        std::cerr << "Failed to initialize gzip decompression" << std::endl;
        return std::vector<uint8_t>();
    }

    stream.avail_in = data.size();
    stream.next_in = const_cast<uint8_t*>(data.data());

    std::vector<uint8_t> decompressed;
    const size_t bufferSize = 32768;
    uint8_t buffer[bufferSize];

    int result;
    do {
        stream.avail_out = bufferSize;
        stream.next_out = buffer;

        result = inflate(&stream, Z_NO_FLUSH);
        if (result == Z_STREAM_ERROR || result == Z_DATA_ERROR || result == Z_MEM_ERROR) {
            inflateEnd(&stream);
            std::cerr << "Gzip decompression error: " << result << std::endl;
            return std::vector<uint8_t>();
        }

        size_t have = bufferSize - stream.avail_out;
        decompressed.insert(decompressed.end(), buffer, buffer + have);

    } while (stream.avail_out == 0);

    inflateEnd(&stream);
    return decompressed;
}

std::vector<uint8_t> Compressor::deflateCompress(const std::vector<uint8_t>& data) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));

    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        std::cerr << "Failed to initialize deflate compression" << std::endl;
        return std::vector<uint8_t>();
    }

    stream.avail_in = data.size();
    stream.next_in = const_cast<uint8_t*>(data.data());

    std::vector<uint8_t> compressed;
    const size_t bufferSize = 32768;
    uint8_t buffer[bufferSize];

    int result;
    do {
        stream.avail_out = bufferSize;
        stream.next_out = buffer;

        result = deflate(&stream, Z_FINISH);
        if (result == Z_STREAM_ERROR) {
            deflateEnd(&stream);
            std::cerr << "Deflate compression error" << std::endl;
            return std::vector<uint8_t>();
        }

        size_t have = bufferSize - stream.avail_out;
        compressed.insert(compressed.end(), buffer, buffer + have);

    } while (stream.avail_out == 0);

    deflateEnd(&stream);
    return compressed;
}

std::vector<uint8_t> Compressor::deflateDecompress(const std::vector<uint8_t>& data) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));

    if (inflateInit(&stream) != Z_OK) {
        std::cerr << "Failed to initialize deflate decompression" << std::endl;
        return std::vector<uint8_t>();
    }

    stream.avail_in = data.size();
    stream.next_in = const_cast<uint8_t*>(data.data());

    std::vector<uint8_t> decompressed;
    const size_t bufferSize = 32768;
    uint8_t buffer[bufferSize];

    int result;
    do {
        stream.avail_out = bufferSize;
        stream.next_out = buffer;

        result = inflate(&stream, Z_NO_FLUSH);
        if (result == Z_STREAM_ERROR || result == Z_DATA_ERROR || result == Z_MEM_ERROR) {
            inflateEnd(&stream);
            std::cerr << "Deflate decompression error: " << result << std::endl;
            return std::vector<uint8_t>();
        }

        size_t have = bufferSize - stream.avail_out;
        decompressed.insert(decompressed.end(), buffer, buffer + have);

    } while (stream.avail_out == 0);

    inflateEnd(&stream);
    return decompressed;
}

bool Compressor::isCompressed(const std::vector<uint8_t>& data, CompressionType type) {
    if (data.size() < 2) {
        return false;
    }

    switch (type) {
        case CompressionType::GZIP:
            return data[0] == 0x1f && data[1] == 0x8b;
        case CompressionType::DEFLATE:
            return (data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9c || data[1] == 0xda));
        default:
            return false;
    }
}

CompressionType Compressor::detectCompression(const std::vector<uint8_t>& data) {
    if (isCompressed(data, CompressionType::GZIP)) {
        return CompressionType::GZIP;
    }
    if (isCompressed(data, CompressionType::DEFLATE)) {
        return CompressionType::DEFLATE;
    }
    return CompressionType::NONE;
}

std::vector<uint8_t> ChunkedEncoder::encode(const std::vector<uint8_t>& data, size_t chunkSize) {
    std::vector<uint8_t> encoded;
    size_t offset = 0;

    while (offset < data.size()) {
        size_t remaining = data.size() - offset;
        size_t currentChunkSize = std::min(chunkSize, remaining);

        std::vector<uint8_t> chunk(data.begin() + offset, data.begin() + offset + currentChunkSize);
        std::string chunkStr = encodeChunk(chunk);

        encoded.insert(encoded.end(), chunkStr.begin(), chunkStr.end());
        offset += currentChunkSize;
    }

    std::string lastChunk = encodeLastChunk();
    encoded.insert(encoded.end(), lastChunk.begin(), lastChunk.end());

    return encoded;
}

std::string ChunkedEncoder::encodeChunk(const std::vector<uint8_t>& chunk) {
    std::stringstream ss;
    ss << std::hex << chunk.size() << "\r\n";
    ss << std::string(chunk.begin(), chunk.end()) << "\r\n";
    return ss.str();
}

std::string ChunkedEncoder::encodeLastChunk() {
    return "0\r\n\r\n";
}

std::vector<uint8_t> ChunkedEncoder::decode(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> decoded;
    std::string str(data.begin(), data.end());
    std::istringstream iss(str);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty() || line == "\r") {
            continue;
        }

        if (line.back() == '\r') {
            line.pop_back();
        }

        size_t chunkSize;
        std::istringstream hexStream(line);
        hexStream >> std::hex >> chunkSize;

        if (chunkSize == 0) {
            break;
        }

        std::vector<char> chunk(chunkSize);
        iss.read(chunk.data(), chunkSize);

        decoded.insert(decoded.end(), chunk.begin(), chunk.begin() + iss.gcount());

        std::getline(iss, line);
    }

    return decoded;
}

}
