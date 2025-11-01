#ifndef LIZARD_COMPRESSION_H
#define LIZARD_COMPRESSION_H

#include "lizard_protocol.h"
#include <vector>
#include <cstdint>
#include <zlib.h>

namespace lizard {

class Compressor {
public:
    static std::vector<uint8_t> compress(const std::vector<uint8_t>& data, CompressionType type);
    static std::vector<uint8_t> decompress(const std::vector<uint8_t>& data, CompressionType type);

    static std::vector<uint8_t> gzipCompress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> gzipDecompress(const std::vector<uint8_t>& data);

    static std::vector<uint8_t> deflateCompress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> deflateDecompress(const std::vector<uint8_t>& data);

    static bool isCompressed(const std::vector<uint8_t>& data, CompressionType type);
    static CompressionType detectCompression(const std::vector<uint8_t>& data);
};

class ChunkedEncoder {
public:
    static std::vector<uint8_t> encode(const std::vector<uint8_t>& data, size_t chunkSize = 4096);
    static std::vector<uint8_t> decode(const std::vector<uint8_t>& data);

    static std::string encodeChunk(const std::vector<uint8_t>& chunk);
    static std::string encodeLastChunk();
};

}

#endif
