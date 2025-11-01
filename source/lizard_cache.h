#ifndef LIZARD_CACHE_H
#define LIZARD_CACHE_H

#include "lizard_protocol.h"
#include <memory>
#include <map>
#include <mutex>
#include <chrono>
#include <list>

namespace lizard {

struct CacheEntry {
    std::shared_ptr<Response> response;
    std::chrono::steady_clock::time_point timestamp;
    std::chrono::seconds maxAge;
    std::string etag;
    std::string lastModified;
    bool noCache;
    bool noStore;
    bool mustRevalidate;

    bool isExpired() const;
    bool isValid() const;
};

class Cache {
private:
    struct LRUNode {
        std::string key;
        CacheEntry entry;
    };

    std::map<std::string, std::list<LRUNode>::iterator> cacheMap_;
    std::list<LRUNode> lruList_;
    size_t maxSize_;
    size_t currentSize_;
    std::mutex mutex_;

    void evictLRU();
    void moveToFront(std::list<LRUNode>::iterator it);
    std::string generateKey(const Request& request) const;

public:
    Cache(size_t maxSize = 100);

    void put(const Request& request, std::shared_ptr<Response> response);
    std::shared_ptr<Response> get(const Request& request);

    bool has(const Request& request) const;
    void remove(const Request& request);
    void clear();

    size_t size() const;
    size_t maxSize() const;

    void setMaxSize(size_t maxSize);
};

class CacheManager {
private:
    std::shared_ptr<Cache> cache_;

public:
    CacheManager(size_t maxSize = 100);

    bool shouldCache(const Request& request, const Response& response);
    bool shouldRevalidate(const CacheEntry& entry);

    void cacheResponse(const Request& request, std::shared_ptr<Response> response);
    std::shared_ptr<Response> getCachedResponse(const Request& request);

    std::shared_ptr<Request> createRevalidationRequest(const Request& originalRequest,
                                                       const CacheEntry& entry);

    void updateCache(const Request& request, std::shared_ptr<Response> response);
    void invalidateCache(const std::string& pattern);

    CacheEntry parseCacheHeaders(std::shared_ptr<Response> response);

    void clear();
};

}

#endif
