#include "lizard_cache.h"
#include <sstream>
#include <algorithm>
#include <regex>

namespace lizard {

bool CacheEntry::isExpired() const {
    if (maxAge.count() == 0) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - timestamp);
    return elapsed >= maxAge;
}

bool CacheEntry::isValid() const {
    if (noStore) {
        return false;
    }

    if (noCache || mustRevalidate) {
        return !isExpired();
    }

    return !isExpired();
}

Cache::Cache(size_t maxSize)
    : maxSize_(maxSize), currentSize_(0) {}

std::string Cache::generateKey(const Request& request) const {
    std::stringstream ss;
    ss << methodToString(request.getMethod()) << ":"
       << request.getURI().host << ":"
       << request.getURI().port << ":"
       << request.getURI().path;

    if (!request.getURI().query.empty()) {
        ss << "?" << request.getURI().query;
    }

    return ss.str();
}

void Cache::put(const Request& request, std::shared_ptr<Response> response) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = generateKey(request);

    auto it = cacheMap_.find(key);
    if (it != cacheMap_.end()) {
        lruList_.erase(it->second);
        currentSize_--;
    }

    CacheEntry entry;
    entry.response = response;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.maxAge = std::chrono::seconds(0);
    entry.noCache = false;
    entry.noStore = false;
    entry.mustRevalidate = false;

    std::string cacheControl = response->headers().get("Cache-Control");
    if (!cacheControl.empty()) {
        std::transform(cacheControl.begin(), cacheControl.end(), cacheControl.begin(), ::tolower);

        if (cacheControl.find("no-store") != std::string::npos) {
            entry.noStore = true;
            return;
        }

        if (cacheControl.find("no-cache") != std::string::npos) {
            entry.noCache = true;
        }

        if (cacheControl.find("must-revalidate") != std::string::npos) {
            entry.mustRevalidate = true;
        }

        std::regex maxAgeRegex("max-age=(\\d+)");
        std::smatch match;
        if (std::regex_search(cacheControl, match, maxAgeRegex)) {
            int seconds = std::stoi(match[1].str());
            entry.maxAge = std::chrono::seconds(seconds);
        }
    }

    entry.etag = response->headers().get("ETag");
    entry.lastModified = response->headers().get("Last-Modified");

    if (currentSize_ >= maxSize_) {
        evictLRU();
    }

    lruList_.push_front({key, entry});
    cacheMap_[key] = lruList_.begin();
    currentSize_++;
}

std::shared_ptr<Response> Cache::get(const Request& request) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = generateKey(request);
    auto it = cacheMap_.find(key);

    if (it == cacheMap_.end()) {
        return nullptr;
    }

    auto& entry = it->second->entry;
    if (!entry.isValid()) {
        lruList_.erase(it->second);
        cacheMap_.erase(it);
        currentSize_--;
        return nullptr;
    }

    moveToFront(it->second);
    return entry.response;
}

bool Cache::has(const Request& request) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = generateKey(request);
    return cacheMap_.find(key) != cacheMap_.end();
}

void Cache::remove(const Request& request) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = generateKey(request);
    auto it = cacheMap_.find(key);

    if (it != cacheMap_.end()) {
        lruList_.erase(it->second);
        cacheMap_.erase(it);
        currentSize_--;
    }
}

void Cache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    lruList_.clear();
    cacheMap_.clear();
    currentSize_ = 0;
}

size_t Cache::size() const {
    return currentSize_;
}

size_t Cache::maxSize() const {
    return maxSize_;
}

void Cache::setMaxSize(size_t maxSize) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxSize_ = maxSize;

    while (currentSize_ > maxSize_) {
        evictLRU();
    }
}

void Cache::evictLRU() {
    if (lruList_.empty()) {
        return;
    }

    auto& node = lruList_.back();
    cacheMap_.erase(node.key);
    lruList_.pop_back();
    currentSize_--;
}

void Cache::moveToFront(std::list<LRUNode>::iterator it) {
    lruList_.splice(lruList_.begin(), lruList_, it);
}

CacheManager::CacheManager(size_t maxSize)
    : cache_(std::make_shared<Cache>(maxSize)) {}

bool CacheManager::shouldCache(const Request& request, const Response& response) {
    Method method = request.getMethod();
    if (method != Method::GET && method != Method::HEAD) {
        return false;
    }

    StatusCode status = response.getStatus();
    if (status != StatusCode::OK &&
        status != StatusCode::NOT_MODIFIED &&
        status != StatusCode::MOVED_PERMANENTLY &&
        status != StatusCode::FOUND) {
        return false;
    }

    std::string cacheControl = response.headers().get("Cache-Control");
    if (!cacheControl.empty()) {
        std::transform(cacheControl.begin(), cacheControl.end(), cacheControl.begin(), ::tolower);
        if (cacheControl.find("no-store") != std::string::npos) {
            return false;
        }
    }

    return true;
}

bool CacheManager::shouldRevalidate(const CacheEntry& entry) {
    if (entry.noCache || entry.mustRevalidate) {
        return true;
    }

    return entry.isExpired();
}

void CacheManager::cacheResponse(const Request& request, std::shared_ptr<Response> response) {
    if (shouldCache(request, *response)) {
        cache_->put(request, response);
    }
}

std::shared_ptr<Response> CacheManager::getCachedResponse(const Request& request) {
    return cache_->get(request);
}

std::shared_ptr<Request> CacheManager::createRevalidationRequest(
    const Request& originalRequest,
    const CacheEntry& entry
) {
    auto request = std::make_shared<Request>(originalRequest);

    if (!entry.etag.empty()) {
        request->headers().set("If-None-Match", entry.etag);
    }

    if (!entry.lastModified.empty()) {
        request->headers().set("If-Modified-Since", entry.lastModified);
    }

    return request;
}

void CacheManager::updateCache(const Request& request, std::shared_ptr<Response> response) {
    if (response->getStatus() == StatusCode::NOT_MODIFIED) {
        auto cached = cache_->get(request);
        if (cached) {
            cached->headers().set("Date", response->headers().get("Date"));
        }
    } else {
        cacheResponse(request, response);
    }
}

void CacheManager::invalidateCache(const std::string& pattern) {
    cache_->clear();
}

CacheEntry CacheManager::parseCacheHeaders(std::shared_ptr<Response> response) {
    CacheEntry entry;
    entry.response = response;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.maxAge = std::chrono::seconds(0);
    entry.noCache = false;
    entry.noStore = false;
    entry.mustRevalidate = false;

    std::string cacheControl = response->headers().get("Cache-Control");
    if (!cacheControl.empty()) {
        std::transform(cacheControl.begin(), cacheControl.end(), cacheControl.begin(), ::tolower);

        if (cacheControl.find("no-store") != std::string::npos) {
            entry.noStore = true;
        }

        if (cacheControl.find("no-cache") != std::string::npos) {
            entry.noCache = true;
        }

        if (cacheControl.find("must-revalidate") != std::string::npos) {
            entry.mustRevalidate = true;
        }

        std::regex maxAgeRegex("max-age=(\\d+)");
        std::smatch match;
        if (std::regex_search(cacheControl, match, maxAgeRegex)) {
            int seconds = std::stoi(match[1].str());
            entry.maxAge = std::chrono::seconds(seconds);
        }
    }

    entry.etag = response->headers().get("ETag");
    entry.lastModified = response->headers().get("Last-Modified");

    return entry;
}

void CacheManager::clear() {
    cache_->clear();
}

}
