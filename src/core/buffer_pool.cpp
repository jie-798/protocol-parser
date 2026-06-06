#include "core/buffer_pool.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace protocol_parser::core {

// ============================================================================
// BufferPool::SizeClassPool 实现
// ============================================================================

BufferPool::SizeClassPool::SizeClassPool(size_t buffer_size, size_t initial_capacity)
    : blocks_(nullptr)
    , buffer_size_(buffer_size)
    , capacity_(0)
    , size_(0) {
    expand_pool(initial_capacity);
}

BufferPool::SizeClassPool::~SizeClassPool() {
    cleanup_blocks();
}

void BufferPool::SizeClassPool::cleanup_blocks() {
    // 释放所有内存块
    if (blocks_ != nullptr) {
        for (size_t i = 0; i < capacity_; ++i) {
            if (blocks_[i].data != nullptr) {
                #ifdef _WIN32
                    _aligned_free(blocks_[i].data);
                #else
                    free(blocks_[i].data);
                #endif
            }
        }
        // 释放块数组本身
        #ifdef _WIN32
            _aligned_free(blocks_);
        #else
            free(blocks_);
        #endif
        blocks_ = nullptr;
    }
    capacity_ = 0;
    size_.store(0, std::memory_order_relaxed);
}

void* BufferPool::SizeClassPool::allocate() {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t index = find_free_block();

    if (index < capacity_) {
        size_.fetch_add(1, std::memory_order_relaxed);
        return blocks_[index].data;
    }

    return nullptr;
}

void BufferPool::SizeClassPool::deallocate(void* ptr) {
    if (ptr == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < capacity_; ++i) {
        if (blocks_[i].data == ptr) {
            blocks_[i].in_use.store(false, std::memory_order_release);
            size_.fetch_sub(1, std::memory_order_relaxed);
            return;
        }
    }
}

void* BufferPool::SizeClassPool::find_block_containing(const void* ptr) noexcept {
    if (ptr == nullptr) {
        return nullptr;
    }

    const auto address = reinterpret_cast<std::uintptr_t>(ptr);
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < capacity_; ++i) {
        const auto begin = reinterpret_cast<std::uintptr_t>(blocks_[i].data);
        if (address >= begin && address < begin + buffer_size_) {
            return blocks_[i].data;
        }
    }
    return nullptr;
}

size_t BufferPool::SizeClassPool::find_free_block() {
    // 线性查找第一个空闲块
    // TODO: 可以优化为位图查找（SIMD）
    for (size_t i = 0; i < capacity_; ++i) {
        bool expected = false;
        if (blocks_[i].in_use.compare_exchange_strong(
            expected, true,
            std::memory_order_acquire,
            std::memory_order_relaxed)) {
            return i;
        }
    }
    return capacity_;  // 未找到
}

void BufferPool::SizeClassPool::expand_pool(size_t additional_blocks) {
    size_t old_capacity = capacity_;
    size_t new_capacity = old_capacity + additional_blocks;

    // 重新分配块数组
    Block* new_blocks = nullptr;

    #ifdef _WIN32
        new_blocks = static_cast<Block*>(_aligned_malloc(new_capacity * sizeof(Block), 64));
    #else
        posix_memalign(reinterpret_cast<void**>(&new_blocks), 64, new_capacity * sizeof(Block));
    #endif

    if (new_blocks == nullptr) {
        throw std::bad_alloc();
    }

    // 初始化新块数组
    for (size_t i = 0; i < new_capacity; ++i) {
        new (&new_blocks[i]) Block();  // placement new

        if (i < old_capacity && blocks_ != nullptr) {
            // 复制旧块
            new_blocks[i].data = blocks_[i].data;
            // 复制原子状态（注意：这里是拷贝构造，原子变量不允许，所以需要特殊处理）
            bool in_use = blocks_[i].in_use.load(std::memory_order_relaxed);
            new_blocks[i].in_use.store(in_use, std::memory_order_relaxed);
        } else {
            // 新块：分配内存
            #ifdef _WIN32
                new_blocks[i].data = _aligned_malloc(buffer_size_, 64);
            #else
                posix_memalign(&new_blocks[i].data, 64, buffer_size_);
            #endif

            if (new_blocks[i].data == nullptr) {
                for (size_t j = old_capacity; j < i; ++j) {
                    if (new_blocks[j].data != nullptr) {
                        #ifdef _WIN32
                            _aligned_free(new_blocks[j].data);
                        #else
                            free(new_blocks[j].data);
                        #endif
                    }
                }
                #ifdef _WIN32
                    _aligned_free(new_blocks);
                #else
                    free(new_blocks);
                #endif
                throw std::bad_alloc();
            }
        }
    }

    // 释放旧数组
    if (blocks_ != nullptr) {
        #ifdef _WIN32
            _aligned_free(blocks_);
        #else
            free(blocks_);
        #endif
    }

    blocks_ = new_blocks;
    capacity_ = new_capacity;
}

void BufferPool::SizeClassPool::reserve(size_t additional_capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (capacity_ < additional_capacity) {
        expand_pool(additional_capacity - capacity_);
    }
}

// ============================================================================
// BufferPool::ThreadLocalCache 实现
// ============================================================================

void* BufferPool::ThreadLocalCache::get(size_t size_class, const BufferPool* owner) {
    for (auto& entry : cache_) {
        if (entry.is_stale()) {
            entry = CacheEntry{};
            continue;
        }

        if (entry.matches(size_class, owner)) {
            void* ptr = entry.ptr;
            entry = CacheEntry{};
            return ptr;
        }
    }
    return nullptr;
}

bool BufferPool::ThreadLocalCache::put(void* ptr, size_t size_class, const BufferPool* owner,
                                       const std::shared_ptr<std::atomic<bool>>& owner_alive) {
    for (auto& entry : cache_) {
        if (entry.is_stale()) {
            entry = CacheEntry{};
        }

        if (entry.ptr == nullptr) {
            entry.ptr = ptr;
            entry.size_class = size_class;
            entry.owner = owner;
            entry.owner_alive = owner_alive;
            return true;
        }
    }

    return false;
}

// ============================================================================
// BufferPool 实现
// ============================================================================

thread_local BufferPool::ThreadLocalCache BufferPool::thread_cache_;

BufferPool::BufferPool(const Config& config)
    : config_(config)
    , alive_(std::make_shared<std::atomic<bool>>(true)) {

    // 初始化各个大小类的池
    pools_[0] = std::make_unique<SizeClassPool>(
        static_cast<size_t>(SizeClass::Small),
        config_.small_pool_size
    );

    pools_[1] = std::make_unique<SizeClassPool>(
        static_cast<size_t>(SizeClass::Medium),
        config_.medium_pool_size
    );

    pools_[2] = std::make_unique<SizeClassPool>(
        static_cast<size_t>(SizeClass::Large),
        config_.large_pool_size
    );

    pools_[3] = std::make_unique<SizeClassPool>(
        static_cast<size_t>(SizeClass::ExtraLarge),
        config_.extra_large_pool_size
    );
}

BufferPool::BufferPool()
    : BufferPool(Config{}) {
}

BufferPool::~BufferPool() {
    alive_->store(false, std::memory_order_release);
    flush_thread_cache();
}

BufferView BufferPool::acquire(size_t size) {
    // 确定大小类
    size_t pool_index = 0;

    if (size <= static_cast<size_t>(SizeClass::Small)) {
        pool_index = 0;
    } else if (size <= static_cast<size_t>(SizeClass::Medium)) {
        pool_index = 1;
    } else if (size <= static_cast<size_t>(SizeClass::Large)) {
        pool_index = 2;
    } else {
        pool_index = 3;
    }

    if (size == 0) {
        return BufferView{};
    }

    if (size > static_cast<size_t>(SizeClass::ExtraLarge)) {
        throw std::length_error("requested buffer size exceeds pool maximum");
    }

    void* ptr = nullptr;
    bool cache_hit = false;
    if (config_.enable_thread_cache) {
        ptr = thread_cache_.get(pool_index, this);
        cache_hit = ptr != nullptr;
    }

    if (ptr == nullptr) {
        ptr = pools_[pool_index]->allocate();

        if (ptr == nullptr && config_.enable_auto_expand) {
            pools_[pool_index]->reserve(std::max(pools_[pool_index]->capacity() * 2, size_t(1)));
            ptr = pools_[pool_index]->allocate();
        }

        if (ptr == nullptr) {
            throw std::bad_alloc();
        }
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (cache_hit) {
            stats_.cache_hits++;
        } else {
            stats_.cache_misses++;
        }
        stats_.total_allocations++;
        stats_.current_usage++;
        stats_.peak_usage = std::max(stats_.peak_usage, stats_.current_usage);
    }

    return BufferView(static_cast<const uint8_t*>(ptr), size);
}

void BufferPool::release(BufferView& buffer) {
    if (buffer.data() == nullptr) {
        return;
    }

    size_t pool_index = 0;
    void* block_ptr = nullptr;
    if (!find_pool_block(buffer.data(), pool_index, block_ptr)) {
        buffer = BufferView{};
        return;
    }

    if (!config_.enable_thread_cache || !thread_cache_.put(block_ptr, pool_index, this, alive_)) {
        pools_[pool_index]->deallocate(block_ptr);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_deallocations++;
        if (stats_.current_usage > 0) {
            stats_.current_usage--;
        }
    }

    buffer = BufferView{};
}

BufferPool::Statistics BufferPool::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

bool BufferPool::find_pool_block(const void* ptr, size_t& pool_index, void*& block_ptr) noexcept {
    for (size_t i = 0; i < 4; ++i) {
        if (pools_[i]) {
            if (void* found = pools_[i]->find_block_containing(ptr)) {
                pool_index = i;
                block_ptr = found;
                return true;
            }
        }
    }
    return false;
}

void BufferPool::warmup() {
    // 预先分配所有池的缓冲区
    for (auto& pool : pools_) {
        if (pool) {
            pool->reserve(pool->capacity());
        }
    }
}

void BufferPool::cleanup() {
    flush_thread_cache();
}

void BufferPool::flush_thread_cache() noexcept {
    for (auto& entry : thread_cache_.cache_) {
        if (entry.ptr != nullptr && entry.owner == this) {
            const size_t pool_index = entry.size_class;
            if (pool_index < 4 && pools_[pool_index]) {
                pools_[pool_index]->deallocate(entry.ptr);
            }
            entry = ThreadLocalCache::CacheEntry{};
        }
    }
}

BufferPool& BufferPool::instance() {
    static BufferPool instance;
    return instance;
}

} // namespace protocol_parser::core
