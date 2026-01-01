#include "core/buffer_pool.hpp"
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace protocol_parser::core {

// ============================================================================
// BufferPool::SizeClassPool 实现
// ============================================================================

BufferPool::SizeClassPool::SizeClassPool(size_t buffer_size, size_t initial_capacity)
    : buffer_size_(buffer_size)
    , capacity_(0)
    , size_(0)
    , blocks_(nullptr) {
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
        free(blocks_);
        blocks_ = nullptr;
    }
    capacity_ = 0;
    size_ = 0;
}

void* BufferPool::SizeClassPool::allocate() {
    // 尝试在已有块中查找空闲块
    size_t index = find_free_block();

    if (index < capacity_) {
        blocks_[index].in_use.store(true, std::memory_order_release);
        size_++;
        return blocks_[index].data;
    }

    // 没有空闲块，扩容
    std::lock_guard<std::mutex> lock(mutex_);
    expand_pool(std::max(capacity_ / 2, size_t(1)));  // 扩容 50%

    // 再次查找
    index = find_free_block();
    if (index < capacity_) {
        blocks_[index].in_use.store(true, std::memory_order_release);
        size_++;
        return blocks_[index].data;
    }

    return nullptr;  // 分配失败
}

void BufferPool::SizeClassPool::deallocate(void* ptr) {
    if (ptr == nullptr) {
        return;
    }

    // 查找对应的块
    for (size_t i = 0; i < capacity_; ++i) {
        if (blocks_[i].data == ptr) {
            blocks_[i].in_use.store(false, std::memory_order_release);
            size_--;
            return;
        }
    }
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
                // 清理已分配的内存
                for (size_t j = 0; j < i; ++j) {
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
    if (capacity_ < additional_capacity) {
        expand_pool(additional_capacity - capacity_);
    }
}

// ============================================================================
// BufferPool::ThreadLocalCache 实现
// ============================================================================

void* BufferPool::ThreadLocalCache::get(size_t size_class) {
    // 在缓存中查找匹配的块
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        if (cache_[i].matches(size_class)) {
            void* ptr = cache_[i].ptr;
            cache_[i].ptr = nullptr;
            return ptr;
        }
    }
    return nullptr;
}

void BufferPool::ThreadLocalCache::put(void* ptr, size_t size_class) {
    // 查找空位存放
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        if (cache_[i].ptr == nullptr) {
            cache_[i].ptr = ptr;
            cache_[i].size_class = size_class;
            return;
        }
    }

    // 缓存已满，替换最老的（简单实现）
    if (CACHE_SIZE > 0) {
        if (cache_[0].ptr != nullptr) {
            free(cache_[0].ptr);
        }
        cache_[0].ptr = ptr;
        cache_[0].size_class = size_class;
    }
}

void BufferPool::ThreadLocalCache::flush() {
    for (auto& entry : cache_) {
        if (entry.ptr != nullptr) {
            free(entry.ptr);
            entry.ptr = nullptr;
        }
    }
}

// ============================================================================
// BufferPool 实现
// ============================================================================

thread_local BufferPool::ThreadLocalCache BufferPool::thread_cache_;

BufferPool::BufferPool(const Config& config)
    : config_(config) {

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
    // 清理线程本地缓存
    thread_cache_.flush();
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

    // 尝试从线程本地缓存获取
    void* ptr = nullptr;
    if (config_.enable_thread_cache) {
        ptr = thread_cache_.get(pool_index);
        if (ptr != nullptr) {
            stats_.cache_hits++;
        }
    }

    // 缓存未命中，从池中分配
    if (ptr == nullptr) {
        stats_.cache_misses++;
        ptr = pools_[pool_index]->allocate();

        if (ptr == nullptr && config_.enable_auto_expand) {
            // 尝试扩容并重新分配
            pools_[pool_index]->reserve(pools_[pool_index]->capacity() * 2);
            ptr = pools_[pool_index]->allocate();
        }

        if (ptr == nullptr) {
            // 最后的回退：直接分配
            #ifdef _WIN32
                ptr = _aligned_malloc(pools_[pool_index]->buffer_size(), 64);
            #else
                posix_memalign(&ptr, 64, pools_[pool_index]->buffer_size());
            #endif
        }
    }

    stats_.total_allocations++;
    stats_.current_usage++;
    stats_.peak_usage = std::max(stats_.peak_usage, stats_.current_usage);

    return BufferView(static_cast<const uint8_t*>(ptr),
                     pools_[pool_index]->buffer_size());
}

void BufferPool::release(BufferView& buffer) {
    if (buffer.data() == nullptr) {
        return;
    }

    // 确定大小类（根据缓冲区大小）
    size_t pool_index = 0;
    size_t size = buffer.capacity();

    if (size <= static_cast<size_t>(SizeClass::Small)) {
        pool_index = 0;
    } else if (size <= static_cast<size_t>(SizeClass::Medium)) {
        pool_index = 1;
    } else if (size <= static_cast<size_t>(SizeClass::Large)) {
        pool_index = 2;
    } else {
        pool_index = 3;
    }

    // 尝试放回线程本地缓存
    if (config_.enable_thread_cache) {
        thread_cache_.put(const_cast<uint8_t*>(buffer.data()), pool_index);
    } else {
        // 直接归还到池
        pools_[pool_index]->deallocate(const_cast<uint8_t*>(buffer.data()));
    }

    stats_.total_deallocations++;
    stats_.current_usage--;

    // 清空缓冲区引用
    buffer = BufferView{};
}

BufferPool::Statistics BufferPool::get_statistics() const {
    return stats_;
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
    // 清理线程本地缓存
    thread_cache_.flush();

    // TODO: 可以在此处实现池的收缩逻辑
    // 释放未使用的内存块
}

BufferPool& BufferPool::instance() {
    static BufferPool instance;
    return instance;
}

} // namespace protocol_parser::core
