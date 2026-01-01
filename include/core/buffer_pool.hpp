#pragma once

#include <cstdint>
#include <atomic>
#include <memory>
#include <array>
#include <vector>
#include <mutex>
#include "buffer_view.hpp"

namespace protocol_parser::core {

/**
 * 高性能内存对象池
 * 用于减少频繁的内存分配/释放开销
 *
 * 特性：
 * - 预分配固定大小缓冲区
 * - 无锁快速路径（thread-local cache）
 * - 线程安全
 * - 自动扩容（可选）
 */
class BufferPool {
public:
    // 缓冲区大小类别（覆盖常见 MTU）
    enum class SizeClass : size_t {
        Small = 128,         // 小包（如 ACK、控制包）
        Medium = 1514,       // 标准以太网 MTU
        Large = 9018,        // Jumbo 帧
        ExtraLarge = 65536   // 最大可能包
    };

    // 池配置
    struct Config {
        size_t small_pool_size = 1024;      // 小缓冲区数量
        size_t medium_pool_size = 512;      // 中缓冲区数量
        size_t large_pool_size = 256;       // 大缓冲区数量
        size_t extra_large_pool_size = 64;  // 超大缓冲区数量
        bool enable_auto_expand = true;     // 允许自动扩容
        bool enable_thread_cache = true;    // 启用线程本地缓存

        // 默认构造函数
        Config() = default;
    };

    explicit BufferPool(const Config& config);
    BufferPool();
    ~BufferPool();

    // 禁止拷贝和移动
    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;
    BufferPool(BufferPool&&) = delete;
    BufferPool& operator=(BufferPool&&) = delete;

    /**
     * 获取缓冲区
     * @param size 请求的大小
     * @return BufferView 对象
     */
    [[nodiscard]] BufferView acquire(size_t size);

    /**
     * 归还缓冲区
     * @param buffer 要归还的缓冲区
     */
    void release(BufferView& buffer);

    /**
     * 获取池统计信息
     */
    struct Statistics {
        size_t total_allocations = 0;
        size_t total_deallocations = 0;
        size_t cache_hits = 0;
        size_t cache_misses = 0;
        size_t current_usage = 0;
        size_t peak_usage = 0;

        double hit_rate() const {
            return total_allocations > 0
                ? static_cast<double>(cache_hits) / total_allocations
                : 0.0;
        }
    };

    [[nodiscard]] Statistics get_statistics() const;

    /**
     * 预热池（预先分配所有缓冲区）
     */
    void warmup();

    /**
     * 清理未使用的缓冲区
     */
    void cleanup();

    /**
     * 获取全局实例（单例）
     */
    static BufferPool& instance();

private:
    // 单个大小类的池
    class SizeClassPool {
    public:
        explicit SizeClassPool(size_t buffer_size, size_t initial_capacity);
        ~SizeClassPool();

        [[nodiscard]] void* allocate();
        void deallocate(void* ptr);

        [[nodiscard]] size_t buffer_size() const noexcept { return buffer_size_; }
        [[nodiscard]] size_t capacity() const noexcept { return capacity_; }
        [[nodiscard]] size_t size() const noexcept { return size_; }

        void reserve(size_t additional_capacity);

    private:
        struct Block {
            void* data = nullptr;
            mutable std::atomic<bool> in_use{false};  // mutable 允许在 const 上下文中修改
        };

        // 使用原始数组指针，避免 std::atomic 的移动问题
        Block* blocks_ = nullptr;
        size_t buffer_size_;
        size_t capacity_;
        size_t size_ = 0;
        std::mutex mutex_;

        [[nodiscard]] size_t find_free_block();
        void expand_pool(size_t additional_blocks);
        void cleanup_blocks();
    };

    // 线程本地缓存
    class ThreadLocalCache {
    public:
        static constexpr size_t CACHE_SIZE = 16;

        struct CacheEntry {
            void* ptr = nullptr;
            size_t size_class = 0;

            bool matches(size_t sc) const {
                return ptr != nullptr && size_class == sc;
            }
        };

        std::array<CacheEntry, CACHE_SIZE> cache_;
        std::atomic<size_t> index_{0};

        void* get(size_t size_class);
        void put(void* ptr, size_t size_class);
        void flush();
    };

    Config config_;
    std::unique_ptr<SizeClassPool> pools_[4];
    Statistics stats_;

    static thread_local ThreadLocalCache thread_cache_;
};

/**
 * RAII 缓冲区守卫
 * 自动管理缓冲区的生命周期
 */
class ScopedBuffer {
public:
    explicit ScopedBuffer(size_t size, BufferPool& pool = BufferPool::instance())
        : pool_(pool), buffer_(pool.acquire(size)) {}

    ~ScopedBuffer() {
        pool_.release(buffer_);
    }

    // 禁止拷贝
    ScopedBuffer(const ScopedBuffer&) = delete;
    ScopedBuffer& operator=(const ScopedBuffer&) = delete;

    // 支持移动
    ScopedBuffer(ScopedBuffer&& other) noexcept
        : pool_(other.pool_), buffer_(other.buffer_) {
        other.buffer_ = BufferView{};
    }

    // 禁止移动赋值（引用成员无法重新赋值）
    ScopedBuffer& operator=(ScopedBuffer&& other) = delete;

    [[nodiscard]] const BufferView& get() const noexcept { return buffer_; }
    [[nodiscard]] BufferView& get() noexcept { return buffer_; }

    [[nodiscard]] const uint8_t* data() const noexcept { return buffer_.data(); }
    [[nodiscard]] size_t size() const noexcept { return buffer_.size(); }

private:
    BufferPool& pool_;
    BufferView buffer_;
};

} // namespace protocol_parser::core
