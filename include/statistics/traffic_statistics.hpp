#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <concepts>
#include <cstdint>

namespace ProtocolParser::Statistics {

// 时间戳类型概念
template<typename T>
concept TimestampType = std::integral<T> || std::floating_point<T>;

// 度量值类型
enum class MetricType : uint8_t {
    COUNTER,          // 计数器：只增不减
    GAUGE,            // 测量值：可增可减
    HISTOGRAM,        // 直方图：分布统计
    SUMMARY,          // 摘要：百分位统计
    RATE              // 速率：时间导数
};

// 原子度量值类 - 高性能无锁设计
class alignas(64) AtomicMetric {
public:
    explicit constexpr AtomicMetric(MetricType type = MetricType::COUNTER) noexcept 
        : type_(type), value_(0), count_(0), sum_squares_(0) {}

    // 原子操作 - 高性能实现
    void increment(uint64_t delta = 1) noexcept {
        value_.fetch_add(delta, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
    }
    
    void decrement(uint64_t delta = 1) noexcept {
        value_.fetch_sub(delta, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
    }
    
    void set(uint64_t new_value) noexcept {
        value_.store(new_value, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
    }
    
    void observe(double observation) noexcept {
        const auto int_obs = static_cast<uint64_t>(observation * 1000); // 微秒精度
        value_.fetch_add(int_obs, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
        
        // 计算平方和用于方差计算
        const auto squared = static_cast<uint64_t>(observation * observation * 1000000);
        sum_squares_.fetch_add(squared, std::memory_order_relaxed);
    }

    // 高性能读取操作
    [[nodiscard]] uint64_t value() const noexcept {
        return value_.load(std::memory_order_relaxed);
    }
    
    [[nodiscard]] uint64_t count() const noexcept {
        return count_.load(std::memory_order_relaxed);
    }
    
    [[nodiscard]] double average() const noexcept {
        const auto c = count();
        return c > 0 ? static_cast<double>(value()) / (c * 1000.0) : 0.0;
    }
    
    [[nodiscard]] double variance() const noexcept {
        const auto c = count();
        if (c <= 1) return 0.0;
        
        const auto mean = average();
        const auto sum_sq = static_cast<double>(sum_squares_.load(std::memory_order_relaxed)) / 1000000.0;
        return (sum_sq / c) - (mean * mean);
    }
    
    [[nodiscard]] MetricType type() const noexcept { return type_; }

    void reset() noexcept {
        value_.store(0, std::memory_order_relaxed);
        count_.store(0, std::memory_order_relaxed);
        sum_squares_.store(0, std::memory_order_relaxed);
    }

private:
    const MetricType type_;
    std::atomic<uint64_t> value_;       // 主要值
    std::atomic<uint64_t> count_;       // 观察次数
    std::atomic<uint64_t> sum_squares_; // 平方和（用于方差计算）
};

// 协议统计信息
struct ProtocolStats {
    AtomicMetric packet_count{MetricType::COUNTER};
    AtomicMetric byte_count{MetricType::COUNTER};
    AtomicMetric error_count{MetricType::COUNTER};
    AtomicMetric parse_time{MetricType::HISTOGRAM};
    AtomicMetric throughput{MetricType::RATE};
    
    void reset() noexcept {
        packet_count.reset();
        byte_count.reset();
        error_count.reset();
        parse_time.reset();
        throughput.reset();
    }
};

// 流量统计引擎
class TrafficStatistics {
public:
    explicit TrafficStatistics(size_t max_protocols = 256);
    ~TrafficStatistics() = default;

    // 禁用拷贝，启用移动
    TrafficStatistics(const TrafficStatistics&) = delete;
    TrafficStatistics& operator=(const TrafficStatistics&) = delete;
    TrafficStatistics(TrafficStatistics&&) = default;
    TrafficStatistics& operator=(TrafficStatistics&&) = default;

    // 统计记录接口
    void record_packet(const std::string& protocol, size_t packet_size) noexcept;
    void record_parse_time(const std::string& protocol, std::chrono::nanoseconds duration) noexcept;
    void record_error(const std::string& protocol) noexcept;
    void record_throughput(const std::string& protocol, double mbps) noexcept;

    // 批量统计接口 - 高性能
    template<TimestampType T>
    void record_batch(std::span<const std::pair<std::string, size_t>> packets, 
                     std::chrono::time_point<std::chrono::high_resolution_clock, std::chrono::duration<T>> timestamp) noexcept;

    // 查询接口
    [[nodiscard]] const ProtocolStats* get_protocol_stats(const std::string& protocol) const noexcept;
    [[nodiscard]] std::vector<std::pair<std::string, ProtocolStats>> get_all_stats() const;
    [[nodiscard]] size_t total_protocols() const noexcept;
    [[nodiscard]] uint64_t total_packets() const noexcept;
    [[nodiscard]] uint64_t total_bytes() const noexcept;

    // 性能分析
    struct PerformanceMetrics {
        double packets_per_second{0.0};
        double bytes_per_second{0.0};
        double average_packet_size{0.0};
        double error_rate{0.0};
        std::chrono::nanoseconds average_parse_time{0};
        size_t active_protocols{0};
    };
    
    [[nodiscard]] PerformanceMetrics get_performance_metrics() const noexcept;

    // 时间窗口统计
    struct TimeWindowStats {
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        std::unordered_map<std::string, ProtocolStats> protocol_stats;
        PerformanceMetrics performance;
    };
    
    [[nodiscard]] TimeWindowStats get_time_window_stats(std::chrono::seconds window_size) const;

    // 重置和清理
    void reset_all_stats() noexcept;
    void reset_protocol_stats(const std::string& protocol) noexcept;
    void cleanup_inactive_protocols(std::chrono::seconds inactivity_threshold);

    // 导出功能
    struct ExportFormat {
        enum Type { JSON, CSV, BINARY, PROMETHEUS } type;
        bool include_timestamps{true};
        bool include_metadata{true};
        bool compress{false};
    };
    
    [[nodiscard]] std::string export_stats(const ExportFormat& format) const;
    void export_to_file(const std::string& filename, const ExportFormat& format) const;

    // 实时监控钩子
    using StatisticsCallback = std::function<void(const std::string&, const ProtocolStats&)>;
    void set_statistics_callback(StatisticsCallback callback) noexcept;
    void remove_statistics_callback() noexcept;

private:
    // 内部数据结构
    mutable std::shared_mutex stats_mutex_;
    std::unordered_map<std::string, std::unique_ptr<ProtocolStats>> protocol_stats_;
    
    // 性能优化成员
    const size_t max_protocols_;
    std::atomic<uint64_t> total_packet_count_{0};
    std::atomic<uint64_t> total_byte_count_{0};
    std::atomic<uint64_t> total_error_count_{0};
    
    // 时间跟踪
    std::chrono::steady_clock::time_point start_time_;
    mutable std::atomic<std::chrono::steady_clock::time_point> last_access_time_;
    
    // 回调机制
    std::atomic<StatisticsCallback*> callback_{nullptr};
    mutable std::mutex callback_mutex_;

    // 内部辅助方法
    ProtocolStats& get_or_create_stats(const std::string& protocol);
    void trigger_callback(const std::string& protocol, const ProtocolStats& stats) const noexcept;
    [[nodiscard]] std::string format_json_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const;
    [[nodiscard]] std::string format_csv_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const;
    [[nodiscard]] std::string format_prometheus_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const;
};

// 模板实现
template<TimestampType T>
void TrafficStatistics::record_batch(
    std::span<const std::pair<std::string, size_t>> packets,
    std::chrono::time_point<std::chrono::high_resolution_clock, std::chrono::duration<T>> timestamp) noexcept {
    
    const auto batch_start = std::chrono::high_resolution_clock::now();
    
    // 批量处理以提高性能
    std::unordered_map<std::string, std::pair<size_t, size_t>> batch_stats; // protocol -> {packet_count, byte_count}
    
    for (const auto& [protocol, size] : packets) {
        auto& [count, bytes] = batch_stats[protocol];
        ++count;
        bytes += size;
    }
    
    // 原子批量更新
    {
        std::shared_lock lock(stats_mutex_);
        for (const auto& [protocol, stats_pair] : batch_stats) {
            auto& proto_stats = get_or_create_stats(protocol);
            proto_stats.packet_count.increment(stats_pair.first);
            proto_stats.byte_count.increment(stats_pair.second);
            
            total_packet_count_.fetch_add(stats_pair.first, std::memory_order_relaxed);
            total_byte_count_.fetch_add(stats_pair.second, std::memory_order_relaxed);
        }
    }
    
    const auto batch_duration = std::chrono::high_resolution_clock::now() - batch_start;
    
    // 记录批处理性能
    for (const auto& [protocol, _] : batch_stats) {
        record_parse_time(protocol, std::chrono::duration_cast<std::chrono::nanoseconds>(batch_duration));
    }
}

} // namespace ProtocolParser::Statistics