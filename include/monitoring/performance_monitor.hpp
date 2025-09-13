#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <functional>
#include <queue>
#include <condition_variable>
#include <concepts>
#include <span>

namespace ProtocolParser::Monitoring {

// 性能指标类型
enum class MetricType : uint8_t {
    LATENCY,        // 延迟指标
    THROUGHPUT,     // 吞吐量指标
    ERROR_RATE,     // 错误率指标
    RESOURCE_USAGE, // 资源使用率
    CUSTOM          // 自定义指标
};

// 时间窗口类型
enum class TimeWindow : uint32_t {
    SECOND = 1,
    MINUTE = 60,
    HOUR = 3600,
    DAY = 86400
};

// 性能指标数据点
struct MetricDataPoint {
    std::chrono::steady_clock::time_point timestamp;
    double value;
    std::string label;
    MetricType type;
    
    MetricDataPoint(double val, const std::string& lbl = "", MetricType mt = MetricType::CUSTOM)
        : timestamp(std::chrono::steady_clock::now()), value(val), label(lbl), type(mt) {}
};

// 性能统计聚合结果
struct PerformanceStats {
    double min_value{0.0};
    double max_value{0.0};
    double avg_value{0.0};
    double median_value{0.0};
    double p95_value{0.0};       // 95百分位
    double p99_value{0.0};       // 99百分位
    double sum_value{0.0};
    uint64_t count{0};
    double variance{0.0};
    double std_deviation{0.0};
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
    [[nodiscard]] std::chrono::milliseconds duration() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    }
    
    [[nodiscard]] double rate_per_second() const noexcept {
        const auto dur = duration();
        return dur.count() > 0 ? (count * 1000.0) / dur.count() : 0.0;
    }
};

// 实时性能计算器
template<typename T>
requires std::floating_point<T>
class alignas(64) RealTimeCalculator {
public:
    explicit RealTimeCalculator(size_t window_size = 1000) 
        : window_size_(window_size), values_(window_size) {}
    
    void add_value(T value) noexcept {
        std::lock_guard lock(mutex_);
        
        if (count_ < window_size_) {
            values_[count_] = value;
            count_++;
        } else {
            // 环形缓冲区
            values_[current_index_] = value;
            current_index_ = (current_index_ + 1) % window_size_;
        }
        
        update_stats();
    }
    
    [[nodiscard]] PerformanceStats get_stats() const noexcept {
        std::lock_guard lock(mutex_);
        return current_stats_;
    }
    
    void reset() noexcept {
        std::lock_guard lock(mutex_);
        count_ = 0;
        current_index_ = 0;
        current_stats_ = PerformanceStats{};
    }

private:
    void update_stats() noexcept {
        if (count_ == 0) return;
        
        const size_t actual_count = std::min(count_, window_size_);
        std::vector<T> sorted_values(actual_count);
        
        for (size_t i = 0; i < actual_count; ++i) {
            sorted_values[i] = values_[i];
        }
        
        std::sort(sorted_values.begin(), sorted_values.end());
        
        current_stats_.count = actual_count;
        current_stats_.min_value = sorted_values.front();
        current_stats_.max_value = sorted_values.back();
        current_stats_.median_value = sorted_values[actual_count / 2];
        current_stats_.p95_value = sorted_values[static_cast<size_t>(actual_count * 0.95)];
        current_stats_.p99_value = sorted_values[static_cast<size_t>(actual_count * 0.99)];
        
        // 计算平均值和方差
        T sum = 0;
        for (size_t i = 0; i < actual_count; ++i) {
            sum += sorted_values[i];
        }
        current_stats_.avg_value = static_cast<double>(sum) / actual_count;
        current_stats_.sum_value = sum;
        
        T variance_sum = 0;
        for (size_t i = 0; i < actual_count; ++i) {
            T diff = sorted_values[i] - static_cast<T>(current_stats_.avg_value);
            variance_sum += diff * diff;
        }
        current_stats_.variance = static_cast<double>(variance_sum) / actual_count;
        current_stats_.std_deviation = std::sqrt(current_stats_.variance);
    }
    
    const size_t window_size_;
    std::vector<T> values_;
    size_t count_{0};
    size_t current_index_{0};
    PerformanceStats current_stats_;
    mutable std::mutex mutex_;
};

// 性能阈值配置
struct PerformanceThreshold {
    std::string metric_name;
    MetricType type;
    double warning_threshold{0.0};
    double critical_threshold{0.0};
    bool enabled{true};
    std::chrono::seconds check_interval{10};
    
    [[nodiscard]] bool is_warning(double value) const noexcept {
        return enabled && value >= warning_threshold;
    }
    
    [[nodiscard]] bool is_critical(double value) const noexcept {
        return enabled && value >= critical_threshold;
    }
};

// 性能告警事件
struct PerformanceAlert {
    enum class Level { INFO, WARNING, CRITICAL, RESOLVED };
    
    Level level{Level::INFO};
    std::string metric_name;
    double current_value{0.0};
    double threshold_value{0.0};
    std::string message;
    std::chrono::steady_clock::time_point timestamp;
    std::string source_component;
    
    PerformanceAlert() : timestamp(std::chrono::steady_clock::now()) {}
};

// 性能监控器主类
class PerformanceMonitor {
public:
    explicit PerformanceMonitor(size_t metric_history_size = 10000);
    ~PerformanceMonitor();

    // 禁用拷贝，启用移动
    PerformanceMonitor(const PerformanceMonitor&) = delete;
    PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;
    PerformanceMonitor(PerformanceMonitor&&) = default;
    PerformanceMonitor& operator=(PerformanceMonitor&&) = default;

    // 核心指标记录接口
    void record_parse_time(const std::string& protocol, std::chrono::nanoseconds duration) noexcept;
    void record_throughput(const std::string& protocol, double packets_per_second) noexcept;
    void record_memory_usage(size_t bytes_used) noexcept;
    void record_cpu_usage(double cpu_percentage) noexcept;
    void record_error_rate(const std::string& protocol, double error_percentage) noexcept;
    void record_custom_metric(const std::string& name, double value, MetricType type = MetricType::CUSTOM) noexcept;

    // 批量记录接口
    void record_batch_metrics(std::span<const MetricDataPoint> metrics) noexcept;

    // 性能统计查询
    [[nodiscard]] std::optional<PerformanceStats> get_protocol_parse_stats(const std::string& protocol, TimeWindow window = TimeWindow::MINUTE) const noexcept;
    [[nodiscard]] std::optional<PerformanceStats> get_throughput_stats(const std::string& protocol, TimeWindow window = TimeWindow::MINUTE) const noexcept;
    [[nodiscard]] std::optional<PerformanceStats> get_system_stats(TimeWindow window = TimeWindow::MINUTE) const noexcept;
    [[nodiscard]] std::optional<PerformanceStats> get_custom_metric_stats(const std::string& name, TimeWindow window = TimeWindow::MINUTE) const noexcept;

    // 实时性能指标
    struct RealTimeMetrics {
        double current_parse_rate{0.0};        // 当前解析速率 (packets/sec)
        double current_throughput{0.0};        // 当前吞吐量 (MB/sec)
        double current_memory_usage{0.0};      // 当前内存使用 (MB)
        double current_cpu_usage{0.0};         // 当前CPU使用率 (%)
        double average_parse_time{0.0};        // 平均解析时间 (microseconds)
        double error_rate{0.0};                // 错误率 (%)
        size_t active_protocols{0};            // 活跃协议数量
        std::chrono::steady_clock::time_point last_update;
    };
    
    [[nodiscard]] RealTimeMetrics get_real_time_metrics() const noexcept;

    // 性能分析报告
    struct PerformanceReport {
        std::unordered_map<std::string, PerformanceStats> protocol_performance;
        PerformanceStats overall_performance;
        std::vector<std::string> performance_bottlenecks;
        std::vector<std::string> optimization_suggestions;
        double overall_efficiency_score{0.0};  // 0-100分
        std::chrono::steady_clock::time_point report_time;
    };
    
    [[nodiscard]] PerformanceReport generate_performance_report(TimeWindow window = TimeWindow::HOUR) const;

    // 阈值管理
    void set_performance_threshold(const PerformanceThreshold& threshold);
    void remove_performance_threshold(const std::string& metric_name);
    [[nodiscard]] std::vector<PerformanceThreshold> get_active_thresholds() const;

    // 告警系统
    using AlertCallback = std::function<void(const PerformanceAlert&)>;
    void set_alert_callback(AlertCallback callback) noexcept;
    void remove_alert_callback() noexcept;
    [[nodiscard]] std::vector<PerformanceAlert> get_recent_alerts(std::chrono::minutes lookback = std::chrono::minutes(10)) const;

    // 性能基准测试
    struct BenchmarkResult {
        std::string test_name;
        double operations_per_second{0.0};
        std::chrono::nanoseconds avg_operation_time{0};
        std::chrono::nanoseconds min_operation_time{0};
        std::chrono::nanoseconds max_operation_time{0};
        double cpu_utilization{0.0};
        size_t memory_peak_usage{0};
        bool passed{false};
        std::string error_message;
    };
    
    BenchmarkResult run_parse_benchmark(const std::string& protocol, const std::vector<std::vector<uint8_t>>& test_data);
    BenchmarkResult run_throughput_benchmark(size_t packet_count, size_t packet_size);

    // 控制接口
    void start_monitoring() noexcept;
    void stop_monitoring() noexcept;
    void pause_monitoring() noexcept;
    void resume_monitoring() noexcept;
    [[nodiscard]] bool is_monitoring_active() const noexcept;

    // 数据导出
    enum class ExportFormat { JSON, CSV, BINARY, PROMETHEUS };
    [[nodiscard]] std::string export_metrics(ExportFormat format, TimeWindow window = TimeWindow::HOUR) const;
    void export_to_file(const std::string& filename, ExportFormat format, TimeWindow window = TimeWindow::HOUR) const;

    // 配置管理
    struct MonitorConfig {
        size_t max_metric_history{10000};
        std::chrono::seconds metric_retention_time{3600};
        std::chrono::milliseconds alert_check_interval{100};
        bool enable_real_time_stats{true};
        bool enable_automatic_gc{true};
        size_t memory_limit_mb{512};
    };
    
    void configure(const MonitorConfig& config);
    [[nodiscard]] MonitorConfig get_configuration() const noexcept;

private:
    // 内部数据结构
    struct MetricStore {
        std::vector<MetricDataPoint> data_points;
        RealTimeCalculator<double> real_time_calc;
        mutable std::shared_mutex mutex;
        
        MetricStore() : real_time_calc(1000) {}
    };
    
    mutable std::shared_mutex metrics_mutex_;
    std::unordered_map<std::string, std::unique_ptr<MetricStore>> metric_stores_;
    
    // 阈值和告警
    mutable std::shared_mutex thresholds_mutex_;
    std::unordered_map<std::string, PerformanceThreshold> thresholds_;
    std::vector<PerformanceAlert> alert_history_;
    std::atomic<AlertCallback*> alert_callback_{nullptr};
    mutable std::mutex alert_mutex_;
    
    // 监控控制
    std::atomic<bool> monitoring_active_{false};
    std::atomic<bool> monitoring_paused_{false};
    std::unique_ptr<std::thread> background_thread_;
    std::condition_variable monitor_cv_;
    std::mutex monitor_mutex_;
    
    // 配置
    MonitorConfig config_;
    std::atomic<std::chrono::steady_clock::time_point> last_gc_time_;
    
    // 内部方法
    MetricStore& get_or_create_metric_store(const std::string& name);
    void background_monitoring_loop();
    void check_thresholds();
    void trigger_alert(const PerformanceAlert& alert) noexcept;
    void cleanup_old_metrics();
    [[nodiscard]] PerformanceStats calculate_window_stats(const MetricStore& store, TimeWindow window) const;
    [[nodiscard]] std::string format_metrics_json(const std::unordered_map<std::string, PerformanceStats>& stats) const;
    [[nodiscard]] std::string format_metrics_csv(const std::unordered_map<std::string, PerformanceStats>& stats) const;
    [[nodiscard]] std::string format_metrics_prometheus(const std::unordered_map<std::string, PerformanceStats>& stats) const;
    
    // 性能分析算法
    [[nodiscard]] std::vector<std::string> analyze_bottlenecks(const std::unordered_map<std::string, PerformanceStats>& stats) const;
    [[nodiscard]] std::vector<std::string> generate_optimization_suggestions(const std::unordered_map<std::string, PerformanceStats>& stats) const;
    [[nodiscard]] double calculate_efficiency_score(const std::unordered_map<std::string, PerformanceStats>& stats) const;
};

} // namespace ProtocolParser::Monitoring