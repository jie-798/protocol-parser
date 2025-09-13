#include "monitoring/performance_monitor.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <chrono>

namespace ProtocolParser::Monitoring {

PerformanceMonitor::PerformanceMonitor(size_t metric_history_size) 
    : config_{.max_metric_history = metric_history_size} {
    
    last_gc_time_.store(std::chrono::steady_clock::now());
}

PerformanceMonitor::~PerformanceMonitor() {
    stop_monitoring();
}

void PerformanceMonitor::record_parse_time(const std::string& protocol, std::chrono::nanoseconds duration) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("parse_time_" + protocol);
        std::unique_lock lock(store.mutex);
        
        MetricDataPoint data_point(
            static_cast<double>(duration.count()) / 1000.0, // 转换为微秒
            protocol,
            MetricType::LATENCY
        );
        
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(data_point.value);
        
        // 限制历史数据大小
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常，避免影响主要业务逻辑
    }
}

void PerformanceMonitor::record_throughput(const std::string& protocol, double packets_per_second) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("throughput_" + protocol);
        std::unique_lock lock(store.mutex);
        
        MetricDataPoint data_point(packets_per_second, protocol, MetricType::THROUGHPUT);
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(packets_per_second);
        
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常
    }
}

void PerformanceMonitor::record_memory_usage(size_t bytes_used) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("memory_usage");
        std::unique_lock lock(store.mutex);
        
        double mb_used = static_cast<double>(bytes_used) / (1024.0 * 1024.0);
        MetricDataPoint data_point(mb_used, "system", MetricType::RESOURCE_USAGE);
        
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(mb_used);
        
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常
    }
}

void PerformanceMonitor::record_cpu_usage(double cpu_percentage) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("cpu_usage");
        std::unique_lock lock(store.mutex);
        
        MetricDataPoint data_point(cpu_percentage, "system", MetricType::RESOURCE_USAGE);
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(cpu_percentage);
        
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常
    }
}

void PerformanceMonitor::record_error_rate(const std::string& protocol, double error_percentage) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("error_rate_" + protocol);
        std::unique_lock lock(store.mutex);
        
        MetricDataPoint data_point(error_percentage, protocol, MetricType::ERROR_RATE);
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(error_percentage);
        
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常
    }
}

void PerformanceMonitor::record_custom_metric(const std::string& name, double value, MetricType type) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    try {
        auto& store = get_or_create_metric_store("custom_" + name);
        std::unique_lock lock(store.mutex);
        
        MetricDataPoint data_point(value, name, type);
        store.data_points.emplace_back(data_point);
        store.real_time_calc.add_value(value);
        
        if (store.data_points.size() > config_.max_metric_history) {
            store.data_points.erase(store.data_points.begin());
        }
    } catch (...) {
        // 静默忽略异常
    }
}

void PerformanceMonitor::record_batch_metrics(std::span<const MetricDataPoint> metrics) noexcept {
    if (!monitoring_active_.load() || monitoring_paused_.load()) return;
    
    for (const auto& metric : metrics) {
        record_custom_metric(metric.label, metric.value, metric.type);
    }
}

std::optional<PerformanceStats> PerformanceMonitor::get_protocol_parse_stats(
    const std::string& protocol, TimeWindow window) const noexcept {
    
    try {
        std::shared_lock metrics_lock(metrics_mutex_);
        auto it = metric_stores_.find("parse_time_" + protocol);
        if (it == metric_stores_.end()) {
            return std::nullopt;
        }
        
        return calculate_window_stats(*it->second, window);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<PerformanceStats> PerformanceMonitor::get_throughput_stats(
    const std::string& protocol, TimeWindow window) const noexcept {
    
    try {
        std::shared_lock metrics_lock(metrics_mutex_);
        auto it = metric_stores_.find("throughput_" + protocol);
        if (it == metric_stores_.end()) {
            return std::nullopt;
        }
        
        return calculate_window_stats(*it->second, window);
    } catch (...) {
        return std::nullopt;
    }
}

PerformanceMonitor::RealTimeMetrics PerformanceMonitor::get_real_time_metrics() const noexcept {
    RealTimeMetrics metrics;
    metrics.last_update = std::chrono::steady_clock::now();
    
    try {
        std::shared_lock metrics_lock(metrics_mutex_);
        
        // 计算总解析速率
        double total_parse_rate = 0.0;
        double total_throughput = 0.0;
        double total_parse_time = 0.0;
        double total_error_rate = 0.0;
        size_t parse_time_count = 0;
        size_t error_rate_count = 0;
        
        for (const auto& [name, store] : metric_stores_) {
            std::shared_lock store_lock(store->mutex);
            auto stats = store->real_time_calc.get_stats();
            
            if (name.starts_with("throughput_")) {
                total_throughput += stats.avg_value;
                metrics.active_protocols++;
            } else if (name.starts_with("parse_time_")) {
                if (stats.count > 0) {
                    total_parse_time += stats.avg_value;
                    parse_time_count++;
                }
            } else if (name.starts_with("error_rate_")) {
                if (stats.count > 0) {
                    total_error_rate += stats.avg_value;
                    error_rate_count++;
                }
            } else if (name == "memory_usage") {
                metrics.current_memory_usage = stats.avg_value;
            } else if (name == "cpu_usage") {
                metrics.current_cpu_usage = stats.avg_value;
            }
        }
        
        metrics.current_throughput = total_throughput;
        if (parse_time_count > 0) {
            metrics.average_parse_time = total_parse_time / parse_time_count;
        }
        if (error_rate_count > 0) {
            metrics.error_rate = total_error_rate / error_rate_count;
        }
        
        // 根据吞吐量估算解析速率
        metrics.current_parse_rate = total_throughput;
        
    } catch (...) {
        // 返回默认值
    }
    
    return metrics;
}

PerformanceMonitor::PerformanceReport PerformanceMonitor::generate_performance_report(TimeWindow window) const {
    PerformanceReport report;
    report.report_time = std::chrono::steady_clock::now();
    
    try {
        std::unordered_map<std::string, PerformanceStats> all_stats;
        
        {
            std::shared_lock metrics_lock(metrics_mutex_);
            
            for (const auto& [name, store] : metric_stores_) {
                auto stats = calculate_window_stats(*store, window);
                all_stats[name] = stats;
                
                // 提取协议性能统计
                if (name.starts_with("parse_time_") || name.starts_with("throughput_")) {
                    size_t underscore_pos = name.find('_');
                    if (underscore_pos != std::string::npos) {
                        std::string protocol = name.substr(underscore_pos + 1);
                        if (report.protocol_performance.find(protocol) == report.protocol_performance.end()) {
                            report.protocol_performance[protocol] = stats;
                        }
                    }
                }
            }
        }
        
        // 计算整体性能
        if (!all_stats.empty()) {
            double total_avg = 0.0;
            uint64_t total_count = 0;
            
            for (const auto& [name, stats] : all_stats) {
                total_avg += stats.avg_value * stats.count;
                total_count += stats.count;
            }
            
            if (total_count > 0) {
                report.overall_performance.avg_value = total_avg / total_count;
                report.overall_performance.count = total_count;
            }
        }
        
        // 分析性能瓶颈
        report.performance_bottlenecks = analyze_bottlenecks(all_stats);
        
        // 生成优化建议
        report.optimization_suggestions = generate_optimization_suggestions(all_stats);
        
        // 计算效率评分
        report.overall_efficiency_score = calculate_efficiency_score(all_stats);
        
    } catch (...) {
        // 返回默认报告
    }
    
    return report;
}

void PerformanceMonitor::start_monitoring() noexcept {
    bool expected = false;
    if (monitoring_active_.compare_exchange_strong(expected, true)) {
        monitoring_paused_.store(false);
        
        // 启动后台监控线程
        background_thread_ = std::make_unique<std::thread>(&PerformanceMonitor::background_monitoring_loop, this);
    }
}

void PerformanceMonitor::stop_monitoring() noexcept {
    monitoring_active_.store(false);
    
    if (background_thread_ && background_thread_->joinable()) {
        monitor_cv_.notify_all();
        background_thread_->join();
        background_thread_.reset();
    }
}

void PerformanceMonitor::pause_monitoring() noexcept {
    monitoring_paused_.store(true);
}

void PerformanceMonitor::resume_monitoring() noexcept {
    monitoring_paused_.store(false);
}

bool PerformanceMonitor::is_monitoring_active() const noexcept {
    return monitoring_active_.load() && !monitoring_paused_.load();
}

std::string PerformanceMonitor::export_metrics(ExportFormat format, TimeWindow window) const {
    try {
        std::unordered_map<std::string, PerformanceStats> stats;
        
        {
            std::shared_lock metrics_lock(metrics_mutex_);
            for (const auto& [name, store] : metric_stores_) {
                stats[name] = calculate_window_stats(*store, window);
            }
        }
        
        switch (format) {
            case ExportFormat::JSON:
                return format_metrics_json(stats);
            case ExportFormat::CSV:
                return format_metrics_csv(stats);
            case ExportFormat::PROMETHEUS:
                return format_metrics_prometheus(stats);
            default:
                return "{}";
        }
    } catch (...) {
        return "{}";
    }
}

PerformanceMonitor::MetricStore& PerformanceMonitor::get_or_create_metric_store(const std::string& name) {
    std::unique_lock lock(metrics_mutex_);
    
    auto it = metric_stores_.find(name);
    if (it == metric_stores_.end()) {
        auto [iter, inserted] = metric_stores_.emplace(name, std::make_unique<MetricStore>());
        return *iter->second;
    }
    
    return *it->second;
}

void PerformanceMonitor::background_monitoring_loop() {
    while (monitoring_active_.load()) {
        try {
            // 检查阈值
            if (config_.enable_real_time_stats) {
                check_thresholds();
            }
            
            // 自动垃圾回收
            if (config_.enable_automatic_gc) {
                auto now = std::chrono::steady_clock::now();
                auto last_gc = last_gc_time_.load();
                
                if (now - last_gc > std::chrono::minutes(5)) {
                    cleanup_old_metrics();
                    last_gc_time_.store(now);
                }
            }
            
            // 等待下次检查
            std::unique_lock lock(monitor_mutex_);
            monitor_cv_.wait_for(lock, config_.alert_check_interval);
            
        } catch (...) {
            // 继续运行，避免监控线程崩溃
        }
    }
}

void PerformanceMonitor::check_thresholds() {
    std::shared_lock thresholds_lock(thresholds_mutex_);
    
    for (const auto& [metric_name, threshold] : thresholds_) {
        if (!threshold.enabled) continue;
        
        try {
            std::shared_lock metrics_lock(metrics_mutex_);
            auto it = metric_stores_.find(metric_name);
            if (it == metric_stores_.end()) continue;
            
            std::shared_lock store_lock(it->second->mutex);
            auto stats = it->second->real_time_calc.get_stats();
            
            if (threshold.is_critical(stats.avg_value)) {
                PerformanceAlert alert;
                alert.level = PerformanceAlert::Level::CRITICAL;
                alert.metric_name = metric_name;
                alert.current_value = stats.avg_value;
                alert.threshold_value = threshold.critical_threshold;
                alert.message = "Critical threshold exceeded for " + metric_name;
                
                trigger_alert(alert);
            } else if (threshold.is_warning(stats.avg_value)) {
                PerformanceAlert alert;
                alert.level = PerformanceAlert::Level::WARNING;
                alert.metric_name = metric_name;
                alert.current_value = stats.avg_value;
                alert.threshold_value = threshold.warning_threshold;
                alert.message = "Warning threshold exceeded for " + metric_name;
                
                trigger_alert(alert);
            }
        } catch (...) {
            // 继续检查其他阈值
        }
    }
}

void PerformanceMonitor::trigger_alert(const PerformanceAlert& alert) noexcept {
    try {
        {
            std::lock_guard lock(alert_mutex_);
            alert_history_.push_back(alert);
            
            // 限制告警历史大小
            if (alert_history_.size() > 1000) {
                alert_history_.erase(alert_history_.begin());
            }
        }
        
        // 调用回调函数
        auto callback = alert_callback_.load();
        if (callback && *callback) {
            (*callback)(alert);
        }
    } catch (...) {
        // 静默忽略异常
    }
}

PerformanceStats PerformanceMonitor::calculate_window_stats(const MetricStore& store, TimeWindow window) const {
    std::shared_lock lock(store.mutex);
    
    if (store.data_points.empty()) {
        return PerformanceStats{};
    }
    
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::seconds(static_cast<uint32_t>(window));
    
    std::vector<double> window_values;
    for (const auto& point : store.data_points) {
        if (point.timestamp >= window_start) {
            window_values.push_back(point.value);
        }
    }
    
    if (window_values.empty()) {
        return PerformanceStats{};
    }
    
    std::sort(window_values.begin(), window_values.end());
    
    PerformanceStats stats;
    stats.count = window_values.size();
    stats.min_value = window_values.front();
    stats.max_value = window_values.back();
    stats.median_value = window_values[stats.count / 2];
    
    if (stats.count > 1) {
        stats.p95_value = window_values[static_cast<size_t>(stats.count * 0.95)];
        stats.p99_value = window_values[static_cast<size_t>(stats.count * 0.99)];
    } else {
        stats.p95_value = stats.max_value;
        stats.p99_value = stats.max_value;
    }
    
    // 计算平均值和方差
    stats.sum_value = 0.0;
    for (double value : window_values) {
        stats.sum_value += value;
    }
    stats.avg_value = stats.sum_value / stats.count;
    
    double variance_sum = 0.0;
    for (double value : window_values) {
        double diff = value - stats.avg_value;
        variance_sum += diff * diff;
    }
    stats.variance = variance_sum / stats.count;
    stats.std_deviation = std::sqrt(stats.variance);
    
    stats.start_time = window_start;
    stats.end_time = now;
    
    return stats;
}

std::string PerformanceMonitor::format_metrics_json(const std::unordered_map<std::string, PerformanceStats>& stats) const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"timestamp\": \"" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << "\",\n";
    json << "  \"metrics\": {\n";
    
    bool first = true;
    for (const auto& [name, stat] : stats) {
        if (!first) json << ",\n";
        first = false;
        
        json << "    \"" << name << "\": {\n";
        json << "      \"count\": " << stat.count << ",\n";
        json << "      \"avg\": " << std::fixed << std::setprecision(2) << stat.avg_value << ",\n";
        json << "      \"min\": " << stat.min_value << ",\n";
        json << "      \"max\": " << stat.max_value << ",\n";
        json << "      \"p95\": " << stat.p95_value << ",\n";
        json << "      \"p99\": " << stat.p99_value << "\n";
        json << "    }";
    }
    
    json << "\n  }\n}";
    return json.str();
}

std::vector<std::string> PerformanceMonitor::analyze_bottlenecks(
    const std::unordered_map<std::string, PerformanceStats>& stats) const {
    
    std::vector<std::string> bottlenecks;
    
    for (const auto& [name, stat] : stats) {
        if (name.starts_with("parse_time_") && stat.avg_value > 1000.0) { // > 1ms
            bottlenecks.push_back("High parse time for " + name.substr(11));
        }
        if (name.starts_with("throughput_") && stat.avg_value < 1000.0) { // < 1000 pps
            bottlenecks.push_back("Low throughput for " + name.substr(11));
        }
        if (name == "memory_usage" && stat.avg_value > 512.0) { // > 512MB
            bottlenecks.push_back("High memory usage");
        }
        if (name == "cpu_usage" && stat.avg_value > 80.0) { // > 80%
            bottlenecks.push_back("High CPU usage");
        }
    }
    
    return bottlenecks;
}

std::vector<std::string> PerformanceMonitor::generate_optimization_suggestions(
    const std::unordered_map<std::string, PerformanceStats>& stats) const {
    
    std::vector<std::string> suggestions;
    
    for (const auto& [name, stat] : stats) {
        if (name.starts_with("parse_time_") && stat.avg_value > 500.0) {
            suggestions.push_back("Consider optimizing " + name.substr(11) + " parser implementation");
        }
        if (name.starts_with("error_rate_") && stat.avg_value > 5.0) {
            suggestions.push_back("High error rate for " + name.substr(11) + " - check input validation");
        }
    }
    
    if (suggestions.empty()) {
        suggestions.push_back("Performance is within acceptable ranges");
    }
    
    return suggestions;
}

double PerformanceMonitor::calculate_efficiency_score(
    const std::unordered_map<std::string, PerformanceStats>& stats) const {
    
    double score = 100.0;
    
    for (const auto& [name, stat] : stats) {
        if (name.starts_with("parse_time_")) {
            if (stat.avg_value > 1000.0) score -= 10.0; // 解析时间过长
        }
        if (name.starts_with("error_rate_")) {
            score -= stat.avg_value; // 错误率直接扣分
        }
        if (name == "memory_usage" && stat.avg_value > 512.0) {
            score -= 5.0; // 内存使用过高
        }
        if (name == "cpu_usage" && stat.avg_value > 80.0) {
            score -= 10.0; // CPU使用过高
        }
    }
    
    return std::max(0.0, score);
}

void PerformanceMonitor::cleanup_old_metrics() {
    auto cutoff_time = std::chrono::steady_clock::now() - config_.metric_retention_time;
    
    std::unique_lock metrics_lock(metrics_mutex_);
    
    for (auto& [name, store] : metric_stores_) {
        std::unique_lock store_lock(store->mutex);
        
        auto it = std::remove_if(store->data_points.begin(), store->data_points.end(),
            [cutoff_time](const MetricDataPoint& point) {
                return point.timestamp < cutoff_time;
            });
        
        store->data_points.erase(it, store->data_points.end());
    }
}

} // namespace ProtocolParser::Monitoring