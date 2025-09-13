#include "statistics/traffic_statistics.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <execution>

namespace ProtocolParser::Statistics {

TrafficStatistics::TrafficStatistics(size_t max_protocols)
    : max_protocols_(max_protocols),
      start_time_(std::chrono::steady_clock::now()) {
    protocol_stats_.reserve(max_protocols_);
    last_access_time_.store(start_time_, std::memory_order_relaxed);
}

void TrafficStatistics::record_packet(const std::string& protocol, size_t packet_size) noexcept {
    try {
        auto& stats = get_or_create_stats(protocol);
        stats.packet_count.increment();
        stats.byte_count.increment(packet_size);
        
        total_packet_count_.fetch_add(1, std::memory_order_relaxed);
        total_byte_count_.fetch_add(packet_size, std::memory_order_relaxed);
        
        last_access_time_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
        trigger_callback(protocol, stats);
    } catch (const std::exception&) {
        // 静默处理错误，不影响主流程
    }
}

void TrafficStatistics::record_parse_time(const std::string& protocol, std::chrono::nanoseconds duration) noexcept {
    try {
        auto& stats = get_or_create_stats(protocol);
        const double duration_ms = duration.count() / 1'000'000.0;
        stats.parse_time.observe(duration_ms);
        
        trigger_callback(protocol, stats);
    } catch (const std::exception&) {
        // 静默处理错误
    }
}

void TrafficStatistics::record_error(const std::string& protocol) noexcept {
    try {
        auto& stats = get_or_create_stats(protocol);
        stats.error_count.increment();
        
        total_error_count_.fetch_add(1, std::memory_order_relaxed);
        trigger_callback(protocol, stats);
    } catch (const std::exception&) {
        // 静默处理错误
    }
}

void TrafficStatistics::record_throughput(const std::string& protocol, double mbps) noexcept {
    try {
        auto& stats = get_or_create_stats(protocol);
        stats.throughput.observe(mbps);
        
        trigger_callback(protocol, stats);
    } catch (const std::exception&) {
        // 静默处理错误
    }
}

const ProtocolStats* TrafficStatistics::get_protocol_stats(const std::string& protocol) const noexcept {
    std::shared_lock lock(stats_mutex_);
    const auto it = protocol_stats_.find(protocol);
    return (it != protocol_stats_.end()) ? it->second.get() : nullptr;
}

std::vector<std::pair<std::string, ProtocolStats>> TrafficStatistics::get_all_stats() const {
    std::shared_lock lock(stats_mutex_);
    std::vector<std::pair<std::string, ProtocolStats>> result;
    result.reserve(protocol_stats_.size());
    
    for (const auto& [protocol, stats_ptr] : protocol_stats_) {
        result.emplace_back(protocol, *stats_ptr);
    }
    
    // 按协议名称排序以保证一致性
    std::sort(std::execution::par_unseq, result.begin(), result.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    
    return result;
}

size_t TrafficStatistics::total_protocols() const noexcept {
    std::shared_lock lock(stats_mutex_);
    return protocol_stats_.size();
}

uint64_t TrafficStatistics::total_packets() const noexcept {
    return total_packet_count_.load(std::memory_order_relaxed);
}

uint64_t TrafficStatistics::total_bytes() const noexcept {
    return total_byte_count_.load(std::memory_order_relaxed);
}

TrafficStatistics::PerformanceMetrics TrafficStatistics::get_performance_metrics() const noexcept {
    const auto current_time = std::chrono::steady_clock::now();
    const auto elapsed_seconds = std::chrono::duration<double>(current_time - start_time_).count();
    
    PerformanceMetrics metrics;
    
    if (elapsed_seconds > 0.0) {
        const auto total_packets = total_packet_count_.load(std::memory_order_relaxed);
        const auto total_bytes = total_byte_count_.load(std::memory_order_relaxed);
        const auto total_errors = total_error_count_.load(std::memory_order_relaxed);
        
        metrics.packets_per_second = total_packets / elapsed_seconds;
        metrics.bytes_per_second = total_bytes / elapsed_seconds;
        metrics.average_packet_size = total_packets > 0 ? static_cast<double>(total_bytes) / total_packets : 0.0;
        metrics.error_rate = total_packets > 0 ? static_cast<double>(total_errors) / total_packets : 0.0;
        
        // 计算平均解析时间
        std::shared_lock lock(stats_mutex_);
        metrics.active_protocols = protocol_stats_.size();
        
        double total_parse_time = 0.0;
        uint64_t total_observations = 0;
        
        for (const auto& [_, stats_ptr] : protocol_stats_) {
            const auto count = stats_ptr->parse_time.count();
            if (count > 0) {
                total_parse_time += stats_ptr->parse_time.average() * count;
                total_observations += count;
            }
        }
        
        if (total_observations > 0) {
            metrics.average_parse_time = std::chrono::nanoseconds(
                static_cast<int64_t>((total_parse_time / total_observations) * 1'000'000));
        }
    }
    
    return metrics;
}

TrafficStatistics::TimeWindowStats TrafficStatistics::get_time_window_stats(std::chrono::seconds window_size) const {
    const auto end_time = std::chrono::steady_clock::now();
    const auto start_time = end_time - window_size;
    
    TimeWindowStats window_stats;
    window_stats.start_time = start_time;
    window_stats.end_time = end_time;
    window_stats.performance = get_performance_metrics();
    
    // 当前实现返回所有协议的统计信息
    // 在生产环境中，这里应该维护时间序列数据
    {
        std::shared_lock lock(stats_mutex_);
        for (const auto& [protocol, stats_ptr] : protocol_stats_) {
            window_stats.protocol_stats[protocol] = *stats_ptr;
        }
    }
    
    return window_stats;
}

void TrafficStatistics::reset_all_stats() noexcept {
    std::unique_lock lock(stats_mutex_);
    
    for (auto& [_, stats_ptr] : protocol_stats_) {
        stats_ptr->reset();
    }
    
    total_packet_count_.store(0, std::memory_order_relaxed);
    total_byte_count_.store(0, std::memory_order_relaxed);
    total_error_count_.store(0, std::memory_order_relaxed);
    
    start_time_ = std::chrono::steady_clock::now();
    last_access_time_.store(start_time_, std::memory_order_relaxed);
}

void TrafficStatistics::reset_protocol_stats(const std::string& protocol) noexcept {
    std::shared_lock lock(stats_mutex_);
    const auto it = protocol_stats_.find(protocol);
    if (it != protocol_stats_.end()) {
        it->second->reset();
    }
}

void TrafficStatistics::cleanup_inactive_protocols(std::chrono::seconds inactivity_threshold) {
    const auto cutoff_time = std::chrono::steady_clock::now() - inactivity_threshold;
    
    std::unique_lock lock(stats_mutex_);
    
    auto it = protocol_stats_.begin();
    while (it != protocol_stats_.end()) {
        // 简化版：移除包计数为0的协议
        // 在生产环境中，应该基于最后访问时间
        if (it->second->packet_count.value() == 0) {
            it = protocol_stats_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string TrafficStatistics::export_stats(const ExportFormat& format) const {
    const auto all_stats_vector = get_all_stats();
    std::unordered_map<std::string, ProtocolStats> all_stats;
    
    for (const auto& [protocol, stats] : all_stats_vector) {
        all_stats[protocol] = stats;
    }
    
    switch (format.type) {
        case ExportFormat::JSON:
            return format_json_stats(all_stats);
        case ExportFormat::CSV:
            return format_csv_stats(all_stats);
        case ExportFormat::PROMETHEUS:
            return format_prometheus_stats(all_stats);
        case ExportFormat::BINARY:
            // 简化实现，返回JSON
            return format_json_stats(all_stats);
        default:
            return format_json_stats(all_stats);
    }
}

void TrafficStatistics::export_to_file(const std::string& filename, const ExportFormat& format) const {
    const auto content = export_stats(format);
    std::ofstream file(filename);
    if (file.is_open()) {
        file << content;
    }
}

void TrafficStatistics::set_statistics_callback(StatisticsCallback callback) noexcept {
    std::lock_guard lock(callback_mutex_);
    callback_.store(new StatisticsCallback(std::move(callback)), std::memory_order_relaxed);
}

void TrafficStatistics::remove_statistics_callback() noexcept {
    std::lock_guard lock(callback_mutex_);
    auto* old_callback = callback_.exchange(nullptr, std::memory_order_relaxed);
    delete old_callback;
}

ProtocolStats& TrafficStatistics::get_or_create_stats(const std::string& protocol) {
    std::shared_lock shared_lock(stats_mutex_);
    
    auto it = protocol_stats_.find(protocol);
    if (it != protocol_stats_.end()) {
        return *it->second;
    }
    
    shared_lock.unlock();
    std::unique_lock unique_lock(stats_mutex_);
    
    // 再次检查（双重检查锁定模式）
    it = protocol_stats_.find(protocol);
    if (it != protocol_stats_.end()) {
        return *it->second;
    }
    
    // 检查是否超过最大协议数量
    if (protocol_stats_.size() >= max_protocols_) {
        // 简化处理：抛出异常或返回默认统计
        static ProtocolStats default_stats;
        return default_stats;
    }
    
    auto stats_ptr = std::make_unique<ProtocolStats>();
    auto& stats_ref = *stats_ptr;
    protocol_stats_[protocol] = std::move(stats_ptr);
    
    return stats_ref;
}

void TrafficStatistics::trigger_callback(const std::string& protocol, const ProtocolStats& stats) const noexcept {
    auto* callback_ptr = callback_.load(std::memory_order_relaxed);
    if (callback_ptr != nullptr) {
        try {
            (*callback_ptr)(protocol, stats);
        } catch (const std::exception&) {
            // 静默处理回调异常
        }
    }
}

std::string TrafficStatistics::format_json_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",\n";
    oss << "  \"protocols\": {\n";
    
    bool first = true;
    for (const auto& [protocol, protocol_stats] : stats) {
        if (!first) oss << ",\n";
        first = false;
        
        oss << "    \"" << protocol << "\": {\n";
        oss << "      \"packet_count\": " << protocol_stats.packet_count.value() << ",\n";
        oss << "      \"byte_count\": " << protocol_stats.byte_count.value() << ",\n";
        oss << "      \"error_count\": " << protocol_stats.error_count.value() << ",\n";
        oss << "      \"average_parse_time_ms\": " << std::fixed << std::setprecision(3) 
            << protocol_stats.parse_time.average() << ",\n";
        oss << "      \"average_throughput_mbps\": " << std::fixed << std::setprecision(3) 
            << protocol_stats.throughput.average() << "\n";
        oss << "    }";
    }
    
    oss << "\n  }\n";
    oss << "}";
    
    return oss.str();
}

std::string TrafficStatistics::format_csv_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const {
    std::ostringstream oss;
    oss << "Protocol,PacketCount,ByteCount,ErrorCount,AvgParseTimeMs,AvgThroughputMbps\n";
    
    for (const auto& [protocol, protocol_stats] : stats) {
        oss << protocol << ","
            << protocol_stats.packet_count.value() << ","
            << protocol_stats.byte_count.value() << ","
            << protocol_stats.error_count.value() << ","
            << std::fixed << std::setprecision(3) << protocol_stats.parse_time.average() << ","
            << std::fixed << std::setprecision(3) << protocol_stats.throughput.average() << "\n";
    }
    
    return oss.str();
}

std::string TrafficStatistics::format_prometheus_stats(const std::unordered_map<std::string, ProtocolStats>& stats) const {
    std::ostringstream oss;
    
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    for (const auto& [protocol, protocol_stats] : stats) {
        oss << "protocol_packet_count{protocol=\"" << protocol << "\"} " 
            << protocol_stats.packet_count.value() << " " << timestamp << "\n";
        oss << "protocol_byte_count{protocol=\"" << protocol << "\"} " 
            << protocol_stats.byte_count.value() << " " << timestamp << "\n";
        oss << "protocol_error_count{protocol=\"" << protocol << "\"} " 
            << protocol_stats.error_count.value() << " " << timestamp << "\n";
        oss << "protocol_avg_parse_time_ms{protocol=\"" << protocol << "\"} " 
            << std::fixed << std::setprecision(3) << protocol_stats.parse_time.average() 
            << " " << timestamp << "\n";
        oss << "protocol_avg_throughput_mbps{protocol=\"" << protocol << "\"} " 
            << std::fixed << std::setprecision(3) << protocol_stats.throughput.average() 
            << " " << timestamp << "\n";
    }
    
    return oss.str();
}

} // namespace ProtocolParser::Statistics