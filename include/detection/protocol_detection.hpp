#pragma once

#include "core/buffer_view.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <span>
#include <concepts>
#include <optional>
#include <functional>
#include <array>
#include <regex>
#include <chrono>
#include <mutex>
#include <shared_mutex>

namespace ProtocolParser::Detection {

// 协议识别置信度
enum class ConfidenceLevel : uint8_t {
    VERY_LOW = 0,    // 0-20%
    LOW = 1,         // 21-40%
    MEDIUM = 2,      // 41-60%  
    HIGH = 3,        // 61-80%
    VERY_HIGH = 4    // 81-100%
};

// 协议检测结果
struct DetectionResult {
    std::string protocol_name;
    ConfidenceLevel confidence{ConfidenceLevel::VERY_LOW};
    double confidence_score{0.0};  // 0.0-1.0精确评分
    uint16_t detected_port{0};
    std::string detection_method;  // 检测方法描述
    std::vector<std::string> evidence;  // 检测证据
    size_t bytes_analyzed{0};
    
    [[nodiscard]] bool is_reliable() const noexcept {
        return confidence >= ConfidenceLevel::HIGH;
    }
    
    [[nodiscard]] bool is_certain() const noexcept {
        return confidence == ConfidenceLevel::VERY_HIGH && confidence_score >= 0.9;
    }
};

// 协议签名匹配器
class ProtocolSignature {
public:
    struct SignaturePattern {
        std::vector<uint8_t> pattern;      // 字节模式
        std::vector<uint8_t> mask;         // 掩码，0xFF表示必须匹配
        size_t offset{0};                  // 在数据包中的偏移
        size_t max_search_range{0};       // 最大搜索范围，0表示无限制
        double weight{1.0};                // 权重（0.0-1.0）
        std::string description;           // 模式描述
        
        [[nodiscard]] bool matches(const uint8_t* data, size_t size) const noexcept;
        [[nodiscard]] bool search_matches(const uint8_t* data, size_t size) const noexcept;
    };
    
    std::string protocol_name;
    std::vector<SignaturePattern> patterns;
    std::vector<uint16_t> typical_ports;
    double base_confidence{0.7};
    
    ProtocolSignature() = default;
    explicit ProtocolSignature(std::string name) : protocol_name(std::move(name)) {}
    
    [[nodiscard]] double calculate_match_score(const protocol_parser::core::BufferView& buffer) const noexcept;
};

// 端口基础的检测器
class PortBasedDetector {
public:
    PortBasedDetector();
    
    [[nodiscard]] std::vector<DetectionResult> detect_by_port(uint16_t src_port, uint16_t dst_port) const noexcept;
    
    void add_port_mapping(uint16_t port, const std::string& protocol, double confidence = 0.6);
    void remove_port_mapping(uint16_t port, const std::string& protocol);
    
private:
    std::unordered_map<uint16_t, std::vector<std::pair<std::string, double>>> port_to_protocols_;
    
    void initialize_standard_ports();
};

// 启发式检测器 - 基于统计特征
class HeuristicDetector {
public:
    struct PacketFeatures {
        size_t packet_size{0};
        double entropy{0.0};                    // 数据熵
        std::array<uint8_t, 256> byte_frequency{};  // 字节频率分布
        size_t printable_chars{0};             // 可打印字符数量
        size_t null_bytes{0};                  // 空字节数量
        size_t consecutive_zeros{0};           // 连续零字节
        bool has_common_headers{false};        // 是否有常见头部
        std::vector<std::string> detected_strings;  // 检测到的字符串
    };
    
    [[nodiscard]] PacketFeatures extract_features(const protocol_parser::core::BufferView& buffer) const noexcept;
    [[nodiscard]] std::vector<DetectionResult> detect_by_heuristics(const PacketFeatures& features) const noexcept;
    
private:
    [[nodiscard]] double calculate_entropy(const uint8_t* data, size_t size) const noexcept;
    [[nodiscard]] bool is_likely_text_protocol(const PacketFeatures& features) const noexcept;
    [[nodiscard]] bool is_likely_binary_protocol(const PacketFeatures& features) const noexcept;
    [[nodiscard]] std::vector<std::string> extract_strings(const protocol_parser::core::BufferView& buffer) const;
};

// 深度包检测器 - 状态机和复杂模式匹配
class DeepPacketInspector {
public:
    explicit DeepPacketInspector();
    
    struct ProtocolRule {
        std::string protocol_name;
        std::vector<std::regex> regex_patterns;    // 正则表达式模式
        std::function<bool(const protocol_parser::core::BufferView&)> custom_validator;  // 自定义验证函数
        uint8_t min_packet_count{1};              // 最少需要的数据包数
        size_t state_window_size{5};              // 状态窗口大小
        double confidence_boost{0.3};             // 置信度加成
    };
    
    void add_rule(const ProtocolRule& rule);
    void remove_rule(const std::string& protocol_name);
    
    [[nodiscard]] std::vector<DetectionResult> inspect_deep(const protocol_parser::core::BufferView& buffer) const noexcept;
    
    // 流状态跟踪
    void update_flow_state(const std::string& flow_id, const protocol_parser::core::BufferView& buffer);
    [[nodiscard]] std::vector<DetectionResult> analyze_flow(const std::string& flow_id) const;
    
private:
    std::vector<ProtocolRule> rules_;
    
    // 流状态跟踪
    struct FlowState {
        std::vector<std::vector<uint8_t>> packet_history;
        std::unordered_map<std::string, double> protocol_scores;
        size_t packet_count{0};
        std::chrono::steady_clock::time_point last_update;
    };
    
    mutable std::unordered_map<std::string, FlowState> flow_states_;
    mutable std::mutex flow_mutex_;
    
    void initialize_standard_rules();
    [[nodiscard]] bool match_regex_patterns(const std::vector<std::regex>& patterns, const protocol_parser::core::BufferView& buffer) const noexcept;
};

// 机器学习特征提取器 (为未来ML集成做准备)
class MLFeatureExtractor {
public:
    struct MLFeatures {
        // 统计特征
        std::array<double, 256> byte_frequency_normalized{};
        double entropy{0.0};
        double compression_ratio{0.0};
        
        // 结构特征  
        size_t header_like_patterns{0};
        size_t length_fields_detected{0};
        size_t checksum_like_patterns{0};
        
        // 时序特征
        std::vector<size_t> packet_size_sequence;
        std::vector<double> inter_packet_intervals;
        
        // 内容特征
        size_t ascii_percentage{0};
        size_t binary_patterns{0};
        size_t structured_data_indicators{0};
    };
    
    [[nodiscard]] MLFeatures extract_features(const std::vector<protocol_parser::core::BufferView>& packet_sequence) const noexcept;
    
    // 特征向量转换 (为ML算法准备)
    [[nodiscard]] std::vector<double> to_feature_vector(const MLFeatures& features) const noexcept;
    
private:
    [[nodiscard]] double calculate_compression_ratio(const protocol_parser::core::BufferView& buffer) const noexcept;
    [[nodiscard]] size_t detect_length_fields(const protocol_parser::core::BufferView& buffer) const noexcept;
    [[nodiscard]] size_t detect_checksum_patterns(const protocol_parser::core::BufferView& buffer) const noexcept;
};

// 主协议检测引擎
class ProtocolDetectionEngine {
public:
    explicit ProtocolDetectionEngine();
    ~ProtocolDetectionEngine() = default;

    // 禁用拷贝，启用移动
    ProtocolDetectionEngine(const ProtocolDetectionEngine&) = delete;
    ProtocolDetectionEngine& operator=(const ProtocolDetectionEngine&) = delete;
    ProtocolDetectionEngine(ProtocolDetectionEngine&&) = default;
    ProtocolDetectionEngine& operator=(ProtocolDetectionEngine&&) = default;

    // 主要检测接口
    [[nodiscard]] DetectionResult detect_protocol(const protocol_parser::core::BufferView& buffer) const noexcept;
    [[nodiscard]] DetectionResult detect_protocol_with_ports(const protocol_parser::core::BufferView& buffer, 
                                                           uint16_t src_port, uint16_t dst_port) const noexcept;
    
    // 批量检测
    [[nodiscard]] std::vector<DetectionResult> detect_multiple(std::span<const protocol_parser::core::BufferView> buffers) const noexcept;
    
    // 流级别检测
    [[nodiscard]] DetectionResult detect_flow_protocol(const std::string& flow_id, 
                                                      const std::vector<protocol_parser::core::BufferView>& packets,
                                                      uint16_t src_port, uint16_t dst_port) const;
    
    // 配置和管理
    void add_signature(const ProtocolSignature& signature);
    void remove_signature(const std::string& protocol_name);
    
    void enable_detector(const std::string& detector_name);
    void disable_detector(const std::string& detector_name);
    
    // 检测策略配置
    struct DetectionConfig {
        bool use_port_based{true};
        bool use_signature_based{true};
        bool use_heuristic_based{true};
        bool use_deep_inspection{true};
        bool enable_flow_analysis{false};
        double min_confidence_threshold{0.3};
        size_t max_signatures_per_protocol{10};
        std::chrono::milliseconds detection_timeout{100};
    };
    
    void configure(const DetectionConfig& config);
    [[nodiscard]] DetectionConfig get_configuration() const noexcept;
    
    // 性能和统计
    struct DetectionStatistics {
        uint64_t total_detections{0};
        uint64_t successful_detections{0};
        uint64_t port_based_detections{0};
        uint64_t signature_based_detections{0};
        uint64_t heuristic_detections{0};
        uint64_t deep_inspection_detections{0};
        std::unordered_map<std::string, uint64_t> protocol_detection_count;
        std::chrono::nanoseconds total_detection_time{0};
        std::chrono::nanoseconds avg_detection_time{0};
    };
    
    [[nodiscard]] DetectionStatistics get_statistics() const noexcept;
    void reset_statistics() noexcept;
    
    // 高级功能
    [[nodiscard]] std::vector<std::string> get_supported_protocols() const noexcept;
    [[nodiscard]] std::vector<std::string> suggest_protocols(const protocol_parser::core::BufferView& buffer) const noexcept;
    
    // 调试和诊断
    struct DetectionTrace {
        std::vector<std::string> detection_steps;
        std::vector<std::pair<std::string, double>> scorer_results;
        std::string final_decision_reason;
        std::chrono::nanoseconds detection_duration{0};
    };
    
    [[nodiscard]] std::pair<DetectionResult, DetectionTrace> detect_with_trace(const protocol_parser::core::BufferView& buffer) const;

private:
    // 检测器组件
    std::unique_ptr<PortBasedDetector> port_detector_;
    std::unique_ptr<HeuristicDetector> heuristic_detector_;
    std::unique_ptr<DeepPacketInspector> deep_inspector_;
    std::unique_ptr<MLFeatureExtractor> ml_extractor_;
    
    // 签名数据库
    std::unordered_map<std::string, ProtocolSignature> signatures_;
    mutable std::shared_mutex signatures_mutex_;
    
    // 配置和状态
    DetectionConfig config_;
    mutable DetectionStatistics statistics_;
    mutable std::mutex stats_mutex_;
    
    // 内部方法
    [[nodiscard]] DetectionResult combine_results(const std::vector<DetectionResult>& results) const noexcept;
    [[nodiscard]] double calculate_combined_confidence(const std::vector<DetectionResult>& results) const noexcept;
    [[nodiscard]] std::string select_best_protocol(const std::vector<DetectionResult>& results) const noexcept;
    
    // 工具方法
    [[nodiscard]] static ConfidenceLevel score_to_confidence_level(double score) noexcept;
    [[nodiscard]] static std::string confidence_level_to_string(ConfidenceLevel level) noexcept;
    
private:
    void update_statistics(const DetectionResult& result, std::chrono::nanoseconds detection_time) const noexcept;
    void initialize_builtin_signatures();
};

// 工具函数
namespace Utils {
    [[nodiscard]] bool is_printable_ascii(uint8_t byte) noexcept;
    [[nodiscard]] bool is_likely_header_field(const uint8_t* data, size_t size) noexcept;
    [[nodiscard]] uint32_t calculate_simple_checksum(const uint8_t* data, size_t size) noexcept;
    [[nodiscard]] std::vector<uint8_t> create_signature_pattern(const std::string& hex_string);
    [[nodiscard]] std::string buffer_to_hex_string(const protocol_parser::core::BufferView& buffer, size_t max_bytes = 32);
}

} // namespace ProtocolParser::Detection