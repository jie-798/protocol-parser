#pragma once

#include "../core/buffer_view.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <array>

namespace protocol_parser::ai {

// 分类结果
struct ClassificationResult {
    std::string protocol_name;
    double confidence = 0.0;
    std::string classification_method;
    std::unordered_map<std::string, std::string> additional_info;
};

// 简化的协议统计信息
struct ProtocolStats {
    std::vector<double> feature_means;
    size_t sample_count = 0;
};

// 简化的AI协议检测器
class AIProtocolDetector {
public:
    AIProtocolDetector();
    
    // 主要检测方法
    std::vector<ClassificationResult> detect_protocol(
        const protocol_parser::core::BufferView& buffer,
        uint16_t src_port = 0, uint16_t dst_port = 0) const;
    
    // 在线学习
    void update_online_classifier(const std::vector<double>& features, 
                                 const std::string& true_label);
    
    // DGA检测
    bool is_suspicious_domain(const std::string& domain) const;

private:
    // 基础配置
    double confidence_threshold_;
    bool ensemble_enabled_;
    bool dga_detection_enabled_;
    
    // 简化的分类器
    double smoothing_factor_;
    std::unordered_map<std::string, ProtocolStats> protocol_stats_;
    
    // 协议模式和端口映射
    std::unordered_map<std::string, std::vector<std::string>> protocol_patterns_;
    std::unordered_map<uint16_t, std::string> port_mappings_;
    
    // 初始化方法
    void initialize_basic_classifiers();
    void load_basic_signatures();
    
    // 特征提取
    std::vector<double> extract_basic_features(
        const protocol_parser::core::BufferView& buffer,
        uint16_t src_port, uint16_t dst_port) const;
    
    // 分类方法
    ClassificationResult classify_naive_bayes(const std::vector<double>& features) const;
    ClassificationResult classify_by_port(uint16_t src_port, uint16_t dst_port) const;
    ClassificationResult classify_by_patterns(const protocol_parser::core::BufferView& buffer) const;
    
    // 辅助方法
    double calculate_entropy(const protocol_parser::core::BufferView& buffer) const;
    double calculate_ascii_ratio(const protocol_parser::core::BufferView& buffer) const;
    double calculate_string_entropy(const std::string& str) const;
};

} // namespace protocol_parser::ai