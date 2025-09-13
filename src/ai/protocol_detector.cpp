#include "ai/protocol_detector.hpp"
#include <algorithm>
#include <cmath>
#include <random>
#include <sstream>
#include <numeric>

namespace protocol_parser::ai {

AIProtocolDetector::AIProtocolDetector()
    : confidence_threshold_(0.7)
    , ensemble_enabled_(true)
    , dga_detection_enabled_(true) {
    
    initialize_basic_classifiers();
    load_basic_signatures();
}

std::vector<ClassificationResult> AIProtocolDetector::detect_protocol(
    const protocol_parser::core::BufferView& buffer,
    uint16_t src_port, uint16_t dst_port) const {
    
    std::vector<ClassificationResult> results;
    
    // 提取基础特征
    auto features = extract_basic_features(buffer, src_port, dst_port);
    
    // 使用朴素贝叶斯分类
    auto nb_result = classify_naive_bayes(features);
    if (nb_result.confidence >= confidence_threshold_) {
        results.push_back(nb_result);
    }
    
    // 端口特征检测
    auto port_result = classify_by_port(src_port, dst_port);
    if (port_result.confidence >= confidence_threshold_) {
        results.push_back(port_result);
    }
    
    // 模式匹配
    auto pattern_result = classify_by_patterns(buffer);
    if (pattern_result.confidence >= confidence_threshold_) {
        results.push_back(pattern_result);
    }
    
    // DGA检测（简化版）
    if (dga_detection_enabled_) {
        std::string payload(reinterpret_cast<const char*>(buffer.data()), 
                          std::min(buffer.size(), size_t(128)));
        if (is_suspicious_domain(payload)) {
            ClassificationResult dga_result;
            dga_result.protocol_name = "DGA_DETECTED";
            dga_result.confidence = 0.85;
            dga_result.classification_method = "DGA_DETECTION";
            results.push_back(dga_result);
        }
    }
    
    // 按置信度排序
    std::sort(results.begin(), results.end(),
        [](const ClassificationResult& a, const ClassificationResult& b) {
            return a.confidence > b.confidence;
        });
    
    return results;
}

bool AIProtocolDetector::is_suspicious_domain(const std::string& domain) const {
    if (domain.length() < 5 || domain.length() > 50) return false;
    
    // 计算熵值
    double entropy = calculate_string_entropy(domain);
    if (entropy > 4.5) return true;
    
    // 检查随机字符比例
    size_t random_chars = 0;
    for (char c : domain) {
        if (std::isalnum(c) && std::isdigit(c)) {
            random_chars++;
        }
    }
    
    double random_ratio = static_cast<double>(random_chars) / domain.length();
    return random_ratio > 0.3;
}

void AIProtocolDetector::update_online_classifier(
    const std::vector<double>& features, 
    const std::string& true_label) {
    
    // 简单的在线学习：更新协议特征统计
    auto& stats = protocol_stats_[true_label];
    if (stats.feature_means.empty()) {
        stats.feature_means = features;
        stats.sample_count = 1;
    } else {
        for (size_t i = 0; i < features.size() && i < stats.feature_means.size(); ++i) {
            stats.feature_means[i] = (stats.feature_means[i] * stats.sample_count + features[i]) 
                                   / (stats.sample_count + 1);
        }
        stats.sample_count++;
    }
}

void AIProtocolDetector::initialize_basic_classifiers() {
    // 初始化基本分类器参数
    smoothing_factor_ = 1.0;
    
    // 初始化协议统计
    protocol_stats_.clear();
}

void AIProtocolDetector::load_basic_signatures() {
    // HTTP签名
    protocol_patterns_["HTTP"] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
        "HTTP/1.0", "HTTP/1.1", "HTTP/2", "Content-Type:", "User-Agent:"
    };
    
    // HTTPS/TLS签名
    protocol_patterns_["TLS"] = {"\x16\x03", "\x14\x03", "\x15\x03", "\x17\x03"};
    
    // SSH签名
    protocol_patterns_["SSH"] = {"SSH-2.0", "SSH-1.99", "SSH-1.5"};
    
    // DNS签名
    protocol_patterns_["DNS"] = {};
    
    // 端口映射
    port_mappings_[80] = "HTTP";
    port_mappings_[443] = "HTTPS";
    port_mappings_[22] = "SSH";
    port_mappings_[53] = "DNS";
    port_mappings_[21] = "FTP";
    port_mappings_[25] = "SMTP";
    port_mappings_[110] = "POP3";
    port_mappings_[143] = "IMAP";
    port_mappings_[993] = "IMAPS";
    port_mappings_[995] = "POP3S";
}

std::vector<double> AIProtocolDetector::extract_basic_features(
    const protocol_parser::core::BufferView& buffer,
    uint16_t src_port, uint16_t dst_port) const {
    
    std::vector<double> features;
    
    // 基础特征
    features.push_back(static_cast<double>(buffer.size()));     // 包大小
    features.push_back(static_cast<double>(src_port));          // 源端口
    features.push_back(static_cast<double>(dst_port));          // 目标端口
    features.push_back(calculate_entropy(buffer));              // 熵
    features.push_back(calculate_ascii_ratio(buffer));          // ASCII比例
    
    // 简单的字节统计特征
    if (buffer.size() > 0) {
        uint8_t first_byte = buffer[0];
        features.push_back(static_cast<double>(first_byte));
        
        if (buffer.size() > 1) {
            uint8_t second_byte = buffer[1];
            features.push_back(static_cast<double>(second_byte));
        } else {
            features.push_back(0.0);
        }
    } else {
        features.push_back(0.0);
        features.push_back(0.0);
    }
    
    return features;
}

ClassificationResult AIProtocolDetector::classify_naive_bayes(
    const std::vector<double>& features) const {
    
    ClassificationResult result;
    result.classification_method = "NAIVE_BAYES";
    
    double best_score = -std::numeric_limits<double>::infinity();
    std::string best_protocol;
    
    for (const auto& [protocol, stats] : protocol_stats_) {
        if (stats.feature_means.empty() || stats.sample_count == 0) continue;
        
        double score = 0.0;
        for (size_t i = 0; i < features.size() && i < stats.feature_means.size(); ++i) {
            // 简化的高斯朴素贝叶斯
            double diff = features[i] - stats.feature_means[i];
            score -= diff * diff; // 简化的概率计算
        }
        
        if (score > best_score) {
            best_score = score;
            best_protocol = protocol;
        }
    }
    
    if (!best_protocol.empty()) {
        result.protocol_name = best_protocol;
        result.confidence = std::exp(best_score / features.size()) * 0.8; // 归一化
    } else {
        result.protocol_name = "UNKNOWN";
        result.confidence = 0.1;
    }
    
    return result;
}

ClassificationResult AIProtocolDetector::classify_by_port(
    uint16_t src_port, uint16_t dst_port) const {
    
    ClassificationResult result;
    result.classification_method = "PORT_BASED";
    
    // 检查目标端口
    auto dst_it = port_mappings_.find(dst_port);
    if (dst_it != port_mappings_.end()) {
        result.protocol_name = dst_it->second;
        result.confidence = 0.8;
        return result;
    }
    
    // 检查源端口
    auto src_it = port_mappings_.find(src_port);
    if (src_it != port_mappings_.end()) {
        result.protocol_name = src_it->second;
        result.confidence = 0.7;
        return result;
    }
    
    result.protocol_name = "UNKNOWN";
    result.confidence = 0.1;
    return result;
}

ClassificationResult AIProtocolDetector::classify_by_patterns(
    const protocol_parser::core::BufferView& buffer) const {
    
    ClassificationResult result;
    result.classification_method = "PATTERN_MATCHING";
    
    std::string payload(reinterpret_cast<const char*>(buffer.data()), 
                       std::min(buffer.size(), size_t(256)));
    
    for (const auto& [protocol, patterns] : protocol_patterns_) {
        for (const auto& pattern : patterns) {
            if (payload.find(pattern) != std::string::npos) {
                result.protocol_name = protocol;
                result.confidence = 0.9;
                return result;
            }
        }
    }
    
    result.protocol_name = "UNKNOWN";
    result.confidence = 0.1;
    return result;
}

double AIProtocolDetector::calculate_entropy(
    const protocol_parser::core::BufferView& buffer) const {
    
    if (buffer.size() == 0) return 0.0;
    
    std::array<size_t, 256> byte_counts = {};
    for (size_t i = 0; i < buffer.size(); ++i) {
        byte_counts[buffer[i]]++;
    }
    
    double entropy = 0.0;
    for (size_t count : byte_counts) {
        if (count > 0) {
            double probability = static_cast<double>(count) / buffer.size();
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

double AIProtocolDetector::calculate_ascii_ratio(
    const protocol_parser::core::BufferView& buffer) const {
    
    if (buffer.size() == 0) return 0.0;
    
    size_t ascii_count = 0;
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
            ascii_count++;
        }
    }
    
    return static_cast<double>(ascii_count) / buffer.size();
}

double AIProtocolDetector::calculate_string_entropy(const std::string& str) const {
    if (str.empty()) return 0.0;
    
    std::array<size_t, 256> char_counts = {};
    for (char c : str) {
        char_counts[static_cast<uint8_t>(c)]++;
    }
    
    double entropy = 0.0;
    for (size_t count : char_counts) {
        if (count > 0) {
            double probability = static_cast<double>(count) / str.length();
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

} // namespace protocol_parser::ai