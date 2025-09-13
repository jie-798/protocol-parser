#include "detection/protocol_detection.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace ProtocolParser::Detection {

// ProtocolSignature::SignaturePattern 实现
bool ProtocolSignature::SignaturePattern::matches(const uint8_t* data, size_t size) const noexcept {
    if (offset + pattern.size() > size) {
        return false;
    }
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        uint8_t data_byte = data[offset + i];
        uint8_t pattern_byte = pattern[i];
        uint8_t mask_byte = i < mask.size() ? mask[i] : 0xFF;
        
        if ((data_byte & mask_byte) != (pattern_byte & mask_byte)) {
            return false;
        }
    }
    
    return true;
}

bool ProtocolSignature::SignaturePattern::search_matches(const uint8_t* data, size_t size) const noexcept {
    if (pattern.empty() || size < pattern.size()) {
        return false;
    }
    
    size_t search_end = (max_search_range > 0) 
        ? std::min(size - pattern.size() + 1, offset + max_search_range)
        : size - pattern.size() + 1;
    
    for (size_t start = offset; start < search_end; ++start) {
        bool match = true;
        for (size_t i = 0; i < pattern.size() && match; ++i) {
            uint8_t data_byte = data[start + i];
            uint8_t pattern_byte = pattern[i];
            uint8_t mask_byte = i < mask.size() ? mask[i] : 0xFF;
            
            if ((data_byte & mask_byte) != (pattern_byte & mask_byte)) {
                match = false;
            }
        }
        
        if (match) {
            return true;
        }
    }
    
    return false;
}

// ProtocolSignature 实现
double ProtocolSignature::calculate_match_score(const Core::BufferView& buffer) const noexcept {
    const auto data = buffer.data();
    const auto size = buffer.size();
    
    double total_score = 0.0;
    double total_weight = 0.0;
    
    for (const auto& pattern : patterns) {
        total_weight += pattern.weight;
        
        if (pattern.search_matches(data, size)) {
            total_score += pattern.weight;
        }
    }
    
    if (total_weight == 0.0) {
        return 0.0;
    }
    
    double match_ratio = total_score / total_weight;
    return match_ratio * base_confidence;
}

// PortBasedDetector 实现
PortBasedDetector::PortBasedDetector() {
    initialize_standard_ports();
}

std::vector<DetectionResult> PortBasedDetector::detect_by_port(uint16_t src_port, uint16_t dst_port) const noexcept {
    std::vector<DetectionResult> results;
    
    auto check_port = [&](uint16_t port) {
        auto it = port_to_protocols_.find(port);
        if (it != port_to_protocols_.end()) {
            for (const auto& [protocol, confidence] : it->second) {
                DetectionResult result;
                result.protocol_name = protocol;
                result.confidence_score = confidence;
                result.confidence = score_to_confidence_level(confidence);
                result.detected_port = port;
                result.detection_method = "Port-based";
                result.evidence.push_back("Standard port " + std::to_string(port));
                results.push_back(result);
            }
        }
    };
    
    check_port(src_port);
    check_port(dst_port);
    
    return results;
}

void PortBasedDetector::add_port_mapping(uint16_t port, const std::string& protocol, double confidence) {
    port_to_protocols_[port].emplace_back(protocol, confidence);
}

void PortBasedDetector::remove_port_mapping(uint16_t port, const std::string& protocol) {
    auto it = port_to_protocols_.find(port);
    if (it != port_to_protocols_.end()) {
        auto& protocols = it->second;
        protocols.erase(
            std::remove_if(protocols.begin(), protocols.end(),
                [&protocol](const auto& pair) { return pair.first == protocol; }),
            protocols.end());
        
        if (protocols.empty()) {
            port_to_protocols_.erase(it);
        }
    }
}

void PortBasedDetector::initialize_standard_ports() {
    // Web协议
    add_port_mapping(80, "HTTP", 0.9);
    add_port_mapping(443, "HTTPS", 0.9);
    add_port_mapping(8080, "HTTP", 0.7);
    add_port_mapping(8443, "HTTPS", 0.7);
    
    // 邮件协议
    add_port_mapping(25, "SMTP", 0.9);
    add_port_mapping(110, "POP3", 0.9);
    add_port_mapping(143, "IMAP", 0.9);
    add_port_mapping(993, "IMAPS", 0.9);
    add_port_mapping(995, "POP3S", 0.9);
    
    // 网络管理
    add_port_mapping(161, "SNMP", 0.9);
    add_port_mapping(162, "SNMP-TRAP", 0.9);
    
    // DHCP
    add_port_mapping(67, "DHCP", 0.9);
    add_port_mapping(68, "DHCP", 0.9);
    
    // 其他常见协议
    add_port_mapping(21, "FTP", 0.9);
    add_port_mapping(22, "SSH", 0.9);
    add_port_mapping(23, "TELNET", 0.9);
    add_port_mapping(53, "DNS", 0.9);
    add_port_mapping(69, "TFTP", 0.8);
}

// HeuristicDetector 实现
HeuristicDetector::PacketFeatures HeuristicDetector::extract_features(const Core::BufferView& buffer) const noexcept {
    PacketFeatures features;
    const auto data = buffer.data();
    const auto size = buffer.size();
    
    features.packet_size = size;
    
    if (size == 0) {
        return features;
    }
    
    // 计算字节频率和统计信息
    for (size_t i = 0; i < size; ++i) {
        uint8_t byte = data[i];
        features.byte_frequency[byte]++;
        
        if (byte == 0) {
            features.null_bytes++;
        } else if (Utils::is_printable_ascii(byte)) {
            features.printable_chars++;
        }
    }
    
    // 计算熵
    features.entropy = calculate_entropy(data, size);
    
    // 检测连续零字节
    size_t current_zeros = 0;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == 0) {
            current_zeros++;
        } else {
            features.consecutive_zeros = std::max(features.consecutive_zeros, current_zeros);
            current_zeros = 0;
        }
    }
    features.consecutive_zeros = std::max(features.consecutive_zeros, current_zeros);
    
    // 检测常见头部模式
    features.has_common_headers = Utils::is_likely_header_field(data, std::min(size, size_t(64)));
    
    // 提取字符串
    features.detected_strings = extract_strings(buffer);
    
    return features;
}

std::vector<DetectionResult> HeuristicDetector::detect_by_heuristics(const PacketFeatures& features) const noexcept {
    std::vector<DetectionResult> results;
    
    // 基于熵的检测
    if (features.entropy < 2.0 && features.printable_chars > features.packet_size * 0.8) {
        // 可能是文本协议
        if (is_likely_text_protocol(features)) {
            DetectionResult result;
            result.protocol_name = "TEXT_BASED";
            result.confidence_score = 0.6;
            result.confidence = ConfidenceLevel::MEDIUM;
            result.detection_method = "Heuristic-Text";
            result.evidence.push_back("High printable character ratio");
            result.evidence.push_back("Low entropy: " + std::to_string(features.entropy));
            results.push_back(result);
        }
    } else if (features.entropy > 6.0) {
        // 可能是加密或压缩数据
        DetectionResult result;
        result.protocol_name = "ENCRYPTED_OR_COMPRESSED";
        result.confidence_score = 0.7;
        result.confidence = ConfidenceLevel::HIGH;
        result.detection_method = "Heuristic-Entropy";
        result.evidence.push_back("High entropy: " + std::to_string(features.entropy));
        results.push_back(result);
    }
    
    // 基于二进制特征的检测
    if (is_likely_binary_protocol(features)) {
        DetectionResult result;
        result.protocol_name = "BINARY_PROTOCOL";
        result.confidence_score = 0.5;
        result.confidence = ConfidenceLevel::MEDIUM;
        result.detection_method = "Heuristic-Binary";
        result.evidence.push_back("Binary protocol characteristics detected");
        results.push_back(result);
    }
    
    return results;
}

double HeuristicDetector::calculate_entropy(const uint8_t* data, size_t size) const noexcept {
    if (size == 0) return 0.0;
    
    std::array<size_t, 256> frequency{};
    for (size_t i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }
    
    double entropy = 0.0;
    for (size_t count : frequency) {
        if (count > 0) {
            double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

bool HeuristicDetector::is_likely_text_protocol(const PacketFeatures& features) const noexcept {
    double printable_ratio = static_cast<double>(features.printable_chars) / features.packet_size;
    return printable_ratio > 0.7 && features.entropy < 3.0;
}

bool HeuristicDetector::is_likely_binary_protocol(const PacketFeatures& features) const noexcept {
    return features.null_bytes > features.packet_size * 0.1 && 
           features.consecutive_zeros > 8;
}

std::vector<std::string> HeuristicDetector::extract_strings(const Core::BufferView& buffer) const {
    std::vector<std::string> strings;
    const auto data = buffer.data();
    const auto size = buffer.size();
    
    std::string current_string;
    const size_t min_string_length = 4;
    
    for (size_t i = 0; i < size; ++i) {
        if (Utils::is_printable_ascii(data[i])) {
            current_string += static_cast<char>(data[i]);
        } else {
            if (current_string.length() >= min_string_length) {
                strings.push_back(current_string);
            }
            current_string.clear();
        }
    }
    
    if (current_string.length() >= min_string_length) {
        strings.push_back(current_string);
    }
    
    return strings;
}

// ProtocolDetectionEngine 实现
ProtocolDetectionEngine::ProtocolDetectionEngine() 
    : port_detector_(std::make_unique<PortBasedDetector>()),
      heuristic_detector_(std::make_unique<HeuristicDetector>()),
      deep_inspector_(std::make_unique<DeepPacketInspector>()),
      ml_extractor_(std::make_unique<MLFeatureExtractor>()) {
    
    initialize_builtin_signatures();
}

DetectionResult ProtocolDetectionEngine::detect_protocol(const Core::BufferView& buffer) const noexcept {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<DetectionResult> all_results;
    
    try {
        // 签名匹配检测
        if (config_.use_signature_based) {
            std::shared_lock lock(signatures_mutex_);
            for (const auto& [name, signature] : signatures_) {
                double score = signature.calculate_match_score(buffer);
                if (score > config_.min_confidence_threshold) {
                    DetectionResult result;
                    result.protocol_name = name;
                    result.confidence_score = score;
                    result.confidence = score_to_confidence_level(score);
                    result.detection_method = "Signature-based";
                    result.evidence.push_back("Signature pattern match");
                    result.bytes_analyzed = buffer.size();
                    all_results.push_back(result);
                }
            }
        }
        
        // 启发式检测
        if (config_.use_heuristic_based) {
            auto features = heuristic_detector_->extract_features(buffer);
            auto heuristic_results = heuristic_detector_->detect_by_heuristics(features);
            all_results.insert(all_results.end(), heuristic_results.begin(), heuristic_results.end());
        }
        
        // 深度检测
        if (config_.use_deep_inspection) {
            auto deep_results = deep_inspector_->inspect_deep(buffer);
            all_results.insert(all_results.end(), deep_results.begin(), deep_results.end());
        }
        
    } catch (const std::exception&) {
        // 静默处理异常
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto detection_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    DetectionResult final_result = combine_results(all_results);
    final_result.bytes_analyzed = buffer.size();
    
    update_statistics(final_result, detection_time);
    
    return final_result;
}

DetectionResult ProtocolDetectionEngine::detect_protocol_with_ports(const Core::BufferView& buffer, 
                                                                   uint16_t src_port, uint16_t dst_port) const noexcept {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<DetectionResult> all_results;
    
    try {
        // 端口检测
        if (config_.use_port_based) {
            auto port_results = port_detector_->detect_by_port(src_port, dst_port);
            all_results.insert(all_results.end(), port_results.begin(), port_results.end());
        }
        
        // 其他检测方法...
        auto content_result = detect_protocol(buffer);
        if (!content_result.protocol_name.empty()) {
            all_results.push_back(content_result);
        }
        
    } catch (const std::exception&) {
        // 静默处理异常
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto detection_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    DetectionResult final_result = combine_results(all_results);
    final_result.bytes_analyzed = buffer.size();
    
    update_statistics(final_result, detection_time);
    
    return final_result;
}

void ProtocolDetectionEngine::add_signature(const ProtocolSignature& signature) {
    std::unique_lock lock(signatures_mutex_);
    signatures_[signature.protocol_name] = signature;
}

void ProtocolDetectionEngine::configure(const DetectionConfig& config) {
    config_ = config;
}

ProtocolDetectionEngine::DetectionConfig ProtocolDetectionEngine::get_configuration() const noexcept {
    return config_;
}

ProtocolDetectionEngine::DetectionStatistics ProtocolDetectionEngine::get_statistics() const noexcept {
    std::lock_guard lock(stats_mutex_);
    return statistics_;
}

void ProtocolDetectionEngine::reset_statistics() noexcept {
    std::lock_guard lock(stats_mutex_);
    statistics_ = DetectionStatistics{};
}

std::vector<std::string> ProtocolDetectionEngine::get_supported_protocols() const noexcept {
    std::vector<std::string> protocols;
    std::shared_lock lock(signatures_mutex_);
    
    for (const auto& [name, _] : signatures_) {
        protocols.push_back(name);
    }
    
    return protocols;
}

// 私有方法实现
DetectionResult ProtocolDetectionEngine::combine_results(const std::vector<DetectionResult>& results) const noexcept {
    if (results.empty()) {
        return DetectionResult{};
    }
    
    if (results.size() == 1) {
        return results[0];
    }
    
    // 按置信度排序
    auto sorted_results = results;
    std::sort(sorted_results.begin(), sorted_results.end(),
              [](const DetectionResult& a, const DetectionResult& b) {
                  return a.confidence_score > b.confidence_score;
              });
    
    // 选择最佳结果
    DetectionResult best_result = sorted_results[0];
    
    // 合并证据
    for (size_t i = 1; i < sorted_results.size(); ++i) {
        if (sorted_results[i].protocol_name == best_result.protocol_name) {
            best_result.confidence_score = std::min(1.0, best_result.confidence_score + 0.1);
            for (const auto& evidence : sorted_results[i].evidence) {
                best_result.evidence.push_back(evidence);
            }
        }
    }
    
    best_result.confidence = score_to_confidence_level(best_result.confidence_score);
    return best_result;
}

void ProtocolDetectionEngine::update_statistics(const DetectionResult& result, std::chrono::nanoseconds detection_time) const noexcept {
    std::lock_guard lock(stats_mutex_);
    
    statistics_.total_detections++;
    
    if (!result.protocol_name.empty() && result.confidence_score > config_.min_confidence_threshold) {
        statistics_.successful_detections++;
        statistics_.protocol_detection_count[result.protocol_name]++;
        
        if (result.detection_method == "Port-based") {
            statistics_.port_based_detections++;
        } else if (result.detection_method == "Signature-based") {
            statistics_.signature_based_detections++;
        } else if (result.detection_method.find("Heuristic") != std::string::npos) {
            statistics_.heuristic_detections++;
        } else if (result.detection_method == "Deep-inspection") {
            statistics_.deep_inspection_detections++;
        }
    }
    
    statistics_.total_detection_time += detection_time;
    if (statistics_.total_detections > 0) {
        statistics_.avg_detection_time = statistics_.total_detection_time / statistics_.total_detections;
    }
}

void ProtocolDetectionEngine::initialize_builtin_signatures() {
    // HTTP签名
    {
        ProtocolSignature http("HTTP");
        http.base_confidence = 0.8;
        
        ProtocolSignature::SignaturePattern get_pattern;
        get_pattern.pattern = {'G', 'E', 'T', ' '};
        get_pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF};
        get_pattern.offset = 0;
        get_pattern.weight = 1.0;
        get_pattern.description = "HTTP GET method";
        http.patterns.push_back(get_pattern);
        
        ProtocolSignature::SignaturePattern post_pattern;
        post_pattern.pattern = {'P', 'O', 'S', 'T', ' '};
        post_pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        post_pattern.offset = 0;
        post_pattern.weight = 1.0;
        post_pattern.description = "HTTP POST method";
        http.patterns.push_back(post_pattern);
        
        add_signature(http);
    }
    
    // DHCP签名
    {
        ProtocolSignature dhcp("DHCP");
        dhcp.base_confidence = 0.9;
        
        ProtocolSignature::SignaturePattern magic_cookie;
        magic_cookie.pattern = {0x63, 0x82, 0x53, 0x63};
        magic_cookie.mask = {0xFF, 0xFF, 0xFF, 0xFF};
        magic_cookie.offset = 236;  // DHCP magic cookie offset
        magic_cookie.weight = 1.0;
        magic_cookie.description = "DHCP magic cookie";
        dhcp.patterns.push_back(magic_cookie);
        
        add_signature(dhcp);
    }
    
    // SNMP签名
    {
        ProtocolSignature snmp("SNMP");
        snmp.base_confidence = 0.8;
        
        ProtocolSignature::SignaturePattern ber_sequence;
        ber_sequence.pattern = {0x30};
        ber_sequence.mask = {0xFF};
        ber_sequence.offset = 0;
        ber_sequence.weight = 0.6;
        ber_sequence.description = "BER SEQUENCE tag";
        snmp.patterns.push_back(ber_sequence);
        
        add_signature(snmp);
    }
}

ConfidenceLevel ProtocolDetectionEngine::score_to_confidence_level(double score) noexcept {
    if (score >= 0.8) return ConfidenceLevel::VERY_HIGH;
    if (score >= 0.6) return ConfidenceLevel::HIGH;
    if (score >= 0.4) return ConfidenceLevel::MEDIUM;
    if (score >= 0.2) return ConfidenceLevel::LOW;
    return ConfidenceLevel::VERY_LOW;
}

// 简化的其他类实现
DeepPacketInspector::DeepPacketInspector() {
    initialize_standard_rules();
}

std::vector<DetectionResult> DeepPacketInspector::inspect_deep(const Core::BufferView& buffer) const noexcept {
    // 简化实现
    return {};
}

void DeepPacketInspector::initialize_standard_rules() {
    // 实现标准规则初始化
}

MLFeatureExtractor::MLFeatures MLFeatureExtractor::extract_features(const std::vector<Core::BufferView>& packet_sequence) const noexcept {
    // 简化实现
    return MLFeatures{};
}

// Utils 命名空间实现
namespace Utils {

bool is_printable_ascii(uint8_t byte) noexcept {
    return byte >= 32 && byte <= 126;
}

bool is_likely_header_field(const uint8_t* data, size_t size) noexcept {
    if (size < 4) return false;
    
    // 检查是否包含典型的头部分隔符
    for (size_t i = 0; i < size - 1; ++i) {
        if (data[i] == ':' && data[i + 1] == ' ') {
            return true;
        }
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return true;
        }
    }
    
    return false;
}

uint32_t calculate_simple_checksum(const uint8_t* data, size_t size) noexcept {
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; ++i) {
        checksum += data[i];
    }
    return checksum;
}

std::vector<uint8_t> create_signature_pattern(const std::string& hex_string) {
    std::vector<uint8_t> pattern;
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_str = hex_string.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        pattern.push_back(byte);
    }
    return pattern;
}

std::string buffer_to_hex_string(const Core::BufferView& buffer, size_t max_bytes) {
    std::ostringstream oss;
    const auto data = buffer.data();
    const auto size = std::min(buffer.size(), max_bytes);
    
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i < size - 1) oss << " ";
    }
    
    return oss.str();
}

} // namespace Utils

} // namespace ProtocolParser::Detection