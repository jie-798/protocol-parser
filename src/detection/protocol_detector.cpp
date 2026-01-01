#include "detection/protocol_detector.hpp"
#include <algorithm>
#include <cstring>
#include <cctype>

namespace protocol_parser::detection {

// ============================================================================
// ProtocolDetector 实现
// ============================================================================

ProtocolDetector::ProtocolDetector() {
    init_signature_database();
    init_port_mappings();
}

const char* ProtocolDetector::get_protocol_name(ProtocolType type) {
    switch (type) {
        case ProtocolType::HTTP: return "HTTP";
        case ProtocolType::HTTPS: return "HTTPS";
        case ProtocolType::FTP: return "FTP";
        case ProtocolType::SSH: return "SSH";
        case ProtocolType::DNS: return "DNS";
        case ProtocolType::SMTP: return "SMTP";
        case ProtocolType::POP3: return "POP3";
        case ProtocolType::IMAP: return "IMAP";
        case ProtocolType::Telnet: return "Telnet";
        case ProtocolType::MQTT: return "MQTT";
        case ProtocolType::WebSocket: return "WebSocket";
        case ProtocolType::QUIC: return "QUIC";
        case ProtocolType::SIP: return "SIP";
        case ProtocolType::RTP: return "RTP";
        case ProtocolType::RTCP: return "RTCP";
        case ProtocolType::TLS: return "TLS";
        case ProtocolType::ModbusTCP: return "ModbusTCP";
        case ProtocolType::DNP3: return "DNP3";
        case ProtocolType::GQUIC: return "GQUIC";
        case ProtocolType::DHCP: return "DHCP";
        case ProtocolType::SNMP: return "SNMP";
        case ProtocolType::NTP: return "NTP";
        case ProtocolType::RDP: return "RDP";
        case ProtocolType::VNC: return "VNC";
        case ProtocolType::IRC: return "IRC";
        case ProtocolType::BitTorrent: return "BitTorrent";
        case ProtocolType::Skype: return "Skype";
        case ProtocolType::MySQL: return "MySQL";
        case ProtocolType::PostgreSQL: return "PostgreSQL";
        case ProtocolType::Redis: return "Redis";
        case ProtocolType::MongoDB: return "MongoDB";
        default: return "Unknown";
    }
}

void ProtocolDetector::init_signature_database() {
    // HTTP
    signatures_.insert({ProtocolType::HTTP, {
        {0x47, 0x45, 0x54, 0x20}, 0, true, "GET"
    }});  // GET
    signatures_.insert({ProtocolType::HTTP, {
        {0x50, 0x4F, 0x53, 0x54}, 0, true, "POST"
    }});  // POST
    signatures_.insert({ProtocolType::HTTP, {
        {0x48, 0x45, 0x41, 0x44}, 0, true, "HEAD"
    }});  // HEAD

    // HTTPS/TLS
    signatures_.insert({ProtocolType::TLS, {
        {0x16, 0x03}, 0, true, ""  // TLS Handshake
    }});  // TLS content type 0x16, version 0x03

    // SSH
    signatures_.insert({ProtocolType::SSH, {
        {0x53, 0x53, 0x48}, 0, true, "SSH"
    }});  // "SSH-"

    // FTP
    signatures_.insert({ProtocolType::FTP, {
        {0x55, 0x53, 0x45, 0x52}, 0, true, "USER"
    }});  // USER

    // DNS
    signatures_.insert({ProtocolType::DNS, {
        {}, 0, true, ""  // DNS 没有固定模式，需要检查端口和结构
    }});

    // SMTP
    signatures_.insert({ProtocolType::SMTP, {
        {0x45, 0x48, 0x4C, 0x4F}, 0, true, "EHLO"
    }});  // EHLO
    signatures_.insert({ProtocolType::SMTP, {
        {0x4D, 0x41, 0x49, 0x4C}, 0, true, "MAIL"
    }});  // MAIL FROM

    // MQTT
    signatures_.insert({ProtocolType::MQTT, {
        {0x10}, 0, true, ""  // MQTT CONNECT
    }});  // MQTT packet type 0x10

    // SIP
    signatures_.insert({ProtocolType::SIP, {
        {0x49, 0x4E, 0x56, 0x49}, 0, true, "INVITE"
    }});  // INVITE

    // QUIC
    signatures_.insert({ProtocolType::QUIC, {
        {}, 0, true, ""  // QUIC 检查特殊包头格式
    }});

    // MySQL
    signatures_.insert({ProtocolType::MySQL, {
        {}, 0, true, ""  // MySQL handshake
    }});

    // Redis
    signatures_.insert({ProtocolType::Redis, {
        {0x2A, 0x31}, 0, true, ""  // RESP protocol "*1"
    }});  // RESP simple string

    // BitTorrent
    signatures_.insert({ProtocolType::BitTorrent, {
        {0x13, 0x42, 0x69, 0x74}, 0, true, "BitTorrent"
    }});  // "\x13BitTorrent protocol"
}

void ProtocolDetector::init_port_mappings() {
    // TCP 端口
    port_mappings_.push_back({80, ProtocolType::HTTP, true});
    port_mappings_.push_back({443, ProtocolType::HTTPS, true});
    port_mappings_.push_back({21, ProtocolType::FTP, true});
    port_mappings_.push_back({22, ProtocolType::SSH, true});
    port_mappings_.push_back({25, ProtocolType::SMTP, true});
    port_mappings_.push_back({110, ProtocolType::POP3, true});
    port_mappings_.push_back({143, ProtocolType::IMAP, true});
    port_mappings_.push_back({23, ProtocolType::Telnet, true});
    port_mappings_.push_back({1883, ProtocolType::MQTT, true});
    port_mappings_.push_back({5060, ProtocolType::SIP, true});
    port_mappings_.push_back({5061, ProtocolType::SIP, true});
    port_mappings_.push_back({3306, ProtocolType::MySQL, true});
    port_mappings_.push_back({5432, ProtocolType::PostgreSQL, true});
    port_mappings_.push_back({6379, ProtocolType::Redis, true});
    port_mappings_.push_back({27017, ProtocolType::MongoDB, true});
    port_mappings_.push_back({3389, ProtocolType::RDP, true});
    port_mappings_.push_back({5900, ProtocolType::VNC, true});
    port_mappings_.push_back({6667, ProtocolType::IRC, true});

    // UDP 端口
    port_mappings_.push_back({53, ProtocolType::DNS, false});
    port_mappings_.push_back({67, ProtocolType::DHCP, false});
    port_mappings_.push_back({161, ProtocolType::SNMP, false});
    port_mappings_.push_back({123, ProtocolType::NTP, false});
    port_mappings_.push_back({5060, ProtocolType::SIP, false});  // SIP 也支持 UDP
}

DetectionResult ProtocolDetector::detect(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const BufferView& payload,
    bool is_tcp) {

    DetectionResult result;
    stats_.total_detections++;

    // 阶段 1: 端口识别（最快）
    auto port_result = detect_by_port(dst_port, is_tcp);
    if (port_result && port_result->confidence == Confidence::Certain) {
        result = *port_result;
        result.by_port = true;
        result.score = 95;
        stats_.by_port_count++;
        return result;
    }

    // 阶段 2: 特征匹配（深度包检测）
    auto sig_result = detect_by_signature(payload);
    if (sig_result) {
        result = *sig_result;
        result.by_signature = true;
        result.score = 85;
        stats_.by_signature_count++;
        return result;
    }

    // 阶段 3: 行为分析
    FlowKey key{src_ip, dst_ip, src_port, dst_port, is_tcp};
    auto behavior_result = detect_by_behavior(key, payload);
    if (behavior_result) {
        result = *behavior_result;
        result.by_behavior = true;
        result.score = 70;
        stats_.by_behavior_count++;
        return result;
    }

    // 阶段 4: 机器学习分类
    auto ml_result = detect_by_ml(key, payload);
    if (ml_result) {
        result = *ml_result;
        result.by_ml = true;
        result.score = 60;
        stats_.by_ml_count++;
        return result;
    }

    // 未识别
    stats_.unknown_count++;
    result.protocol = ProtocolType::Unknown;
    result.confidence = Confidence::Low;
    result.protocol_name = "Unknown";
    result.score = 0;

    return result;
}

std::optional<DetectionResult> ProtocolDetector::detect_by_port(
    uint16_t port,
    bool is_tcp) const {

    // 查找端口映射
    for (const auto& mapping : port_mappings_) {
        if (mapping.port == port && mapping.is_tcp == is_tcp) {
            DetectionResult result;
            result.protocol = mapping.protocol;
            result.confidence = Confidence::High;  // 端口识别置信度高
            result.protocol_name = get_protocol_name(mapping.protocol);
            result.by_port = true;
            return result;
        }
    }

    return std::nullopt;
}

std::optional<DetectionResult> ProtocolDetector::detect_by_signature(
    const BufferView& payload) const {

    if (payload.empty()) {
        return std::nullopt;
    }

    // 遍历所有协议特征
    for (const auto& [protocol, signatures] : signatures_) {
        auto range = signatures.equal_range(protocol);

        for (auto it = range.first; it != range.second; ++it) {
            const auto& sig = it->second;

            if (check_pattern(payload, sig)) {
                DetectionResult result;
                result.protocol = protocol;
                result.confidence = Confidence::High;
                result.protocol_name = get_protocol_name(protocol);
                result.by_signature = true;
                result.details = "Matched signature: " + sig.string_pattern;
                return result;
            }
        }
    }

    // 特殊检查：QUIC
    if (parsers::QuicParser::is_quic_packet(payload)) {
        DetectionResult result;
        result.protocol = ProtocolType::QUIC;
        result.confidence = Confidence::High;
        result.protocol_name = "QUIC";
        result.by_signature = true;
        return result;
    }

    // 特殊检查：SIP
    if (parsers::SipParser::is_sip_message(payload)) {
        DetectionResult result;
        result.protocol = ProtocolType::SIP;
        result.confidence = Confidence::High;
        result.protocol_name = "SIP";
        result.by_signature = true;
        return result;
    }

    // 特殊检查：RTP/RTCP
    if (parsers::RtpParser::is_rtp_packet(payload)) {
        DetectionResult result;
        result.protocol = ProtocolType::RTP;
        result.confidence = Confidence::High;
        result.protocol_name = "RTP";
        result.by_signature = true;
        return result;
    }

    return std::nullopt;
}

std::optional<DetectionResult> ProtocolDetector::detect_by_behavior(
    const FlowKey& key,
    const BufferView& payload) {

    auto it = flow_states_.find(key);
    if (it == flow_states_.end()) {
        return std::nullopt;  // 没有流状态，无法行为分析
    }

    const auto& state = it->second;

    // 基于行为特征判断协议

    // 加密协议检测（高熵值）
    if (payload.size() >= 16) {
        double entropy = 0.0;
        std::array<int, 256> freq{};
        freq.fill(0);

        for (size_t i = 0; i < payload.size(); ++i) {
            freq[payload[i]]++;
        }

        for (int f : freq) {
            if (f > 0) {
                double p = static_cast<double>(f) / payload.size();
                entropy -= p * std::log2(p);
            }
        }

        // 高熵值可能是加密流量
        if (entropy > 7.5) {
            DetectionResult result;
            result.protocol = ProtocolType::TLS;  // 猜测是 TLS
            result.confidence = Confidence::Medium;
            result.protocol_name = "Encrypted (likely TLS)";
            result.by_behavior = true;
            result.details = "High entropy: " + std::to_string(entropy);
            return result;
        }
    }

    // 小包频繁交互可能是控制协议
    if (state.packet_count > 10 && state.byte_count < state.packet_count * 100) {
        DetectionResult result;
        result.protocol = ProtocolType::SSH;  // 猜测是 SSH
        result.confidence = Confidence::Low;
        result.protocol_name = "Likely SSH (small packets)";
        result.by_behavior = true;
        return result;
    }

    return std::nullopt;
}

std::optional<DetectionResult> ProtocolDetector::detect_by_ml(
    const FlowKey& key,
    const BufferView& payload) {

    // 简化的机器学习模型（实际应用中应使用训练好的模型）
    // 这里使用简单的启发式规则

    auto it = flow_states_.find(key);
    if (it == flow_states_.end()) {
        return std::nullopt;
    }

    const auto& state = it->second;

    // 特征提取
    double avg_packet_size = static_cast<double>(state.byte_count) / state.packet_count;
    double ratio = static_cast<double>(state.client_to_server_bytes) /
                  (state.server_to_client_bytes + 1);

    // 简单的决策树
    if (avg_packet_size < 100 && ratio > 2.0) {
        DetectionResult result;
        result.protocol = ProtocolType::HTTP;
        result.confidence = Confidence::Low;
        result.protocol_name = "Likely HTTP (ML)";
        result.by_ml = true;
        return result;
    }

    return std::nullopt;
}

bool ProtocolDetector::check_pattern(
    const BufferView& payload,
    const ProtocolSignature& sig) const {

    if (sig.pattern.empty() && !sig.string_pattern.empty()) {
        return check_string_pattern(payload, sig.string_pattern);
    }

    if (sig.offset + sig.pattern.size() > payload.size()) {
        return false;
    }

    // 检查字节模式
    for (size_t i = 0; i < sig.pattern.size(); ++i) {
        if (payload[sig.offset + i] != sig.pattern[i]) {
            return false;
        }
    }

    return true;
}

bool ProtocolDetector::check_string_pattern(
    const BufferView& payload,
    const std::string& pattern) const {

    if (pattern.size() > payload.size()) {
        return false;
    }

    // 检查字符串模式（不区分大小写）
    std::string_view payload_sv(reinterpret_cast<const char*>(payload.data()),
                                payload.size());
    std::string pattern_lower = pattern;
    std::transform(pattern_lower.begin(), pattern_lower.end(),
                  pattern_lower.begin(), ::tolower);

    // 查找模式
    size_t pos = 0;
    for (size_t i = 0; i <= payload.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (std::tolower(payload[i + j]) != pattern_lower[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }

    return false;
}

void ProtocolDetector::update_flow_state(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    size_t payload_size,
    bool is_client_to_server) {

    FlowKey key{src_ip, dst_ip, src_port, dst_port, true};  // 简化：假设都是 TCP
    auto& state = flow_states_[key];

    state.packet_count++;
    state.byte_count += payload_size;

    if (is_client_to_server) {
        state.client_to_server_packets++;
        state.client_to_server_bytes += payload_size;
    } else {
        state.server_to_client_packets++;
        state.server_to_client_bytes += payload_size;
    }

    // 数据包大小分布
    if (payload_size < 64) {
        state.size_buckets[0]++;
    } else if (payload_size < 512) {
        state.size_buckets[1]++;
    } else if (payload_size < 1024) {
        state.size_buckets[2]++;
    } else {
        state.size_buckets[3]++;
    }
}

const FlowState* ProtocolDetector::get_flow_state(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port) const {

    FlowKey key{src_ip, dst_ip, src_port, dst_port, true};
    auto it = flow_states_.find(key);
    if (it != flow_states_.end()) {
        return &it->second;
    }
    return nullptr;
}

void ProtocolDetector::cleanup_old_flows(uint64_t current_time_ms, uint64_t timeout_ms) {
    auto it = flow_states_.begin();
    while (it != flow_states_.end()) {
        if (current_time_ms - it->second.last_packet_time > timeout_ms) {
            it = flow_states_.erase(it);
        } else {
            ++it;
        }
    }
}

void ProtocolDetector::add_signature(ProtocolType protocol, const ProtocolSignature& signature) {
    signatures_.insert({protocol, signature});
}

void ProtocolDetector::add_port_mapping(uint16_t port, ProtocolType protocol, bool is_tcp) {
    port_mappings_.push_back({port, protocol, is_tcp});
}

// ============================================================================
// ProtocolDetectorFactory 实现
// ============================================================================

ProtocolDetector& ProtocolDetectorFactory::get_default_detector() {
    static ProtocolDetector instance;
    return instance;
}

std::unique_ptr<ProtocolDetector> ProtocolDetectorFactory::create_detector() {
    return std::make_unique<ProtocolDetector>();
}

} // namespace protocol_parser::detection
