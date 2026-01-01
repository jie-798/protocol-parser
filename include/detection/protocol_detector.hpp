#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <array>

namespace protocol_parser::detection {

/**
 * 协议类型枚举
 */
enum class ProtocolType : uint32_t {
    Unknown = 0,
    HTTP = 1,
    HTTPS = 2,
    FTP = 3,
    SSH = 4,
    DNS = 5,
    SMTP = 6,
    POP3 = 7,
    IMAP = 8,
    Telnet = 9,
    MQTT = 10,
    WebSocket = 11,
    QUIC = 12,
    SIP = 13,
    RTP = 14,
    RTCP = 15,
    TLS = 16,
    ModbusTCP = 17,
    DNP3 = 18,
    GQUIC = 19,
    DHCP = 20,
    SNMP = 21,
    NTP = 22,
    RDP = 23,
    VNC = 24,
    IRC = 25,
    BitTorrent = 26,
    Skype = 27,
    MySQL = 28,
    PostgreSQL = 29,
    Redis = 30,
    MongoDB = 31
};

/**
 * 识别置信度
 */
enum class Confidence : uint8_t {
    Low = 1,       // 低置信度（可能误判）
    Medium = 2,    // 中等置信度
    High = 3,      // 高置信度
    Certain = 4    // 确定无误
};

/**
 * 协议识别结果
 */
struct DetectionResult {
    ProtocolType protocol = ProtocolType::Unknown;
    Confidence confidence = Confidence::Low;
    std::string protocol_name;
    uint8_t score = 0;  // 0-100 分

    // 识别方法
    bool by_port = false;
    bool by_signature = false;
    bool by_behavior = false;
    bool by_ml = false;

    // 附加信息
    std::string details;
};

/**
 * 协议特征
 */
struct ProtocolSignature {
    std::vector<uint8_t> pattern;           // 字节模式
    size_t offset;                          // 偏移位置
    bool is_request;                        // 是请求还是响应
    std::string string_pattern;             // 字符串模式（用于文本协议）
};

/**
 * 端口到协议的映射
 */
struct PortMapping {
    uint16_t port;
    ProtocolType protocol;
    bool is_tcp;  // true for TCP, false for UDP
};

/**
 * 流状态（用于行为分析）
 */
struct FlowState {
    // 统计信息
    uint32_t packet_count = 0;
    uint32_t byte_count = 0;
    uint32_t duration_ms = 0;

    // 数据包大小分布
    std::array<uint32_t, 4> size_buckets{};  // <64, <512, <1024, >=1024

    // 方向性
    uint32_t client_to_server_packets = 0;
    uint32_t server_to_client_packets = 0;
    uint32_t client_to_server_bytes = 0;
    uint32_t server_to_client_bytes = 0;

    // 时序特征
    uint64_t first_packet_time = 0;
    uint64_t last_packet_time = 0;
    std::vector<uint64_t> inter_arrival_times;

    // 协议特定特征
    bool has_handshake = false;
    bool has_encryption = false;
    bool has_persistent_connection = false;
};

/**
 * 多阶段协议检测器
 * 基于 nDPI 设计，支持：
 * 1. 端口识别（快速路径）
 * 2. 特征匹配（深度包检测）
 * 3. 行为分析
 * 4. 机器学习分类
 */
class ProtocolDetector {
public:
    ProtocolDetector();
    ~ProtocolDetector() = default;

    /**
     * 检测协议
     * @param src_ip 源 IP
     * @param dst_ip 目的 IP
     * @param src_port 源端口
     * @param dst_port 目的端口
     * @param payload 载荷数据
     * @param is_tcp 是否是 TCP
     * @return 检测结果
     */
    [[nodiscard]] DetectionResult detect(
        uint32_t src_ip,
        uint32_t dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        const BufferView& payload,
        bool is_tcp
    );

    /**
     * 更新流状态（用于行为分析）
     */
    void update_flow_state(
        uint32_t src_ip,
        uint32_t dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        size_t payload_size,
        bool is_client_to_server
    );

    /**
     * 获取流状态
     */
    [[nodiscard]] const FlowState* get_flow_state(
        uint32_t src_ip,
        uint32_t dst_ip,
        uint16_t src_port,
        uint16_t dst_port
    ) const;

    /**
     * 清理过期流状态
     */
    void cleanup_old_flows(uint64_t current_time_ms, uint64_t timeout_ms);

    /**
     * 获取协议名称
     */
    [[nodiscard]] static const char* get_protocol_name(ProtocolType type);

    /**
     * 添加自定义协议特征
     */
    void add_signature(ProtocolType protocol, const ProtocolSignature& signature);

    /**
     * 添加端口映射
     */
    void add_port_mapping(uint16_t port, ProtocolType protocol, bool is_tcp);

private:
    // 流键
    struct FlowKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        bool is_tcp;

        bool operator<(const FlowKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            if (dst_port != other.dst_port) return dst_port < other.dst_port;
            return is_tcp < other.is_tcp;
        }

        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip &&
                   dst_ip == other.dst_ip &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port &&
                   is_tcp == other.is_tcp;
        }
    };

    // 阶段 1: 端口识别
    [[nodiscard]] std::optional<DetectionResult> detect_by_port(
        uint16_t port,
        bool is_tcp
    ) const;

    // 阶段 2: 特征匹配
    [[nodiscard]] std::optional<DetectionResult> detect_by_signature(
        const BufferView& payload
    ) const;

    // 阶段 3: 行为分析
    [[nodiscard]] std::optional<DetectionResult> detect_by_behavior(
        const FlowKey& key,
        const BufferView& payload
    );

    // 阶段 4: 机器学习分类（简化版）
    [[nodiscard]] std::optional<DetectionResult> detect_by_ml(
        const FlowKey& key,
        const BufferView& payload
    );

    // 辅助函数：检查字节模式
    [[nodiscard]] bool check_pattern(
        const BufferView& payload,
        const ProtocolSignature& sig
    ) const;

    // 辅助函数：检查字符串模式
    [[nodiscard]] bool check_string_pattern(
        const BufferView& payload,
        const std::string& pattern
    ) const;

    // 初始化协议特征库
    void init_signature_database();

    // 初始化端口映射表
    void init_port_mappings();

    // 特征库
    std::multimap<ProtocolType, ProtocolSignature> signatures_;

    // 端口映射
    std::vector<PortMapping> port_mappings_;

    // 流状态跟踪
    std::map<FlowKey, FlowState> flow_states_;

    // 统计信息
    struct Statistics {
        uint64_t total_detections = 0;
        uint64_t by_port_count = 0;
        uint64_t by_signature_count = 0;
        uint64_t by_behavior_count = 0;
        uint64_t by_ml_count = 0;
        uint64_t unknown_count = 0;
    } stats_;
};

/**
 * 协议检测器工厂
 * 创建和管理多个检测器实例
 */
class ProtocolDetectorFactory {
public:
    static ProtocolDetector& get_default_detector();

    /**
     * 创建自定义检测器
     */
    [[nodiscard]] static std::unique_ptr<ProtocolDetector> create_detector();
};

} // namespace protocol_parser::detection
