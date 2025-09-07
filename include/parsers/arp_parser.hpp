#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <array>
#include <optional>
#include <cstdint>

namespace protocol_parser::parsers {

/**
 * ARP操作码常量
 */
namespace ARPOpcode {
    constexpr uint16_t REQUEST = 1;     // ARP请求
    constexpr uint16_t REPLY = 2;       // ARP回复
    constexpr uint16_t RARP_REQUEST = 3; // RARP请求
    constexpr uint16_t RARP_REPLY = 4;   // RARP回复
}

/**
 * ARP硬件类型常量
 */
namespace ARPHardwareType {
    constexpr uint16_t ETHERNET = 1;    // 以太网
    constexpr uint16_t IEEE802 = 6;     // IEEE 802网络
    constexpr uint16_t ARCNET = 7;      // ARCNET
    constexpr uint16_t FRAME_RELAY = 15; // 帧中继
    constexpr uint16_t ATM = 16;        // ATM
    constexpr uint16_t HDLC = 17;       // HDLC
    constexpr uint16_t FIBRE_CHANNEL = 18; // 光纤通道
}

/**
 * ARP协议类型常量
 */
namespace ARPProtocolType {
    constexpr uint16_t IPV4 = 0x0800;   // IPv4
    constexpr uint16_t IPV6 = 0x86DD;   // IPv6
}

/**
 * MAC地址类型定义
 */
using MacAddress = std::array<uint8_t, 6>;

/**
 * IPv4地址类型定义
 */
using IPv4Address = std::array<uint8_t, 4>;

/**
 * ARP头部结构
 */
struct ARPHeader {
    uint16_t hardware_type;     // 硬件类型
    uint16_t protocol_type;     // 协议类型
    uint8_t hardware_length;    // 硬件地址长度
    uint8_t protocol_length;    // 协议地址长度
    uint16_t opcode;           // 操作码
    MacAddress sender_mac;      // 发送方MAC地址
    IPv4Address sender_ip;      // 发送方IP地址
    MacAddress target_mac;      // 目标MAC地址
    IPv4Address target_ip;      // 目标IP地址
    
    static constexpr size_t SIZE = 28;
    
    /**
     * 从缓冲区解析ARP头部
     */
    static std::expected<ARPHeader, ParseResult> parse(const core::BufferView& buffer) noexcept;
    
    /**
     * 检查是否为有效的ARP包
     */
    [[nodiscard]] bool is_valid() const noexcept;
    
    /**
     * 检查是否为以太网ARP
     */
    [[nodiscard]] bool is_ethernet_arp() const noexcept {
        return hardware_type == ARPHardwareType::ETHERNET && 
               hardware_length == 6;
    }
    
    /**
     * 检查是否为IPv4 ARP
     */
    [[nodiscard]] bool is_ipv4_arp() const noexcept {
        return protocol_type == ARPProtocolType::IPV4 && 
               protocol_length == 4;
    }
    
    /**
     * 检查是否为ARP请求
     */
    [[nodiscard]] bool is_request() const noexcept {
        return opcode == ARPOpcode::REQUEST;
    }
    
    /**
     * 检查是否为ARP回复
     */
    [[nodiscard]] bool is_reply() const noexcept {
        return opcode == ARPOpcode::REPLY;
    }
    
    /**
     * 获取发送方MAC地址字符串
     */
    [[nodiscard]] std::string sender_mac_string() const;
    
    /**
     * 获取目标MAC地址字符串
     */
    [[nodiscard]] std::string target_mac_string() const;
    
    /**
     * 获取发送方IP地址字符串
     */
    [[nodiscard]] std::string sender_ip_string() const;
    
    /**
     * 获取目标IP地址字符串
     */
    [[nodiscard]] std::string target_ip_string() const;
};

/**
 * ARP解析结果
 */
struct ARPParseResult {
    ARPHeader header;               // ARP头部
    core::BufferView extra_data;    // 额外数据（如果有）
    size_t total_length = 0;        // 总长度
    
    // 移动构造函数
    ARPParseResult(ARPParseResult&&) noexcept = default;
    ARPParseResult& operator=(ARPParseResult&&) noexcept = default;
    
    // 禁用拷贝构造
    ARPParseResult(const ARPParseResult&) = delete;
    ARPParseResult& operator=(const ARPParseResult&) = delete;
    
    ARPParseResult() = default;
};

/**
 * ARP协议解析器
 */
class ARPParser : public BaseParser {
public:
    ARPParser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    /**
     * 获取解析结果
     */
    [[nodiscard]] const ARPParseResult& get_result() const noexcept {
        return result_;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    ARPParseResult result_;
    
    // 状态机处理函数
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_extra_data(ParseContext& context) noexcept;
    
    // 辅助函数
    [[nodiscard]] bool is_supported_hardware_type(uint16_t hw_type) const noexcept;
    [[nodiscard]] bool is_supported_protocol_type(uint16_t proto_type) const noexcept;
    void setup_state_machine();
};

/**
 * ARP解析器工厂
 */
class ARPParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<ARPParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {0x0806};  // ARP以太网类型
    }
};

/**
 * ARP工具函数
 */
namespace arp_utils {
    /**
     * 格式化MAC地址
     */
    [[nodiscard]] std::string format_mac_address(const MacAddress& mac);
    
    /**
     * 解析MAC地址字符串
     */
    [[nodiscard]] std::optional<MacAddress> parse_mac_address(const std::string& mac_str);
    
    /**
     * 格式化IPv4地址
     */
    [[nodiscard]] std::string format_ipv4_address(const IPv4Address& ip);
    
    /**
     * 解析IPv4地址字符串
     */
    [[nodiscard]] std::optional<IPv4Address> parse_ipv4_address(const std::string& ip_str);
    
    /**
     * 获取硬件类型名称
     */
    [[nodiscard]] std::string get_hardware_type_name(uint16_t hw_type);
    
    /**
     * 获取协议类型名称
     */
    [[nodiscard]] std::string get_protocol_type_name(uint16_t proto_type);
    
    /**
     * 获取操作码名称
     */
    [[nodiscard]] std::string get_opcode_name(uint16_t opcode);
    
    /**
     * 检查MAC地址是否为广播地址
     */
    [[nodiscard]] bool is_broadcast_mac(const MacAddress& mac);
    
    /**
     * 检查MAC地址是否为零地址
     */
    [[nodiscard]] bool is_zero_mac(const MacAddress& mac);
    
    /**
     * 检查IP地址是否为零地址
     */
    [[nodiscard]] bool is_zero_ip(const IPv4Address& ip);
    
    /**
     * 创建ARP请求包
     */
    [[nodiscard]] std::vector<uint8_t> create_arp_request(
        const MacAddress& sender_mac,
        const IPv4Address& sender_ip,
        const IPv4Address& target_ip
    );
    
    /**
     * 创建ARP回复包
     */
    [[nodiscard]] std::vector<uint8_t> create_arp_reply(
        const MacAddress& sender_mac,
        const IPv4Address& sender_ip,
        const MacAddress& target_mac,
        const IPv4Address& target_ip
    );
}

} // namespace protocol_parser::parsers