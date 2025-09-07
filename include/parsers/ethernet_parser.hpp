#pragma once

#include "parsers/base_parser.hpp"
#include <array>
#include <optional>

namespace protocol_parser::parsers {

/**
 * 以太网帧类型常量
 */
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t ARP = 0x0806;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t MPLS = 0x8847;
}

/**
 * MAC地址类型
 */
using MacAddress = std::array<uint8_t, 6>;

/**
 * 以太网帧头结构
 */
struct EthernetHeader {
    MacAddress dst_mac;     // 目标MAC地址
    MacAddress src_mac;     // 源MAC地址
    uint16_t ether_type;    // 以太网类型
    
    static constexpr size_t SIZE = 14;
    
    /**
     * 从缓冲区解析以太网头
     */
    static std::expected<EthernetHeader, ParseResult> parse(const core::BufferView& buffer) noexcept;
    
    /**
     * 检查MAC地址是否为广播地址
     */
    [[nodiscard]] bool is_broadcast() const noexcept;
    
    /**
     * 检查MAC地址是否为多播地址
     */
    [[nodiscard]] bool is_multicast() const noexcept;
    
    /**
     * 获取MAC地址字符串表示
     */
    [[nodiscard]] std::string src_mac_string() const;
    [[nodiscard]] std::string dst_mac_string() const;
};

/**
 * VLAN标签结构
 */
struct VlanTag {
    uint16_t tci;           // Tag Control Information
    uint16_t ether_type;    // 内层以太网类型
    
    static constexpr size_t SIZE = 4;
    
    /**
     * 获取VLAN ID
     */
    [[nodiscard]] uint16_t get_vlan_id() const noexcept {
        return tci & 0x0FFF;
    }
    
    /**
     * 获取优先级
     */
    [[nodiscard]] uint8_t get_priority() const noexcept {
        return (tci >> 13) & 0x07;
    }
    
    /**
     * 获取CFI位
     */
    [[nodiscard]] bool get_cfi() const noexcept {
        return (tci >> 12) & 0x01;
    }
};

/**
 * 以太网解析结果
 */
struct EthernetParseResult {
    EthernetHeader header;              // 以太网头
    std::optional<VlanTag> vlan_tag;    // VLAN标签（可选）
    core::BufferView payload;           // 载荷数据
    uint16_t next_protocol;             // 下一层协议类型
};

/**
 * 以太网解析器
 * 支持标准以太网帧和VLAN标签
 */
class EthernetParser : public BaseParser {
public:
    EthernetParser();
    
    // BaseParser接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept override;
    
    /**
     * 获取解析结果
     */
    [[nodiscard]] const EthernetParseResult& get_result() const noexcept {
        return result_;
    }
    
    /**
     * 设置是否解析VLAN标签
     */
    void set_parse_vlan(bool enable) noexcept {
        parse_vlan_ = enable;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    EthernetParseResult result_;
    bool parse_vlan_ = true;
    
    // 状态机处理函数
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_vlan(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
    
    // 辅助函数
    [[nodiscard]] bool is_valid_ether_type(uint16_t ether_type) const noexcept;
    void setup_state_machine();
};

/**
 * 以太网解析器工厂
 */
class EthernetParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<EthernetParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {0x0001};  // 以太网类型标识
    }
};

/**
 * 工具函数
 */
namespace ethernet_utils {
    /**
     * 格式化MAC地址
     */
    [[nodiscard]] std::string format_mac_address(const MacAddress& mac);
    
    /**
     * 解析MAC地址字符串
     */
    [[nodiscard]] std::optional<MacAddress> parse_mac_address(const std::string& mac_str);
    
    /**
     * 检查以太网类型是否有效
     */
    [[nodiscard]] bool is_valid_ether_type(uint16_t ether_type);
    
    /**
     * 获取以太网类型名称
     */
    [[nodiscard]] std::string get_ether_type_name(uint16_t ether_type);
}

} // namespace protocol_parser::parsers