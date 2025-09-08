#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <array>
#include <optional>
#include <cstdint>

namespace protocol_parser::parsers {

/**
 * ICMP消息类型常量
 */
namespace ICMPType {
    // ICMPv4类型
    constexpr uint8_t ECHO_REPLY = 0;
    constexpr uint8_t DEST_UNREACHABLE = 3;
    constexpr uint8_t SOURCE_QUENCH = 4;
    constexpr uint8_t REDIRECT = 5;
    constexpr uint8_t ECHO_REQUEST = 8;
    constexpr uint8_t TIME_EXCEEDED = 11;
    constexpr uint8_t PARAM_PROBLEM = 12;
    constexpr uint8_t TIMESTAMP_REQ = 13;
    constexpr uint8_t TIMESTAMP_REP = 14;
    constexpr uint8_t INFO_REQ = 15;
    constexpr uint8_t INFO_REP = 16;
    
    // ICMPv6类型
    constexpr uint8_t DEST_UNREACHABLE_V6 = 1;
    constexpr uint8_t PACKET_TOO_BIG = 2;
    constexpr uint8_t TIME_EXCEEDED_V6 = 3;
    constexpr uint8_t PARAM_PROBLEM_V6 = 4;
    constexpr uint8_t ECHO_REQUEST_V6 = 128;
    constexpr uint8_t ECHO_REPLY_V6 = 129;
    constexpr uint8_t ROUTER_SOLICITATION = 133;
    constexpr uint8_t ROUTER_ADVERTISEMENT = 134;
    constexpr uint8_t NEIGHBOR_SOLICITATION = 135;
    constexpr uint8_t NEIGHBOR_ADVERTISEMENT = 136;
    constexpr uint8_t REDIRECT_V6 = 137;
}

/**
 * ICMP代码常量
 */
namespace ICMPCode {
    // 目标不可达代码
    constexpr uint8_t NET_UNREACHABLE = 0;
    constexpr uint8_t HOST_UNREACHABLE = 1;
    constexpr uint8_t PROTOCOL_UNREACHABLE = 2;
    constexpr uint8_t PORT_UNREACHABLE = 3;
    constexpr uint8_t FRAGMENTATION_NEEDED = 4;
    constexpr uint8_t SOURCE_ROUTE_FAILED = 5;
    
    // 时间超时代码
    constexpr uint8_t TTL_EXCEEDED = 0;
    constexpr uint8_t FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1;
}

/**
 * ICMP头部结构
 */
struct ICMPHeader {
    uint8_t type;       // ICMP类型
    uint8_t code;       // ICMP代码
    uint16_t checksum;  // 校验和
    uint32_t rest;      // 剩余字段（根据类型不同含义不同）
    
    static constexpr size_t SIZE = 8;
    
    /**
     * 从缓冲区解析ICMP头部
     */
    static std::expected<ICMPHeader, ParseResult> parse(const core::BufferView& buffer) noexcept;
    
    /**
     * 验证校验和
     */
    [[nodiscard]] bool verify_checksum(const core::BufferView& packet_data) const noexcept;
    
    /**
     * 计算校验和
     */
    [[nodiscard]] uint16_t calculate_checksum(const core::BufferView& packet_data) const noexcept;
    
    /**
     * 获取标识符（用于Echo请求/回复）
     */
    [[nodiscard]] uint16_t get_identifier() const noexcept {
        return static_cast<uint16_t>(rest >> 16);
    }
    
    /**
     * 获取序列号（用于Echo请求/回复）
     */
    [[nodiscard]] uint16_t get_sequence() const noexcept {
        return static_cast<uint16_t>(rest & 0xFFFF);
    }
    
    /**
     * 获取MTU（用于Packet Too Big）
     */
    [[nodiscard]] uint32_t get_mtu() const noexcept {
        return rest;
    }
    
    /**
     * 获取网关地址（用于重定向）
     */
    [[nodiscard]] uint32_t get_gateway() const noexcept {
        return rest;
    }
};

/**
 * ICMP解析结果
 */
struct ICMPParseResult {
    ICMPHeader header;              // ICMP头部
    core::BufferView payload;       // 载荷数据
    bool checksum_valid = false;    // 校验和是否有效
    bool is_ipv6 = false;          // 是否为ICMPv6
    size_t payload_length = 0;      // 载荷长度
    
    // 默认构造函数
    ICMPParseResult() = default;
    
    // 拷贝构造函数和赋值运算符
    ICMPParseResult(const ICMPParseResult&) = default;
    ICMPParseResult& operator=(const ICMPParseResult&) = default;
    
    // 移动构造函数和赋值运算符
    ICMPParseResult(ICMPParseResult&&) noexcept = default;
    ICMPParseResult& operator=(ICMPParseResult&&) noexcept = default;
};

/**
 * ICMP协议解析器
 */
class ICMPParser : public BaseParser {
public:
    ICMPParser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    /**
     * 获取解析结果
     */
    [[nodiscard]] const ICMPParseResult& get_result() const noexcept {
        return result_;
    }
    
    /**
     * 设置是否为IPv6模式
     */
    void set_ipv6_mode(bool is_ipv6) noexcept {
        is_ipv6_mode_ = is_ipv6;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    ICMPParseResult result_;
    bool is_ipv6_mode_ = false;
    
    // 状态机处理函数
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
    
    // 辅助函数
    [[nodiscard]] bool is_valid_type(uint8_t type) const noexcept;
    void setup_state_machine();
};

/**
 * ICMP解析器工厂
 */
class ICMPParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<ICMPParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {1, 58};  // ICMP (1) 和 ICMPv6 (58)
    }
};

/**
 * ICMP工具函数
 */
namespace icmp_utils {
    /**
     * 获取ICMP类型名称
     */
    [[nodiscard]] std::string get_type_name(uint8_t type, bool is_ipv6 = false);
    
    /**
     * 获取ICMP代码名称
     */
    [[nodiscard]] std::string get_code_name(uint8_t type, uint8_t code, bool is_ipv6 = false);
    
    /**
     * 检查是否为错误消息
     */
    [[nodiscard]] bool is_error_message(uint8_t type, bool is_ipv6 = false);
    
    /**
     * 检查是否为信息消息
     */
    [[nodiscard]] bool is_info_message(uint8_t type, bool is_ipv6 = false);
    
    /**
     * 计算ICMP校验和
     */
    [[nodiscard]] uint16_t calculate_checksum(const void* data, size_t length);
    
    /**
     * 验证ICMP校验和
     */
    [[nodiscard]] bool verify_checksum(const void* data, size_t length, uint16_t expected_checksum);
}

} // namespace protocol_parser::parsers