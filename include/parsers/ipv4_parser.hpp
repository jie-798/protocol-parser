#pragma once

#include "parsers/base_parser.hpp"
#include <array>
#include <optional>
#include <vector>

namespace protocol_parser::parsers {

/**
 * IP协议类型常量
 */
namespace IPProtocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
    constexpr uint8_t IPv6 = 41;
    constexpr uint8_t GRE = 47;
    constexpr uint8_t ESP = 50;
    constexpr uint8_t AH = 51;
}

/**
 * IPv4地址类型
 */
using IPv4Address = std::array<uint8_t, 4>;

/**
 * IPv4选项结构
 */
struct IPv4Option {
    uint8_t type;           // 选项类型
    uint8_t length;         // 选项长度
    std::vector<uint8_t> data;  // 选项数据
};

/**
 * IPv4头结构
 */
struct IPv4Header {
    uint8_t version_ihl;        // 版本(4位) + 头长度(4位)
    uint8_t tos;                // 服务类型
    uint16_t total_length;      // 总长度
    uint16_t identification;    // 标识
    uint16_t flags_fragment;    // 标志(3位) + 片偏移(13位)
    uint8_t ttl;                // 生存时间
    uint8_t protocol;           // 协议
    uint16_t checksum;          // 头校验和
    IPv4Address src_ip;         // 源IP地址
    IPv4Address dst_ip;         // 目标IP地址
    
    static constexpr size_t MIN_SIZE = 20;
    static constexpr size_t MAX_SIZE = 60;
    
    /**
     * 从缓冲区解析IPv4头
     */
    static std::expected<IPv4Header, ParseResult> parse(const core::BufferView& buffer) noexcept;
    
    /**
     * 获取版本号
     */
    [[nodiscard]] uint8_t get_version() const noexcept {
        return (version_ihl >> 4) & 0x0F;
    }
    
    /**
     * 获取头长度（字节数）
     */
    [[nodiscard]] uint8_t get_header_length() const noexcept {
        return (version_ihl & 0x0F) * 4;
    }
    
    /**
     * 获取DSCP值
     */
    [[nodiscard]] uint8_t get_dscp() const noexcept {
        return (tos >> 2) & 0x3F;
    }
    
    /**
     * 获取ECN值
     */
    [[nodiscard]] uint8_t get_ecn() const noexcept {
        return tos & 0x03;
    }
    
    /**
     * 检查是否有更多分片
     */
    [[nodiscard]] bool has_more_fragments() const noexcept {
        return (flags_fragment & 0x2000) != 0;
    }
    
    /**
     * 检查是否禁止分片
     */
    [[nodiscard]] bool dont_fragment() const noexcept {
        return (flags_fragment & 0x4000) != 0;
    }
    
    /**
     * 获取分片偏移
     */
    [[nodiscard]] uint16_t get_fragment_offset() const noexcept {
        return (flags_fragment & 0x1FFF) * 8;
    }
    
    /**
     * 检查是否为分片包
     */
    [[nodiscard]] bool is_fragment() const noexcept {
        return has_more_fragments() || get_fragment_offset() != 0;
    }
    
    /**
     * 验证校验和
     */
    [[nodiscard]] bool verify_checksum(const core::BufferView& header_data) const noexcept;
    
    /**
     * 计算校验和
     */
    [[nodiscard]] uint16_t calculate_checksum(const core::BufferView& header_data) const noexcept;
    
    /**
     * 获取IP地址字符串表示
     */
    [[nodiscard]] std::string src_ip_string() const;
    [[nodiscard]] std::string dst_ip_string() const;
};

/**
 * IPv4解析结果
 */
struct IPv4ParseResult {
    IPv4Header header;                      // IPv4头
    std::vector<IPv4Option> options;        // IP选项
    core::BufferView payload;               // 载荷数据
    bool checksum_valid = false;            // 校验和是否有效
};

/**
 * IPv4解析器
 * 支持选项解析和分片重组
 */
class IPv4Parser : public BaseParser {
public:
    IPv4Parser();
    
    // BaseParser接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    /**
     * 获取解析结果
     */
    [[nodiscard]] const IPv4ParseResult& get_result() const noexcept {
        return result_;
    }
    
    /**
     * 设置是否验证校验和
     */
    void set_verify_checksum(bool enable) noexcept {
        verify_checksum_ = enable;
    }
    
    /**
     * 设置是否解析选项
     */
    void set_parse_options(bool enable) noexcept {
        parse_options_ = enable;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    IPv4ParseResult result_;
    bool verify_checksum_ = true;
    bool parse_options_ = true;
    
    // 状态机处理函数
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_options(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
    
    // 辅助函数
    ParseResult parse_single_option(const core::BufferView& buffer, size_t& offset, IPv4Option& option) noexcept;
    void setup_state_machine();
};

/**
 * IPv4解析器工厂
 */
class IPv4ParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<IPv4Parser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {0x0800};  // IPv4 EtherType
    }
};

/**
 * 工具函数
 */
namespace ipv4_utils {
    /**
     * 格式化IPv4地址
     */
    [[nodiscard]] std::string format_ipv4_address(const IPv4Address& ip);
    
    /**
     * 解析IPv4地址字符串
     */
    [[nodiscard]] std::optional<IPv4Address> parse_ipv4_address(const std::string& ip_str);
    
    /**
     * 计算IPv4校验和
     */
    [[nodiscard]] uint16_t calculate_checksum(const void* data, size_t length);
    
    /**
     * 检查IP地址类型
     */
    [[nodiscard]] bool is_private_address(const IPv4Address& ip);
    [[nodiscard]] bool is_multicast_address(const IPv4Address& ip);
    [[nodiscard]] bool is_broadcast_address(const IPv4Address& ip);
    [[nodiscard]] bool is_loopback_address(const IPv4Address& ip);
    
    /**
     * 获取协议名称
     */
    [[nodiscard]] std::string get_protocol_name(uint8_t protocol);
    
    /**
     * IP选项解析
     */
    [[nodiscard]] std::string get_option_name(uint8_t option_type);
}

} // namespace protocol_parser::parsers