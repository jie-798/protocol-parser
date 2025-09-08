#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <array>
#include <optional>
#include <cstdint>

namespace protocol_parser::parsers {

/**
 * ICMPv6消息类型常量
 */
namespace ICMPv6Type {
    // 错误消息 (1-127)
    constexpr uint8_t DEST_UNREACHABLE = 1;
    constexpr uint8_t PACKET_TOO_BIG = 2;
    constexpr uint8_t TIME_EXCEEDED = 3;
    constexpr uint8_t PARAM_PROBLEM = 4;
    
    // 信息消息 (128-255)
    constexpr uint8_t ECHO_REQUEST = 128;
    constexpr uint8_t ECHO_REPLY = 129;
    
    // 邻居发现协议 (Neighbor Discovery Protocol)
    constexpr uint8_t ROUTER_SOLICITATION = 133;
    constexpr uint8_t ROUTER_ADVERTISEMENT = 134;
    constexpr uint8_t NEIGHBOR_SOLICITATION = 135;
    constexpr uint8_t NEIGHBOR_ADVERTISEMENT = 136;
    constexpr uint8_t REDIRECT = 137;
    
    // 多播监听器发现 (Multicast Listener Discovery)
    constexpr uint8_t MLD_QUERY = 130;
    constexpr uint8_t MLD_REPORT = 131;
    constexpr uint8_t MLD_DONE = 132;
}

/**
 * ICMPv6代码常量
 */
namespace ICMPv6Code {
    // 目标不可达代码
    constexpr uint8_t NO_ROUTE = 0;
    constexpr uint8_t ADMIN_PROHIBITED = 1;
    constexpr uint8_t BEYOND_SCOPE = 2;
    constexpr uint8_t ADDR_UNREACHABLE = 3;
    constexpr uint8_t PORT_UNREACHABLE = 4;
    constexpr uint8_t SOURCE_ADDR_FAILED = 5;
    constexpr uint8_t REJECT_ROUTE = 6;
    
    // 时间超时代码
    constexpr uint8_t HOP_LIMIT_EXCEEDED = 0;
    constexpr uint8_t FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1;
    
    // 参数问题代码
    constexpr uint8_t ERRONEOUS_HEADER_FIELD = 0;
    constexpr uint8_t UNRECOGNIZED_NEXT_HEADER = 1;
    constexpr uint8_t UNRECOGNIZED_IPV6_OPTION = 2;
}

/**
 * ICMPv6头部结构
 */
struct ICMPv6Header {
    uint8_t type;       // ICMPv6类型
    uint8_t code;       // ICMPv6代码
    uint16_t checksum;  // 校验和（包含IPv6伪头部）
    uint32_t data;      // 数据字段（根据类型不同含义不同）
    
    static constexpr size_t SIZE = 8;
    
    /**
     * 从缓冲区解析ICMPv6头部
     */
    static std::expected<ICMPv6Header, ParseResult> parse(const core::BufferView& buffer) noexcept;
    
    /**
     * 验证校验和（需要IPv6伪头部）
     */
    [[nodiscard]] bool verify_checksum(const core::BufferView& packet_data, 
                                      const std::array<uint8_t, 16>& src_addr,
                                      const std::array<uint8_t, 16>& dst_addr,
                                      uint32_t payload_length) const noexcept;
    
    /**
     * 计算校验和（包含IPv6伪头部）
     */
    [[nodiscard]] uint16_t calculate_checksum(const core::BufferView& packet_data,
                                             const std::array<uint8_t, 16>& src_addr,
                                             const std::array<uint8_t, 16>& dst_addr,
                                             uint32_t payload_length) const noexcept;
    
    /**
     * 获取标识符（用于Echo请求/回复）
     */
    [[nodiscard]] uint16_t get_identifier() const noexcept {
        return static_cast<uint16_t>(data >> 16);
    }
    
    /**
     * 获取序列号（用于Echo请求/回复）
     */
    [[nodiscard]] uint16_t get_sequence() const noexcept {
        return static_cast<uint16_t>(data & 0xFFFF);
    }
    
    /**
     * 获取MTU（用于Packet Too Big）
     */
    [[nodiscard]] uint32_t get_mtu() const noexcept {
        return data;
    }
    
    /**
     * 获取指针（用于Parameter Problem）
     */
    [[nodiscard]] uint32_t get_pointer() const noexcept {
        return data;
    }
};

/**
 * 邻居发现选项结构
 */
struct NDOption {
    uint8_t type;
    uint8_t length;  // 以8字节为单位
    
    static constexpr uint8_t SOURCE_LINK_LAYER_ADDR = 1;
    static constexpr uint8_t TARGET_LINK_LAYER_ADDR = 2;
    static constexpr uint8_t PREFIX_INFORMATION = 3;
    static constexpr uint8_t REDIRECTED_HEADER = 4;
    static constexpr uint8_t MTU = 5;
};

/**
 * ICMPv6解析结果
 */
struct ICMPv6ParseResult {
    ICMPv6Header header;                    // ICMPv6头部
    core::BufferView payload;               // 载荷数据
    bool checksum_valid = false;            // 校验和是否有效
    size_t payload_length = 0;              // 载荷长度
    std::vector<NDOption> nd_options;       // 邻居发现选项（如果适用）
    
    // 默认构造函数
    ICMPv6ParseResult() = default;
    
    // 拷贝构造函数和赋值运算符
    ICMPv6ParseResult(const ICMPv6ParseResult&) = default;
    ICMPv6ParseResult& operator=(const ICMPv6ParseResult&) = default;
    
    // 移动构造函数和赋值运算符
    ICMPv6ParseResult(ICMPv6ParseResult&&) noexcept = default;
    ICMPv6ParseResult& operator=(ICMPv6ParseResult&&) noexcept = default;
};

/**
 * ICMPv6协议解析器
 */
class ICMPv6Parser : public BaseParser {
public:
    ICMPv6Parser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    /**
     * 获取解析结果
     */
    [[nodiscard]] const ICMPv6ParseResult& get_result() const noexcept {
        return result_;
    }
    
    /**
     * 设置IPv6地址信息（用于校验和计算）
     */
    void set_ipv6_addresses(const std::array<uint8_t, 16>& src_addr,
                           const std::array<uint8_t, 16>& dst_addr) noexcept {
        src_addr_ = src_addr;
        dst_addr_ = dst_addr;
        has_addresses_ = true;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    ICMPv6ParseResult result_;
    std::array<uint8_t, 16> src_addr_{};
    std::array<uint8_t, 16> dst_addr_{};
    bool has_addresses_ = false;
    
    // 状态机处理函数
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
    ParseResult parse_nd_options(ParseContext& context) noexcept;
    
    // 辅助函数
    [[nodiscard]] bool is_valid_type(uint8_t type) const noexcept;
    [[nodiscard]] bool is_error_message(uint8_t type) const noexcept;
    [[nodiscard]] bool is_info_message(uint8_t type) const noexcept;
    [[nodiscard]] bool has_nd_options(uint8_t type) const noexcept;
    void setup_state_machine();
};

/**
 * ICMPv6解析器工厂
 */
class ICMPv6ParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<ICMPv6Parser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {58};  // ICMPv6协议号
    }
};

/**
 * ICMPv6工具函数
 */
namespace icmpv6_utils {
    /**
     * 获取ICMPv6类型名称
     */
    [[nodiscard]] std::string get_type_name(uint8_t type);
    
    /**
     * 获取ICMPv6代码名称
     */
    [[nodiscard]] std::string get_code_name(uint8_t type, uint8_t code);
    
    /**
     * 检查是否为错误消息
     */
    [[nodiscard]] bool is_error_message(uint8_t type);
    
    /**
     * 检查是否为信息消息
     */
    [[nodiscard]] bool is_info_message(uint8_t type);
    
    /**
     * 计算ICMPv6校验和（包含IPv6伪头部）
     */
    [[nodiscard]] uint16_t calculate_checksum(const void* data, size_t length,
                                             const std::array<uint8_t, 16>& src_addr,
                                             const std::array<uint8_t, 16>& dst_addr,
                                             uint32_t payload_length);
    
    /**
     * 验证ICMPv6校验和
     */
    [[nodiscard]] bool verify_checksum(const void* data, size_t length,
                                      const std::array<uint8_t, 16>& src_addr,
                                      const std::array<uint8_t, 16>& dst_addr,
                                      uint32_t payload_length,
                                      uint16_t expected_checksum);
}

} // namespace protocol_parser::parsers