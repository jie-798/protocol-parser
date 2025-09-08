#pragma once

#include "../base_parser.hpp"
#include "../../core/buffer_view.hpp"
#include <array>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <optional>

namespace protocol_parser::parsers {

// IPv6常量定义
namespace ipv6_constants {
    constexpr size_t IPV6_HEADER_SIZE = 40;
    constexpr size_t IPV6_ADDRESS_SIZE = 16;
    constexpr uint16_t IPV6_VERSION = 6;
    constexpr uint16_t IPV6_VERSION_MASK = 0xF000;
    constexpr uint16_t IPV6_TRAFFIC_CLASS_MASK = 0x0FF0;
    constexpr uint32_t IPV6_FLOW_LABEL_MASK = 0x000FFFFF;
}

// IPv6下一个头部类型
enum class IPv6NextHeader : uint8_t {
    HOP_BY_HOP = 0,
    ICMPV6 = 58,
    TCP = 6,
    UDP = 17,
    ROUTING = 43,
    FRAGMENT = 44,
    DESTINATION_OPTIONS = 60,
    NO_NEXT_HEADER = 59
};

// IPv6基本头部结构
struct IPv6Header {
    uint32_t version_traffic_flow;  // 版本(4) + 流量类别(8) + 流标签(20)
    uint16_t payload_length;        // 载荷长度
    uint8_t next_header;           // 下一个头部
    uint8_t hop_limit;             // 跳数限制
    std::array<uint8_t, 16> src_addr;  // 源地址
    std::array<uint8_t, 16> dst_addr;  // 目的地址

    [[nodiscard]] uint8_t get_version() const noexcept {
        return (version_traffic_flow >> 28) & 0xF;
    }

    [[nodiscard]] uint8_t get_traffic_class() const noexcept {
        return (version_traffic_flow >> 20) & 0xFF;
    }

    [[nodiscard]] uint32_t get_flow_label() const noexcept {
        return version_traffic_flow & 0xFFFFF;
    }
};

// IPv6扩展头部基类
struct IPv6ExtensionHeader {
    uint8_t next_header;
    uint8_t length;
    
    virtual ~IPv6ExtensionHeader() = default;
    [[nodiscard]] virtual size_t get_total_length() const noexcept = 0;
};

// 逐跳选项头部
struct IPv6HopByHopHeader : public IPv6ExtensionHeader {
    std::vector<uint8_t> options;
    
    [[nodiscard]] size_t get_total_length() const noexcept override {
        return (length + 1) * 8;
    }
};

// 路由头部
struct IPv6RoutingHeader : public IPv6ExtensionHeader {
    uint8_t routing_type;
    uint8_t segments_left;
    std::vector<uint8_t> data;
    
    [[nodiscard]] size_t get_total_length() const noexcept override {
        return (length + 1) * 8;
    }
};

// 目的选项头部
struct IPv6DestinationOptionsHeader : public IPv6ExtensionHeader {
    std::vector<uint8_t> options;
    
    [[nodiscard]] size_t get_total_length() const noexcept override {
        return (length + 1) * 8;
    }
};

// IPv6解析结果
struct IPv6ParseResult {
    uint32_t version_class_label;       // 版本(4位) + 流量类别(8位) + 流标签(20位)
    std::array<uint8_t, 16> src_addr;
    std::array<uint8_t, 16> dst_addr;
    uint8_t next_header;
    uint8_t hop_limit;
    uint16_t payload_length;
    size_t header_length;
    bool is_valid;
    std::string error_message;
    
    // 便利方法获取各个字段
    [[nodiscard]] uint8_t get_version() const noexcept {
        return (version_class_label >> 28) & 0x0F;
    }
    
    [[nodiscard]] uint8_t get_traffic_class() const noexcept {
        return (version_class_label >> 20) & 0xFF;
    }
    
    [[nodiscard]] uint32_t get_flow_label() const noexcept {
        return version_class_label & 0xFFFFF;
    }
    
    // 复制构造函数和赋值操作符
    IPv6ParseResult() = default;
    IPv6ParseResult(const IPv6ParseResult&) = default;
    IPv6ParseResult& operator=(const IPv6ParseResult&) = default;
    IPv6ParseResult(IPv6ParseResult&&) = default;
    IPv6ParseResult& operator=(IPv6ParseResult&&) = default;
};

// IPv6解析器类
class IPv6Parser : public BaseParser {
public:
    IPv6Parser() = default;
    ~IPv6Parser() override = default;

    // 实现BaseParser的纯虚函数
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    
    // 便利方法
    [[nodiscard]] ParseResult parse(const core::BufferView& buffer);
    [[nodiscard]] std::string get_protocol_name() const {
        return "IPv6";
    }
    [[nodiscard]] uint16_t get_protocol_type() const {
        return 0x86DD; // IPv6 EtherType
    }

private:
    [[nodiscard]] bool is_extension_header(uint8_t next_header) const;
    [[nodiscard]] bool validate_header(const IPv6Header& header) const noexcept;
};

// IPv6解析器工厂
class IPv6ParserFactory {
public:
    [[nodiscard]] static std::unique_ptr<IPv6Parser> create_parser() {
        return std::make_unique<IPv6Parser>();
    }
    
    [[nodiscard]] static std::vector<uint16_t> get_supported_types() {
        return {0x86DD}; // IPv6 EtherType
    }
};

// IPv6工具函数命名空间
namespace ipv6_utils {
    // 地址格式化
    [[nodiscard]] std::string format_address(const std::array<uint8_t, 16>& addr);
    
    // 地址解析
    [[nodiscard]] std::optional<std::array<uint8_t, 16>> parse_address(const std::string& addr_str);
    
    // 地址类型检查
    [[nodiscard]] bool is_loopback(const std::array<uint8_t, 16>& addr) noexcept;
    [[nodiscard]] bool is_unspecified(const std::array<uint8_t, 16>& addr) noexcept;
    [[nodiscard]] bool is_multicast(const std::array<uint8_t, 16>& addr) noexcept;
    [[nodiscard]] bool is_link_local(const std::array<uint8_t, 16>& addr) noexcept;
    
    // 网络前缀获取
    [[nodiscard]] std::array<uint8_t, 16> get_network_prefix(
        const std::array<uint8_t, 16>& addr, uint8_t prefix_length) noexcept;
    
    // 地址比较
    [[nodiscard]] bool addresses_equal(
        const std::array<uint8_t, 16>& addr1, 
        const std::array<uint8_t, 16>& addr2) noexcept;
    
    [[nodiscard]] int compare_addresses(
        const std::array<uint8_t, 16>& addr1, 
        const std::array<uint8_t, 16>& addr2) noexcept;
    
    // 下一个头部类型名称
    [[nodiscard]] std::string get_next_header_name(uint8_t next_header) noexcept;
    
    // 地址压缩和展开
    [[nodiscard]] std::string compress_address(const std::string& addr);
    [[nodiscard]] std::string expand_address(const std::string& addr);
}

// IPv6伪头部（用于校验和计算）
struct IPv6PseudoHeader {
    std::array<uint8_t, 16> src_addr;
    std::array<uint8_t, 16> dst_addr;
    uint32_t length;
    uint32_t next_header;
};

// 构建伪头部
[[nodiscard]] IPv6PseudoHeader build_pseudo_header(
    const std::array<uint8_t, 16>& src_addr,
    const std::array<uint8_t, 16>& dst_addr,
    uint32_t payload_length,
    uint8_t next_header) noexcept;

} // namespace protocol_parser::parsers