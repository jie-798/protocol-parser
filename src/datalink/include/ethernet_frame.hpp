#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <optional>
#include <string_view>

namespace protocol_parser::datalink {

/**
 * 以太网帧头部结构 (IEEE 802.3)
 * 
 * 帧格式:
 * +----------+----------+------+----------+-----+
 * |   DA     |   SA     | Type |   Data   | FCS |
 * | (6 bytes)| (6 bytes)|(2 B) |          |(4 B)|
 * +----------+----------+------+----------+-----+
 */
struct ethernet_header {
    std::array<uint8_t, 6> destination_mac;  // 目标MAC地址
    std::array<uint8_t, 6> source_mac;       // 源MAC地址
    uint16_t ethertype;                      // 以太网类型/长度
} __attribute__((packed));

static_assert(sizeof(ethernet_header) == 14, "Ethernet header must be 14 bytes");

/**
 * 常见以太网类型定义
 */
namespace ethertype {
    constexpr uint16_t IPV4 = 0x0800;        // IPv4
    constexpr uint16_t ARP  = 0x0806;        // ARP
    constexpr uint16_t VLAN = 0x8100;        // 802.1Q VLAN
    constexpr uint16_t IPV6 = 0x86DD;        // IPv6
    constexpr uint16_t QINQ = 0x88A8;        // 802.1ad QinQ
}

/**
 * 以太网帧解析结果
 */
struct ethernet_frame {
    ethernet_header header;
    std::span<const uint8_t> payload;        // 载荷数据
    uint32_t frame_check_sequence;           // 帧校验序列(如果存在)
    
    // 便利方法
    std::string_view destination_mac_str() const;
    std::string_view source_mac_str() const;
    bool is_broadcast() const;
    bool is_multicast() const;
};

/**
 * 以太网帧解析器
 */
class ethernet_parser {
public:
    /**
     * 解析以太网帧
     * @param data 原始数据
     * @return 解析结果，如果解析失败返回nullopt
     */
    static std::optional<ethernet_frame> parse(std::span<const uint8_t> data);
    
    /**
     * 验证以太网帧的最小长度
     * @param data 原始数据
     * @return 是否满足最小长度要求
     */
    static bool validate_min_length(std::span<const uint8_t> data);
    
    /**
     * 获取下一层协议类型
     * @param frame 以太网帧
     * @return 协议类型
     */
    static uint16_t get_next_protocol(const ethernet_frame& frame);
    
private:
    static constexpr size_t MIN_FRAME_SIZE = 64;   // 最小帧大小(包含FCS)
    static constexpr size_t MAX_FRAME_SIZE = 1518; // 最大帧大小(包含FCS)
    static constexpr size_t HEADER_SIZE = sizeof(ethernet_header);
    static constexpr size_t FCS_SIZE = 4;          // 帧校验序列大小
};

/**
 * MAC地址工具类
 */
class mac_address {
public:
    explicit mac_address(const std::array<uint8_t, 6>& addr) : addr_(addr) {}
    
    std::string to_string() const;
    bool is_broadcast() const;
    bool is_multicast() const;
    bool is_unicast() const;
    
    static std::optional<mac_address> from_string(std::string_view str);
    
    const std::array<uint8_t, 6>& bytes() const { return addr_; }
    
private:
    std::array<uint8_t, 6> addr_;
};

} // namespace protocol_parser::datalink