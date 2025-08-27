#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <optional>
#include <string>

namespace protocol_parser::datalink {

/**
 * ARP数据包结构 (RFC 826)
 * 
 * 数据包格式:
 * +--------+--------+-------+-------+--------+----------+----------+----------+----------+
 * | HTYPE  | PTYPE  | HLEN  | PLEN  |   OP   |   SHA    |   SPA    |   THA    |   TPA    |
 * |(2 B)   |(2 B)   |(1 B)  |(1 B)  | (2 B)  | (6 B)    | (4 B)    | (6 B)    | (4 B)    |
 * +--------+--------+-------+-------+--------+----------+----------+----------+----------+
 */
struct arp_header {
    uint16_t hardware_type;                  // 硬件类型
    uint16_t protocol_type;                  // 协议类型
    uint8_t hardware_length;                 // 硬件地址长度
    uint8_t protocol_length;                 // 协议地址长度
    uint16_t operation;                      // 操作类型
    std::array<uint8_t, 6> sender_hw_addr;  // 发送方硬件地址
    std::array<uint8_t, 4> sender_proto_addr; // 发送方协议地址
    std::array<uint8_t, 6> target_hw_addr;  // 目标硬件地址
    std::array<uint8_t, 4> target_proto_addr; // 目标协议地址
} __attribute__((packed));

static_assert(sizeof(arp_header) == 28, "ARP header must be 28 bytes");

/**
 * ARP硬件类型定义
 */
namespace arp_hardware_type {
    constexpr uint16_t ETHERNET = 1;         // 以太网
    constexpr uint16_t IEEE802 = 6;          // IEEE 802网络
    constexpr uint16_t ARCNET = 7;           // ARCNET
    constexpr uint16_t FRAME_RELAY = 15;     // 帧中继
    constexpr uint16_t ATM = 16;             // ATM
    constexpr uint16_t HDLC = 17;            // HDLC
    constexpr uint16_t FIBRE_CHANNEL = 18;   // 光纤通道
}

/**
 * ARP协议类型定义
 */
namespace arp_protocol_type {
    constexpr uint16_t IPV4 = 0x0800;        // IPv4
    constexpr uint16_t IPV6 = 0x86DD;        // IPv6
}

/**
 * ARP操作类型定义
 */
namespace arp_operation {
    constexpr uint16_t REQUEST = 1;          // ARP请求
    constexpr uint16_t REPLY = 2;            // ARP应答
    constexpr uint16_t RARP_REQUEST = 3;     // RARP请求
    constexpr uint16_t RARP_REPLY = 4;       // RARP应答
    constexpr uint16_t DRARP_REQUEST = 5;    // 动态RARP请求
    constexpr uint16_t DRARP_REPLY = 6;      // 动态RARP应答
    constexpr uint16_t DRARP_ERROR = 7;      // 动态RARP错误
    constexpr uint16_t INARP_REQUEST = 8;    // 逆向ARP请求
    constexpr uint16_t INARP_REPLY = 9;      // 逆向ARP应答
}

/**
 * ARP数据包解析结果
 */
struct arp_packet {
    arp_header header;
    
    // 便利方法
    std::string sender_ip_str() const;
    std::string target_ip_str() const;
    std::string sender_mac_str() const;
    std::string target_mac_str() const;
    bool is_request() const { return header.operation == arp_operation::REQUEST; }
    bool is_reply() const { return header.operation == arp_operation::REPLY; }
    bool is_ethernet_ipv4() const {
        return header.hardware_type == arp_hardware_type::ETHERNET &&
               header.protocol_type == arp_protocol_type::IPV4;
    }
};

/**
 * ARP解析器
 */
class arp_parser {
public:
    /**
     * 解析ARP数据包
     * @param data 原始数据
     * @return 解析结果，如果解析失败返回nullopt
     */
    static std::optional<arp_packet> parse(std::span<const uint8_t> data);
    
    /**
     * 验证ARP数据包的有效性
     * @param data 原始数据
     * @return 是否有效
     */
    static bool validate(std::span<const uint8_t> data);
    
    /**
     * 检查是否为标准以太网IPv4 ARP
     * @param packet ARP数据包
     * @return 是否为标准格式
     */
    static bool is_standard_ethernet_ipv4(const arp_packet& packet);
    
private:
    static constexpr size_t MIN_ARP_SIZE = sizeof(arp_header);
};

/**
 * ARP缓存条目
 */
struct arp_cache_entry {
    std::array<uint8_t, 4> ip_addr;          // IP地址
    std::array<uint8_t, 6> mac_addr;         // MAC地址
    uint64_t timestamp;                      // 时间戳
    bool is_static;                          // 是否为静态条目
    
    // 便利方法
    std::string ip_str() const;
    std::string mac_str() const;
    bool is_expired(uint64_t current_time, uint64_t timeout) const;
};

/**
 * ARP缓存管理器
 */
class arp_cache {
public:
    /**
     * 添加ARP缓存条目
     * @param ip_addr IP地址
     * @param mac_addr MAC地址
     * @param is_static 是否为静态条目
     */
    void add_entry(const std::array<uint8_t, 4>& ip_addr,
                   const std::array<uint8_t, 6>& mac_addr,
                   bool is_static = false);
    
    /**
     * 查找ARP缓存条目
     * @param ip_addr IP地址
     * @return 缓存条目，如果不存在返回nullopt
     */
    std::optional<arp_cache_entry> lookup(const std::array<uint8_t, 4>& ip_addr) const;
    
    /**
     * 删除ARP缓存条目
     * @param ip_addr IP地址
     * @return 是否成功删除
     */
    bool remove_entry(const std::array<uint8_t, 4>& ip_addr);
    
    /**
     * 清理过期条目
     * @param timeout 超时时间（秒）
     * @return 清理的条目数量
     */
    size_t cleanup_expired(uint64_t timeout = 300);
    
    /**
     * 获取所有缓存条目
     * @return 缓存条目列表
     */
    std::vector<arp_cache_entry> get_all_entries() const;
    
    /**
     * 清空缓存
     */
    void clear();
    
    /**
     * 获取缓存大小
     * @return 缓存条目数量
     */
    size_t size() const;
    
private:
    std::unordered_map<uint32_t, arp_cache_entry> cache_;
    mutable std::shared_mutex mutex_;
    
    uint32_t ip_to_key(const std::array<uint8_t, 4>& ip_addr) const;
    uint64_t get_current_timestamp() const;
};

/**
 * ARP工具类
 */
class arp_utils {
public:
    /**
     * 创建ARP请求数据包
     * @param sender_mac 发送方MAC地址
     * @param sender_ip 发送方IP地址
     * @param target_ip 目标IP地址
     * @return ARP请求数据包
     */
    static arp_packet create_request(const std::array<uint8_t, 6>& sender_mac,
                                   const std::array<uint8_t, 4>& sender_ip,
                                   const std::array<uint8_t, 4>& target_ip);
    
    /**
     * 创建ARP应答数据包
     * @param sender_mac 发送方MAC地址
     * @param sender_ip 发送方IP地址
     * @param target_mac 目标MAC地址
     * @param target_ip 目标IP地址
     * @return ARP应答数据包
     */
    static arp_packet create_reply(const std::array<uint8_t, 6>& sender_mac,
                                 const std::array<uint8_t, 4>& sender_ip,
                                 const std::array<uint8_t, 6>& target_mac,
                                 const std::array<uint8_t, 4>& target_ip);
    
    /**
     * 将ARP数据包序列化为字节数组
     * @param packet ARP数据包
     * @return 字节数组
     */
    static std::array<uint8_t, 28> serialize(const arp_packet& packet);
    
    /**
     * 获取操作类型描述
     * @param operation 操作类型
     * @return 操作描述字符串
     */
    static const char* get_operation_name(uint16_t operation);
    
    /**
     * 获取硬件类型描述
     * @param hw_type 硬件类型
     * @return 硬件类型描述字符串
     */
    static const char* get_hardware_type_name(uint16_t hw_type);
    
    /**
     * IP地址转字符串
     * @param ip_addr IP地址字节数组
     * @return IP地址字符串
     */
    static std::string ip_to_string(const std::array<uint8_t, 4>& ip_addr);
    
    /**
     * 字符串转IP地址
     * @param ip_str IP地址字符串
     * @return IP地址字节数组，如果格式错误返回nullopt
     */
    static std::optional<std::array<uint8_t, 4>> string_to_ip(const std::string& ip_str);
};

} // namespace protocol_parser::datalink