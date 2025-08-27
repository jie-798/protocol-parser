#pragma once

/**
 * 数据链路层协议解析库
 * 
 * 本模块提供以下协议的解析功能：
 * - 以太网帧 (IEEE 802.3)
 * - VLAN标签 (IEEE 802.1Q/802.1ad)
 * - ARP协议 (RFC 826)

 */

#include "ethernet_frame.hpp"
#include "vlan_tag.hpp"
#include "arp_packet.hpp"

namespace protocol_parser::datalink {

/**
 * 数据链路层协议类型
 */
enum class datalink_protocol {
    ETHERNET,
    VLAN,
    ARP,
    UNKNOWN
};

/**
 * 数据链路层解析结果
 */
struct datalink_parse_result {
    datalink_protocol protocol;
    std::span<const uint8_t> remaining_data;
    
    // 协议特定数据（使用variant存储）
    std::variant<
        ethernet_frame,
        vlan_ethernet_frame,
        arp_packet
    > parsed_data;
    
    // 便利方法
    template<typename T>
    std::optional<T> get() const {
        if (std::holds_alternative<T>(parsed_data)) {
            return std::get<T>(parsed_data);
        }
        return std::nullopt;
    }
    
    bool is_ethernet() const { return protocol == datalink_protocol::ETHERNET; }
    bool is_vlan() const { return protocol == datalink_protocol::VLAN; }
    bool is_arp() const { return protocol == datalink_protocol::ARP; }
};

/**
 * 数据链路层统一解析器
 */
class datalink_parser {
public:
    /**
     * 自动检测并解析数据链路层协议
     * @param data 原始数据
     * @return 解析结果
     */
    static std::optional<datalink_parse_result> parse(std::span<const uint8_t> data);
    
    /**
     * 检测协议类型
     * @param data 原始数据
     * @return 协议类型
     */
    static datalink_protocol detect_protocol(std::span<const uint8_t> data);
    
    /**
     * 解析以太网帧（可能包含VLAN标签）
     * @param data 原始数据
     * @return 解析结果
     */
    static std::optional<datalink_parse_result> parse_ethernet(std::span<const uint8_t> data);
    
    /**
     * 解析ARP数据包
     * @param data 原始数据
     * @return 解析结果
     */
    static std::optional<datalink_parse_result> parse_arp(std::span<const uint8_t> data);
    
private:
    static bool is_likely_ethernet(std::span<const uint8_t> data);
    static bool is_likely_arp(std::span<const uint8_t> data);
};

/**
 * 数据链路层统计信息
 */
struct datalink_stats {
    uint64_t total_frames = 0;
    uint64_t ethernet_frames = 0;
    uint64_t vlan_frames = 0;
    uint64_t arp_packets = 0;
    uint64_t broadcast_frames = 0;
    uint64_t multicast_frames = 0;
    uint64_t unicast_frames = 0;
    uint64_t parse_errors = 0;
    
    // 便利方法
    double ethernet_ratio() const {
        return total_frames > 0 ? static_cast<double>(ethernet_frames) / total_frames : 0.0;
    }
    
    double vlan_ratio() const {
        return total_frames > 0 ? static_cast<double>(vlan_frames) / total_frames : 0.0;
    }
    
    double error_ratio() const {
        return total_frames > 0 ? static_cast<double>(parse_errors) / total_frames : 0.0;
    }
    
    void reset() {
        *this = datalink_stats{};
    }
};

/**
 * 数据链路层分析器
 */
class datalink_analyzer {
public:
    /**
     * 分析数据包并更新统计信息
     * @param data 原始数据
     */
    void analyze(std::span<const uint8_t> data);
    
    /**
     * 获取统计信息
     * @return 统计信息
     */
    const datalink_stats& get_stats() const { return stats_; }
    
    /**
     * 重置统计信息
     */
    void reset_stats() { stats_.reset(); }
    
    /**
     * 获取ARP缓存
     * @return ARP缓存引用
     */
    arp_cache& get_arp_cache() { return arp_cache_; }
    
    /**
     * 处理ARP数据包并更新缓存
     * @param packet ARP数据包
     */
    void process_arp_packet(const arp_packet& packet);
    
private:
    datalink_stats stats_;
    arp_cache arp_cache_;
    std::mutex stats_mutex_;
};

/**
 * 数据链路层工具函数
 */
namespace datalink_utils {
    /**
     * 获取协议名称
     * @param protocol 协议类型
     * @return 协议名称
     */
    const char* get_protocol_name(datalink_protocol protocol);
    
    /**
     * 计算以太网帧的CRC32校验和
     * @param data 帧数据（不包含FCS）
     * @return CRC32校验和
     */
    uint32_t calculate_ethernet_crc32(std::span<const uint8_t> data);
    
    /**
     * 验证以太网帧的CRC32校验和
     * @param data 完整帧数据（包含FCS）
     * @return 校验是否正确
     */
    bool verify_ethernet_crc32(std::span<const uint8_t> data);
    
    /**
     * 格式化MAC地址
     * @param mac MAC地址字节数组
     * @param uppercase 是否使用大写字母
     * @param separator 分隔符
     * @return 格式化的MAC地址字符串
     */
    std::string format_mac_address(const std::array<uint8_t, 6>& mac,
                                  bool uppercase = false,
                                  char separator = ':');
    
    /**
     * 解析MAC地址字符串
     * @param mac_str MAC地址字符串
     * @return MAC地址字节数组，如果格式错误返回nullopt
     */
    std::optional<std::array<uint8_t, 6>> parse_mac_address(const std::string& mac_str);
}

} // namespace protocol_parser::datalink