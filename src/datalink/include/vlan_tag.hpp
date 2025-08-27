#pragma once

#include <cstdint>
#include <span>
#include <optional>
#include <vector>

namespace protocol_parser::datalink {

/**
 * VLAN标签结构 (IEEE 802.1Q)
 * 
 * 标签格式:
 * +------+-----+-----+----------+
 * | TPID | PCP | DEI |   VID    |
 * |(2 B) |(3b) |(1b)|  (12b)   |
 * +------+-----+-----+----------+
 */
struct vlan_tag {
    uint16_t tpid;          // Tag Protocol Identifier
    uint8_t pcp : 3;        // Priority Code Point
    uint8_t dei : 1;        // Drop Eligible Indicator
    uint16_t vid : 12;      // VLAN Identifier
    
    // 便利构造函数
    vlan_tag() = default;
    vlan_tag(uint16_t tpid_val, uint8_t pcp_val, uint8_t dei_val, uint16_t vid_val)
        : tpid(tpid_val), pcp(pcp_val), dei(dei_val), vid(vid_val) {}
    
    // 从原始数据构造
    static vlan_tag from_bytes(uint16_t tpid_val, uint16_t tci_val);
    
    // 转换为原始字节
    uint16_t to_tci() const;
} __attribute__((packed));

/**
 * VLAN TPID定义
 */
namespace vlan_tpid {
    constexpr uint16_t DOT1Q = 0x8100;       // 802.1Q标准VLAN
    constexpr uint16_t DOT1AD = 0x88A8;      // 802.1ad QinQ外层标签
    constexpr uint16_t DOT1AH = 0x88E7;      // 802.1ah Provider Backbone Bridge
}

/**
 * VLAN优先级定义
 */
namespace vlan_priority {
    constexpr uint8_t BEST_EFFORT = 0;        // 尽力而为
    constexpr uint8_t BACKGROUND = 1;         // 背景流量
    constexpr uint8_t EXCELLENT_EFFORT = 2;   // 优秀努力
    constexpr uint8_t CRITICAL_APPS = 3;      // 关键应用
    constexpr uint8_t VIDEO = 4;              // 视频流量
    constexpr uint8_t VOICE = 5;              // 语音流量
    constexpr uint8_t INTERNETWORK_CONTROL = 6; // 网络控制
    constexpr uint8_t NETWORK_CONTROL = 7;    // 网络管理
}

/**
 * 带VLAN标签的以太网帧
 */
struct vlan_ethernet_frame {
    std::array<uint8_t, 6> destination_mac;  // 目标MAC地址
    std::array<uint8_t, 6> source_mac;       // 源MAC地址
    std::vector<vlan_tag> vlan_tags;         // VLAN标签（支持QinQ）
    uint16_t ethertype;                      // 以太网类型
    std::span<const uint8_t> payload;        // 载荷数据
    
    // 便利方法
    bool has_vlan() const { return !vlan_tags.empty(); }
    bool is_qinq() const { return vlan_tags.size() > 1; }
    uint16_t outer_vid() const { return vlan_tags.empty() ? 0 : vlan_tags[0].vid; }
    uint16_t inner_vid() const { return vlan_tags.size() < 2 ? 0 : vlan_tags[1].vid; }
};

/**
 * VLAN解析器
 */
class vlan_parser {
public:
    /**
     * 解析带VLAN标签的以太网帧
     * @param data 原始数据
     * @return 解析结果，如果解析失败返回nullopt
     */
    static std::optional<vlan_ethernet_frame> parse(std::span<const uint8_t> data);
    
    /**
     * 检查是否为VLAN标签
     * @param ethertype 以太网类型字段
     * @return 是否为VLAN TPID
     */
    static bool is_vlan_tpid(uint16_t ethertype);
    
    /**
     * 解析单个VLAN标签
     * @param data 数据指针
     * @param offset 偏移量
     * @return VLAN标签和下一个偏移量
     */
    static std::pair<vlan_tag, size_t> parse_vlan_tag(std::span<const uint8_t> data, size_t offset);
    
    /**
     * 计算带VLAN标签的帧头部大小
     * @param vlan_count VLAN标签数量
     * @return 头部大小
     */
    static constexpr size_t header_size(size_t vlan_count) {
        return 12 + (vlan_count * 4);  // MAC(12) + VLAN标签(4*N)
    }
    
private:
    static constexpr size_t VLAN_TAG_SIZE = 4;     // VLAN标签大小
    static constexpr size_t MAX_VLAN_TAGS = 2;     // 最大支持的VLAN标签数量
};

/**
 * VLAN配置类型
 */
enum class vlan_port_type {
    ACCESS,     // 接入端口
    TRUNK,      // 干道端口
    HYBRID      // 混合端口
};

/**
 * VLAN端口配置
 */
struct vlan_port_config {
    vlan_port_type type;
    uint16_t native_vlan;           // 本征VLAN（用于TRUNK端口）
    std::vector<uint16_t> allowed_vlans;  // 允许的VLAN列表
    
    // 便利方法
    bool is_vlan_allowed(uint16_t vid) const;
    bool needs_tag(uint16_t vid) const;
};

/**
 * VLAN工具类
 */
class vlan_utils {
public:
    /**
     * 验证VLAN ID有效性
     * @param vid VLAN ID
     * @return 是否有效
     */
    static bool is_valid_vid(uint16_t vid) {
        return vid >= 1 && vid <= 4094;  // 0和4095为保留值
    }
    
    /**
     * 获取优先级描述
     * @param pcp 优先级代码点
     * @return 优先级描述字符串
     */
    static const char* get_priority_name(uint8_t pcp);
    
    /**
     * 计算VLAN标签的字节表示
     * @param tag VLAN标签
     * @return 4字节的标签数据
     */
    static std::array<uint8_t, 4> tag_to_bytes(const vlan_tag& tag);
    
    /**
     * 从字节数据解析VLAN标签
     * @param bytes 4字节的标签数据
     * @return VLAN标签
     */
    static vlan_tag bytes_to_tag(const std::array<uint8_t, 4>& bytes);
};

} // namespace protocol_parser::datalink