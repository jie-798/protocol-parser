#include "vlan_tag.hpp"
#include <cstring>
#include <algorithm>

namespace protocol_parser::datalink {

// VLAN标签静态方法实现
vlan_tag vlan_tag::from_bytes(uint16_t tpid_val, uint16_t tci_val) {
    vlan_tag tag;
    tag.tpid = tpid_val;
    tag.pcp = (tci_val >> 13) & 0x07;
    tag.dei = (tci_val >> 12) & 0x01;
    tag.vid = tci_val & 0x0FFF;
    return tag;
}

uint16_t vlan_tag::to_tci() const {
    return (static_cast<uint16_t>(pcp) << 13) |
           (static_cast<uint16_t>(dei) << 12) |
           (vid & 0x0FFF);
}

// VLAN解析器实现
std::optional<vlan_ethernet_frame> vlan_parser::parse(std::span<const uint8_t> data) {
    if (data.size() < 14) {  // 最小以太网头部大小
        return std::nullopt;
    }
    
    vlan_ethernet_frame frame;
    size_t offset = 0;
    
    // 解析MAC地址
    std::memcpy(frame.destination_mac.data(), data.data() + offset, 6);
    offset += 6;
    std::memcpy(frame.source_mac.data(), data.data() + offset, 6);
    offset += 6;
    
    // 解析VLAN标签
    while (offset + 4 <= data.size()) {
        uint16_t ethertype_or_tpid;
        std::memcpy(&ethertype_or_tpid, data.data() + offset, 2);
        ethertype_or_tpid = __builtin_bswap16(ethertype_or_tpid);
        
        if (is_vlan_tpid(ethertype_or_tpid)) {
            // 这是一个VLAN标签
            auto [tag, next_offset] = parse_vlan_tag(data, offset);
            frame.vlan_tags.push_back(tag);
            offset = next_offset;
            
            // 限制VLAN标签数量
            if (frame.vlan_tags.size() >= MAX_VLAN_TAGS) {
                break;
            }
        } else {
            // 这是EtherType
            frame.ethertype = ethertype_or_tpid;
            offset += 2;
            break;
        }
    }
    
    // 设置载荷
    if (offset < data.size()) {
        frame.payload = data.subspan(offset);
    }
    
    return frame;
}

bool vlan_parser::is_vlan_tpid(uint16_t ethertype) {
    return ethertype == vlan_tpid::DOT1Q ||
           ethertype == vlan_tpid::DOT1AD ||
           ethertype == vlan_tpid::DOT1AH;
}

std::pair<vlan_tag, size_t> vlan_parser::parse_vlan_tag(std::span<const uint8_t> data, size_t offset) {
    vlan_tag tag;
    
    // 解析TPID
    std::memcpy(&tag.tpid, data.data() + offset, 2);
    tag.tpid = __builtin_bswap16(tag.tpid);
    
    // 解析TCI
    uint16_t tci;
    std::memcpy(&tci, data.data() + offset + 2, 2);
    tci = __builtin_bswap16(tci);
    
    tag.pcp = (tci >> 13) & 0x07;
    tag.dei = (tci >> 12) & 0x01;
    tag.vid = tci & 0x0FFF;
    
    return {tag, offset + VLAN_TAG_SIZE};
}

// VLAN端口配置实现
bool vlan_port_config::is_vlan_allowed(uint16_t vid) const {
    return std::find(allowed_vlans.begin(), allowed_vlans.end(), vid) != allowed_vlans.end();
}

bool vlan_port_config::needs_tag(uint16_t vid) const {
    switch (type) {
        case vlan_port_type::ACCESS:
            return false;  // 接入端口不打标签
        case vlan_port_type::TRUNK:
            return vid != native_vlan;  // 干道端口除本征VLAN外都打标签
        case vlan_port_type::HYBRID:
            // 混合端口的标签策略需要更复杂的配置
            return vid != native_vlan;
        default:
            return false;
    }
}

// VLAN工具类实现
const char* vlan_utils::get_priority_name(uint8_t pcp) {
    switch (pcp) {
        case vlan_priority::BEST_EFFORT: return "Best Effort";
        case vlan_priority::BACKGROUND: return "Background";
        case vlan_priority::EXCELLENT_EFFORT: return "Excellent Effort";
        case vlan_priority::CRITICAL_APPS: return "Critical Applications";
        case vlan_priority::VIDEO: return "Video";
        case vlan_priority::VOICE: return "Voice";
        case vlan_priority::INTERNETWORK_CONTROL: return "Internetwork Control";
        case vlan_priority::NETWORK_CONTROL: return "Network Control";
        default: return "Unknown";
    }
}

std::array<uint8_t, 4> vlan_utils::tag_to_bytes(const vlan_tag& tag) {
    std::array<uint8_t, 4> bytes;
    
    // TPID (大端序)
    uint16_t tpid_be = __builtin_bswap16(tag.tpid);
    std::memcpy(bytes.data(), &tpid_be, 2);
    
    // TCI (大端序)
    uint16_t tci = tag.to_tci();
    uint16_t tci_be = __builtin_bswap16(tci);
    std::memcpy(bytes.data() + 2, &tci_be, 2);
    
    return bytes;
}

vlan_tag vlan_utils::bytes_to_tag(const std::array<uint8_t, 4>& bytes) {
    vlan_tag tag;
    
    // 解析TPID
    uint16_t tpid_be;
    std::memcpy(&tpid_be, bytes.data(), 2);
    tag.tpid = __builtin_bswap16(tpid_be);
    
    // 解析TCI
    uint16_t tci_be;
    std::memcpy(&tci_be, bytes.data() + 2, 2);
    uint16_t tci = __builtin_bswap16(tci_be);
    
    tag.pcp = (tci >> 13) & 0x07;
    tag.dei = (tci >> 12) & 0x01;
    tag.vid = tci & 0x0FFF;
    
    return tag;
}

} // namespace protocol_parser::datalink