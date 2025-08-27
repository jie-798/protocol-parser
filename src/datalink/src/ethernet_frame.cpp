#include "ethernet_frame.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace protocol_parser::datalink {

// 以太网帧解析器实现
std::optional<ethernet_frame> ethernet_parser::parse(std::span<const uint8_t> data) {
    // 检查最小长度
    if (!validate_min_length(data)) {
        return std::nullopt;
    }
    
    ethernet_frame frame{};
    
    // 解析头部 - 零拷贝方式
    if (data.size() < HEADER_SIZE) {
        return std::nullopt;
    }
    
    std::memcpy(&frame.header, data.data(), HEADER_SIZE);
    
    // 转换字节序（以太网类型字段是大端序）
    frame.header.ethertype = __builtin_bswap16(frame.header.ethertype);
    
    // 计算载荷大小
    size_t payload_size = data.size() - HEADER_SIZE;
    if (payload_size >= FCS_SIZE) {
        payload_size -= FCS_SIZE;
        
        // 提取FCS（如果存在）
        const uint8_t* fcs_ptr = data.data() + data.size() - FCS_SIZE;
        std::memcpy(&frame.frame_check_sequence, fcs_ptr, FCS_SIZE);
        frame.frame_check_sequence = __builtin_bswap32(frame.frame_check_sequence);
    }
    
    // 设置载荷数据
    frame.payload = data.subspan(HEADER_SIZE, payload_size);
    
    return frame;
}

bool ethernet_parser::validate_min_length(std::span<const uint8_t> data) {
    return data.size() >= HEADER_SIZE;
}

uint16_t ethernet_parser::get_next_protocol(const ethernet_frame& frame) {
    return frame.header.ethertype;
}

// 以太网帧便利方法实现
std::string_view ethernet_frame::destination_mac_str() const {
    static thread_local std::string mac_str;
    mac_address mac(header.destination_mac);
    mac_str = mac.to_string();
    return mac_str;
}

std::string_view ethernet_frame::source_mac_str() const {
    static thread_local std::string mac_str;
    mac_address mac(header.source_mac);
    mac_str = mac.to_string();
    return mac_str;
}

bool ethernet_frame::is_broadcast() const {
    mac_address mac(header.destination_mac);
    return mac.is_broadcast();
}

bool ethernet_frame::is_multicast() const {
    mac_address mac(header.destination_mac);
    return mac.is_multicast();
}

// MAC地址工具类实现
std::string mac_address::to_string() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < addr_.size(); ++i) {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(addr_[i]);
    }
    return oss.str();
}

bool mac_address::is_broadcast() const {
    return std::all_of(addr_.begin(), addr_.end(), [](uint8_t byte) {
        return byte == 0xFF;
    });
}

bool mac_address::is_multicast() const {
    return (addr_[0] & 0x01) != 0 && !is_broadcast();
}

bool mac_address::is_unicast() const {
    return !is_multicast() && !is_broadcast();
}

std::optional<mac_address> mac_address::from_string(std::string_view str) {
    std::array<uint8_t, 6> addr{};
    
    // 简单的MAC地址解析（格式：XX:XX:XX:XX:XX:XX）
    if (str.length() != 17) {
        return std::nullopt;
    }
    
    for (size_t i = 0; i < 6; ++i) {
        size_t pos = i * 3;
        if (i > 0 && str[pos - 1] != ':') {
            return std::nullopt;
        }
        
        char* end;
        std::string byte_str(str.substr(pos, 2));
        unsigned long byte_val = std::strtoul(byte_str.c_str(), &end, 16);
        
        if (end != byte_str.c_str() + 2 || byte_val > 255) {
            return std::nullopt;
        }
        
        addr[i] = static_cast<uint8_t>(byte_val);
    }
    
    return mac_address(addr);
}

} // namespace protocol_parser::datalink