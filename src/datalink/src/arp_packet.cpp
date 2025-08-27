#include "arp_packet.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <shared_mutex>
#include <unordered_map>

namespace protocol_parser::datalink {

// ARP数据包便利方法实现
std::string arp_packet::sender_ip_str() const {
    return arp_utils::ip_to_string(header.sender_proto_addr);
}

std::string arp_packet::target_ip_str() const {
    return arp_utils::ip_to_string(header.target_proto_addr);
}

std::string arp_packet::sender_mac_str() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < header.sender_hw_addr.size(); ++i) {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(header.sender_hw_addr[i]);
    }
    return oss.str();
}

std::string arp_packet::target_mac_str() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < header.target_hw_addr.size(); ++i) {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(header.target_hw_addr[i]);
    }
    return oss.str();
}

// ARP解析器实现
std::optional<arp_packet> arp_parser::parse(std::span<const uint8_t> data) {
    if (!validate(data)) {
        return std::nullopt;
    }
    
    arp_packet packet;
    std::memcpy(&packet.header, data.data(), sizeof(arp_header));
    
    // 转换字节序（网络字节序到主机字节序）
    packet.header.hardware_type = __builtin_bswap16(packet.header.hardware_type);
    packet.header.protocol_type = __builtin_bswap16(packet.header.protocol_type);
    packet.header.operation = __builtin_bswap16(packet.header.operation);
    
    return packet;
}

bool arp_parser::validate(std::span<const uint8_t> data) {
    if (data.size() < MIN_ARP_SIZE) {
        return false;
    }
    
    // 检查基本字段的合理性
    if (data.size() >= 8) {
        uint16_t hw_type = __builtin_bswap16(*reinterpret_cast<const uint16_t*>(data.data()));
        uint16_t proto_type = __builtin_bswap16(*reinterpret_cast<const uint16_t*>(data.data() + 2));
        uint8_t hw_len = data[4];
        uint8_t proto_len = data[5];
        
        // 检查长度字段的合理性
        if (hw_len == 0 || proto_len == 0 || hw_len > 32 || proto_len > 32) {
            return false;
        }
        
        // 检查数据包大小是否匹配
        size_t expected_size = 8 + (hw_len * 2) + (proto_len * 2);
        if (data.size() < expected_size) {
            return false;
        }
    }
    
    return true;
}

bool arp_parser::is_standard_ethernet_ipv4(const arp_packet& packet) {
    return packet.header.hardware_type == arp_hardware_type::ETHERNET &&
           packet.header.protocol_type == arp_protocol_type::IPV4 &&
           packet.header.hardware_length == 6 &&
           packet.header.protocol_length == 4;
}

// ARP缓存条目实现
std::string arp_cache_entry::ip_str() const {
    return arp_utils::ip_to_string(ip_addr);
}

std::string arp_cache_entry::mac_str() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac_addr.size(); ++i) {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(mac_addr[i]);
    }
    return oss.str();
}

bool arp_cache_entry::is_expired(uint64_t current_time, uint64_t timeout) const {
    return !is_static && (current_time - timestamp) > timeout;
}

// ARP缓存管理器实现
void arp_cache::add_entry(const std::array<uint8_t, 4>& ip_addr,
                         const std::array<uint8_t, 6>& mac_addr,
                         bool is_static) {
    std::unique_lock lock(mutex_);
    
    uint32_t key = ip_to_key(ip_addr);
    arp_cache_entry entry;
    entry.ip_addr = ip_addr;
    entry.mac_addr = mac_addr;
    entry.timestamp = get_current_timestamp();
    entry.is_static = is_static;
    
    cache_[key] = entry;
}

std::optional<arp_cache_entry> arp_cache::lookup(const std::array<uint8_t, 4>& ip_addr) const {
    std::shared_lock lock(mutex_);
    
    uint32_t key = ip_to_key(ip_addr);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool arp_cache::remove_entry(const std::array<uint8_t, 4>& ip_addr) {
    std::unique_lock lock(mutex_);
    
    uint32_t key = ip_to_key(ip_addr);
    return cache_.erase(key) > 0;
}

size_t arp_cache::cleanup_expired(uint64_t timeout) {
    std::unique_lock lock(mutex_);
    
    uint64_t current_time = get_current_timestamp();
    size_t removed_count = 0;
    
    auto it = cache_.begin();
    while (it != cache_.end()) {
        if (it->second.is_expired(current_time, timeout)) {
            it = cache_.erase(it);
            ++removed_count;
        } else {
            ++it;
        }
    }
    
    return removed_count;
}

std::vector<arp_cache_entry> arp_cache::get_all_entries() const {
    std::shared_lock lock(mutex_);
    
    std::vector<arp_cache_entry> entries;
    entries.reserve(cache_.size());
    
    for (const auto& [key, entry] : cache_) {
        entries.push_back(entry);
    }
    
    return entries;
}

void arp_cache::clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
}

size_t arp_cache::size() const {
    std::shared_lock lock(mutex_);
    return cache_.size();
}

uint32_t arp_cache::ip_to_key(const std::array<uint8_t, 4>& ip_addr) const {
    return (static_cast<uint32_t>(ip_addr[0]) << 24) |
           (static_cast<uint32_t>(ip_addr[1]) << 16) |
           (static_cast<uint32_t>(ip_addr[2]) << 8) |
           static_cast<uint32_t>(ip_addr[3]);
}

uint64_t arp_cache::get_current_timestamp() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ARP工具类实现
arp_packet arp_utils::create_request(const std::array<uint8_t, 6>& sender_mac,
                                   const std::array<uint8_t, 4>& sender_ip,
                                   const std::array<uint8_t, 4>& target_ip) {
    arp_packet packet;
    packet.header.hardware_type = arp_hardware_type::ETHERNET;
    packet.header.protocol_type = arp_protocol_type::IPV4;
    packet.header.hardware_length = 6;
    packet.header.protocol_length = 4;
    packet.header.operation = arp_operation::REQUEST;
    packet.header.sender_hw_addr = sender_mac;
    packet.header.sender_proto_addr = sender_ip;
    packet.header.target_hw_addr = {0, 0, 0, 0, 0, 0};  // 未知MAC地址
    packet.header.target_proto_addr = target_ip;
    
    return packet;
}

arp_packet arp_utils::create_reply(const std::array<uint8_t, 6>& sender_mac,
                                 const std::array<uint8_t, 4>& sender_ip,
                                 const std::array<uint8_t, 6>& target_mac,
                                 const std::array<uint8_t, 4>& target_ip) {
    arp_packet packet;
    packet.header.hardware_type = arp_hardware_type::ETHERNET;
    packet.header.protocol_type = arp_protocol_type::IPV4;
    packet.header.hardware_length = 6;
    packet.header.protocol_length = 4;
    packet.header.operation = arp_operation::REPLY;
    packet.header.sender_hw_addr = sender_mac;
    packet.header.sender_proto_addr = sender_ip;
    packet.header.target_hw_addr = target_mac;
    packet.header.target_proto_addr = target_ip;
    
    return packet;
}

std::array<uint8_t, 28> arp_utils::serialize(const arp_packet& packet) {
    std::array<uint8_t, 28> data;
    arp_header header = packet.header;
    
    // 转换为网络字节序
    header.hardware_type = __builtin_bswap16(header.hardware_type);
    header.protocol_type = __builtin_bswap16(header.protocol_type);
    header.operation = __builtin_bswap16(header.operation);
    
    std::memcpy(data.data(), &header, sizeof(arp_header));
    return data;
}

const char* arp_utils::get_operation_name(uint16_t operation) {
    switch (operation) {
        case arp_operation::REQUEST: return "ARP Request";
        case arp_operation::REPLY: return "ARP Reply";
        case arp_operation::RARP_REQUEST: return "RARP Request";
        case arp_operation::RARP_REPLY: return "RARP Reply";
        case arp_operation::DRARP_REQUEST: return "Dynamic RARP Request";
        case arp_operation::DRARP_REPLY: return "Dynamic RARP Reply";
        case arp_operation::DRARP_ERROR: return "Dynamic RARP Error";
        case arp_operation::INARP_REQUEST: return "Inverse ARP Request";
        case arp_operation::INARP_REPLY: return "Inverse ARP Reply";
        default: return "Unknown";
    }
}

const char* arp_utils::get_hardware_type_name(uint16_t hw_type) {
    switch (hw_type) {
        case arp_hardware_type::ETHERNET: return "Ethernet";
        case arp_hardware_type::IEEE802: return "IEEE 802";
        case arp_hardware_type::ARCNET: return "ARCNET";
        case arp_hardware_type::FRAME_RELAY: return "Frame Relay";
        case arp_hardware_type::ATM: return "ATM";
        case arp_hardware_type::HDLC: return "HDLC";
        case arp_hardware_type::FIBRE_CHANNEL: return "Fibre Channel";
        default: return "Unknown";
    }
}

std::string arp_utils::ip_to_string(const std::array<uint8_t, 4>& ip_addr) {
    std::ostringstream oss;
    oss << static_cast<unsigned>(ip_addr[0]) << '.'
        << static_cast<unsigned>(ip_addr[1]) << '.'
        << static_cast<unsigned>(ip_addr[2]) << '.'
        << static_cast<unsigned>(ip_addr[3]);
    return oss.str();
}

std::optional<std::array<uint8_t, 4>> arp_utils::string_to_ip(const std::string& ip_str) {
    std::array<uint8_t, 4> ip_addr{};
    std::istringstream iss(ip_str);
    std::string octet;
    
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(iss, octet, '.')) {
            return std::nullopt;
        }
        
        try {
            int value = std::stoi(octet);
            if (value < 0 || value > 255) {
                return std::nullopt;
            }
            ip_addr[i] = static_cast<uint8_t>(value);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    
    // 检查是否还有多余的字符
    if (std::getline(iss, octet)) {
        return std::nullopt;
    }
    
    return ip_addr;
}

} // namespace protocol_parser::datalink