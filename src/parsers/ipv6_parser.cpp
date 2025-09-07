#include "parsers/ipv6_parser.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>

namespace protocol_parser::parsers {

// 静态协议信息
static const ProtocolInfo ipv6_protocol_info = {
    "IPv6",
    0x86DD,
    40,  // IPv6头部固定40字节
    40,  // 最小包大小
    65535 + 40  // 最大包大小
};

// IPv6Parser实现
const ProtocolInfo& IPv6Parser::get_protocol_info() const noexcept {
    return ipv6_protocol_info;
}

bool IPv6Parser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < 40) {
        return false;
    }
    
    // 检查版本号
    uint8_t version = (buffer.data()[0] >> 4) & 0x0F;
    return version == 6;
}

ParseResult IPv6Parser::parse(ParseContext& context) noexcept {
    try {
        // 检查缓冲区大小
        if (context.buffer.size() < ipv6_constants::IPV6_HEADER_SIZE) {
            context.state = ParserState::Error;
            return ParseResult::BufferTooSmall;
        }
        
        // 解析IPv6头部
        IPv6ParseResult ipv6_result;
        const uint8_t* data = context.buffer.data();
        
        // 读取IPv6头部字段
        uint32_t version_traffic_flow = 
            (static_cast<uint32_t>(data[0]) << 24) |
            (static_cast<uint32_t>(data[1]) << 16) |
            (static_cast<uint32_t>(data[2]) << 8) |
            static_cast<uint32_t>(data[3]);
        
        // 检查版本号
        uint8_t version = (version_traffic_flow >> 28) & 0x0F;
        if (version != 6) {
            ipv6_result.is_valid = false;
            ipv6_result.error_message = "Invalid IPv6 version";
            context.state = ParserState::Error;
            return ParseResult::InvalidFormat;
        }
        
        ipv6_result.payload_length = 
            (static_cast<uint16_t>(data[4]) << 8) | data[5];
        
        ipv6_result.next_header = data[6];
        ipv6_result.hop_limit = data[7];
        
        // 复制源地址和目的地址
        std::memcpy(ipv6_result.src_addr.data(), data + 8, 16);
        std::memcpy(ipv6_result.dst_addr.data(), data + 24, 16);
        
        // 设置基本信息
        ipv6_result.version_class_label = version_traffic_flow;
        ipv6_result.header_length = ipv6_constants::IPV6_HEADER_SIZE;
        ipv6_result.is_valid = true;
        
        // 解析扩展头部（简化版本，只计算长度）
        size_t offset = ipv6_constants::IPV6_HEADER_SIZE;
        uint8_t current_next_header = ipv6_result.next_header;
        
        // 处理扩展头部
        while (is_extension_header(current_next_header) && offset < context.buffer.size()) {
            if (offset + 2 > context.buffer.size()) {
                break; // 不够读取扩展头部的基本字段
            }
            
            uint8_t next_header = data[offset];
            uint8_t ext_length = data[offset + 1];
            
            size_t header_size;
            if (current_next_header == 44) { // Fragment header
                header_size = 8;
            } else {
                header_size = (ext_length + 1) * 8;
            }
            
            if (offset + header_size > context.buffer.size()) {
                break; // 扩展头部超出缓冲区
            }
            
            offset += header_size;
            ipv6_result.header_length += header_size;
            current_next_header = next_header;
        }
        
        ipv6_result.next_header = current_next_header;
        
        // 将解析结果存储到metadata中
        context.metadata["ipv6_result"] = ipv6_result;
        context.offset = ipv6_result.header_length;
        context.state = ParserState::Complete;
        
        return ParseResult::Success;
    } catch (...) {
        context.state = ParserState::Error;
        return ParseResult::InternalError;
    }
}

void IPv6Parser::reset() noexcept {
    // 重置解析器状态
    state_machine_.set_state(ParserState::Initial);
    error_message_.clear();
}



bool IPv6Parser::is_extension_header(uint8_t next_header) const {
    switch (next_header) {
        case 0:   // Hop-by-Hop Options Header
        case 43:  // Routing Header
        case 44:  // Fragment Header
        case 60:  // Destination Options Header
        case 51:  // Authentication Header
        case 50:  // Encapsulating Security Payload Header
        case 135: // Mobility Header
            return true;
        default:
            return false;
    }
}

bool IPv6Parser::validate_header(const IPv6Header& header) const noexcept {
    // 检查版本号
    uint8_t version = (header.version_traffic_flow >> 28) & 0x0F;
    if (version != 6) {
        return false;
    }
    
    // payload_length是uint16_t类型，不需要检查是否大于65535
    
    return true;
}

// IPv6工具函数实现
namespace ipv6_utils {

std::string format_address(const std::array<uint8_t, 16>& addr) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t group = (static_cast<uint16_t>(addr[i]) << 8) | addr[i + 1];
        oss << std::setw(4) << group;
    }
    
    return oss.str();
}

std::optional<std::array<uint8_t, 16>> parse_address(const std::string& addr_str) {
    // 解析IPv6地址字符串为16字节数组
    if (addr_str.empty()) {
        return std::nullopt;
    }
    
    try {
        // 首先展开地址以获得标准格式
        std::string expanded = expand_address(addr_str);
        
        // 分割为8个段
        std::vector<std::string> segments;
        std::stringstream ss(expanded);
        std::string segment;
        
        while (std::getline(ss, segment, ':')) {
            segments.push_back(segment);
        }
        
        // 检查是否有8个段
        if (segments.size() != 8) {
            return std::nullopt;
        }
        
        std::array<uint8_t, 16> result{};
        
        // 将每个段转换为2个字节
        for (size_t i = 0; i < 8; ++i) {
            if (segments[i].length() != 4) {
                return std::nullopt;
            }
            
            // 解析16位值
            uint16_t value = 0;
            for (char c : segments[i]) {
                value <<= 4;
                if (c >= '0' && c <= '9') {
                    value |= (c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    value |= (c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    value |= (c - 'A' + 10);
                } else {
                    return std::nullopt; // 无效字符
                }
            }
            
            // 存储为大端序
            result[i * 2] = static_cast<uint8_t>(value >> 8);
            result[i * 2 + 1] = static_cast<uint8_t>(value & 0xFF);
        }
        
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

bool is_loopback(const std::array<uint8_t, 16>& addr) noexcept {
    // IPv6回环地址是 ::1
    for (size_t i = 0; i < 15; ++i) {
        if (addr[i] != 0) return false;
    }
    return addr[15] == 1;
}

bool is_unspecified(const std::array<uint8_t, 16>& addr) noexcept {
    // IPv6未指定地址是 ::
    for (uint8_t byte : addr) {
        if (byte != 0) return false;
    }
    return true;
}

bool is_multicast(const std::array<uint8_t, 16>& addr) noexcept {
    return (addr[0] & 0xFF) == 0xFF;
}

bool is_link_local(const std::array<uint8_t, 16>& addr) noexcept {
    return (addr[0] == 0xFE) && ((addr[1] & 0xC0) == 0x80);
}

std::array<uint8_t, 16> get_network_prefix(
    const std::array<uint8_t, 16>& addr, uint8_t prefix_length) noexcept {
    std::array<uint8_t, 16> result = addr;
    
    if (prefix_length >= 128) {
        return result;
    }
    
    size_t byte_index = prefix_length / 8;
    uint8_t bit_offset = prefix_length % 8;
    
    // 清除前缀长度之后的位
    if (byte_index < 16) {
        if (bit_offset > 0) {
            uint8_t mask = 0xFF << (8 - bit_offset);
            result[byte_index] &= mask;
            ++byte_index;
        }
        
        // 清除剩余字节
        for (size_t i = byte_index; i < 16; ++i) {
            result[i] = 0;
        }
    }
    
    return result;
}

bool addresses_equal(
    const std::array<uint8_t, 16>& addr1, 
    const std::array<uint8_t, 16>& addr2) noexcept {
    return addr1 == addr2;
}

int compare_addresses(
    const std::array<uint8_t, 16>& addr1, 
    const std::array<uint8_t, 16>& addr2) noexcept {
    for (size_t i = 0; i < 16; ++i) {
        if (addr1[i] < addr2[i]) return -1;
        if (addr1[i] > addr2[i]) return 1;
    }
    return 0;
}

std::string get_next_header_name(uint8_t next_header) noexcept {
    switch (next_header) {
        case 0: return "Hop-by-Hop Options";
        case 6: return "TCP";
        case 17: return "UDP";
        case 43: return "Routing";
        case 44: return "Fragment";
        case 58: return "ICMPv6";
        case 59: return "No Next Header";
        case 60: return "Destination Options";
        case 132: return "SCTP";
        default: return "Unknown (" + std::to_string(next_header) + ")";
    }
}

std::string compress_address(const std::string& addr) {
    // 实现IPv6地址压缩（RFC 4291）
    if (addr.empty()) {
        return addr;
    }
    
    // 分割地址为8个16位段
    std::vector<std::string> segments;
    std::stringstream ss(addr);
    std::string segment;
    
    while (std::getline(ss, segment, ':')) {
        segments.push_back(segment);
    }
    
    // 如果不是标准的8段格式，直接返回
    if (segments.size() != 8) {
        return addr;
    }
    
    // 找到最长的连续零段序列
    int max_zero_start = -1;
    int max_zero_length = 0;
    int current_zero_start = -1;
    int current_zero_length = 0;
    
    for (int i = 0; i < 8; ++i) {
        if (segments[i] == "0" || segments[i] == "0000") {
            if (current_zero_start == -1) {
                current_zero_start = i;
                current_zero_length = 1;
            } else {
                current_zero_length++;
            }
        } else {
            if (current_zero_length > max_zero_length) {
                max_zero_start = current_zero_start;
                max_zero_length = current_zero_length;
            }
            current_zero_start = -1;
            current_zero_length = 0;
        }
    }
    
    // 检查最后一段
    if (current_zero_length > max_zero_length) {
        max_zero_start = current_zero_start;
        max_zero_length = current_zero_length;
    }
    
    // 构建压缩后的地址
    std::string result;
    
    if (max_zero_length > 1) {
        // 添加零段之前的部分
        for (int i = 0; i < max_zero_start; ++i) {
            if (i > 0) result += ":";
            // 移除前导零
            std::string seg = segments[i];
            size_t first_non_zero = seg.find_first_not_of('0');
            if (first_non_zero == std::string::npos) {
                result += "0";
            } else {
                result += seg.substr(first_non_zero);
            }
        }
        
        // 添加压缩标记
        if (max_zero_start == 0) {
            result = "::";
        } else {
            result += "::";
        }
        
        // 添加零段之后的部分
        for (int i = max_zero_start + max_zero_length; i < 8; ++i) {
            if (i > max_zero_start + max_zero_length) result += ":";
            // 移除前导零
            std::string seg = segments[i];
            size_t first_non_zero = seg.find_first_not_of('0');
            if (first_non_zero == std::string::npos) {
                result += "0";
            } else {
                result += seg.substr(first_non_zero);
            }
        }
    } else {
        // 没有连续的零段，只移除前导零
        for (int i = 0; i < 8; ++i) {
            if (i > 0) result += ":";
            std::string seg = segments[i];
            size_t first_non_zero = seg.find_first_not_of('0');
            if (first_non_zero == std::string::npos) {
                result += "0";
            } else {
                result += seg.substr(first_non_zero);
            }
        }
    }
    
    return result;
}

std::string expand_address(const std::string& addr) {
    // 实现IPv6地址展开
    if (addr.empty()) {
        return addr;
    }
    
    std::string expanded = addr;
    
    // 处理 :: 压缩
    size_t double_colon_pos = expanded.find("::");
    if (double_colon_pos != std::string::npos) {
        // 计算需要补充的零段数量
        std::string before = expanded.substr(0, double_colon_pos);
        std::string after = expanded.substr(double_colon_pos + 2);
        
        int before_segments = before.empty() ? 0 : std::count(before.begin(), before.end(), ':') + 1;
        int after_segments = after.empty() ? 0 : std::count(after.begin(), after.end(), ':') + 1;
        
        if (before.empty()) before_segments = 0;
        if (after.empty()) after_segments = 0;
        
        int missing_segments = 8 - before_segments - after_segments;
        
        // 构建展开的地址
        std::string replacement;
        for (int i = 0; i < missing_segments; ++i) {
            if (i > 0 || !before.empty()) replacement += ":";
            replacement += "0000";
        }
        
        if (!after.empty()) {
            replacement += ":";
        }
        
        expanded = before + replacement + after;
    }
    
    // 展开每个段为4位十六进制数
    std::vector<std::string> segments;
    std::stringstream ss(expanded);
    std::string segment;
    
    while (std::getline(ss, segment, ':')) {
        // 将每个段补齐为4位
        while (segment.length() < 4) {
            segment = "0" + segment;
        }
        segments.push_back(segment);
    }
    
    // 重新组合
    std::string result;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i > 0) result += ":";
        result += segments[i];
    }
    
    return result;
}

} // namespace ipv6_utils

// 构建IPv6伪头部
IPv6PseudoHeader build_pseudo_header(
    const std::array<uint8_t, 16>& src_addr,
    const std::array<uint8_t, 16>& dst_addr,
    uint32_t payload_length,
    uint8_t next_header) noexcept {
    IPv6PseudoHeader pseudo_header;
    pseudo_header.src_addr = src_addr;
    pseudo_header.dst_addr = dst_addr;
    pseudo_header.length = payload_length;
    pseudo_header.next_header = static_cast<uint32_t>(next_header);
    return pseudo_header;
}

} // namespace protocol_parser::parsers