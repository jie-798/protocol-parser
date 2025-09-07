#include "parsers/arp_parser.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace protocol_parser::parsers {

// 协议信息定义
const ProtocolInfo ARPParser::protocol_info_ = {
    .name = "ARP",
    .type = 0x0806,
    .header_size = ARPHeader::SIZE,
    .min_packet_size = ARPHeader::SIZE,
    .max_packet_size = ARPHeader::SIZE + 64  // ARP包通常很小，预留一些额外空间
};

// ARP头部解析
std::expected<ARPHeader, ParseResult> ARPHeader::parse(const core::BufferView& buffer) noexcept {
    if (buffer.size() < SIZE) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    ARPHeader header;
    size_t offset = 0;
    
    // 读取硬件类型（网络字节序）
    header.hardware_type = (static_cast<uint16_t>(buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    
    // 读取协议类型（网络字节序）
    header.protocol_type = (static_cast<uint16_t>(buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    
    // 读取硬件地址长度
    header.hardware_length = buffer[offset++];
    
    // 读取协议地址长度
    header.protocol_length = buffer[offset++];
    
    // 读取操作码（网络字节序）
    header.opcode = (static_cast<uint16_t>(buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    
    // 读取发送方MAC地址
    std::memcpy(header.sender_mac.data(), buffer.data() + offset, 6);
    offset += 6;
    
    // 读取发送方IP地址
    std::memcpy(header.sender_ip.data(), buffer.data() + offset, 4);
    offset += 4;
    
    // 读取目标MAC地址
    std::memcpy(header.target_mac.data(), buffer.data() + offset, 6);
    offset += 6;
    
    // 读取目标IP地址
    std::memcpy(header.target_ip.data(), buffer.data() + offset, 4);
    
    return header;
}

bool ARPHeader::is_valid() const noexcept {
    // 检查基本字段有效性
    if (hardware_length == 0 || protocol_length == 0) {
        return false;
    }
    
    // 检查操作码
    if (opcode < ARPOpcode::REQUEST || opcode > ARPOpcode::RARP_REPLY) {
        return false;
    }
    
    // 对于以太网ARP，检查地址长度
    if (hardware_type == ARPHardwareType::ETHERNET && hardware_length != 6) {
        return false;
    }
    
    // 对于IPv4 ARP，检查地址长度
    if (protocol_type == ARPProtocolType::IPV4 && protocol_length != 4) {
        return false;
    }
    
    return true;
}

std::string ARPHeader::sender_mac_string() const {
    return arp_utils::format_mac_address(sender_mac);
}

std::string ARPHeader::target_mac_string() const {
    return arp_utils::format_mac_address(target_mac);
}

std::string ARPHeader::sender_ip_string() const {
    return arp_utils::format_ipv4_address(sender_ip);
}

std::string ARPHeader::target_ip_string() const {
    return arp_utils::format_ipv4_address(target_ip);
}

// ARP解析器实现
ARPParser::ARPParser() {
    setup_state_machine();
}

const ProtocolInfo& ARPParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool ARPParser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < ARPHeader::SIZE) {
        return false;
    }
    
    // 检查硬件类型和协议类型
    uint16_t hw_type = (static_cast<uint16_t>(buffer[0]) << 8) | buffer[1];
    uint16_t proto_type = (static_cast<uint16_t>(buffer[2]) << 8) | buffer[3];
    
    return is_supported_hardware_type(hw_type) && is_supported_protocol_type(proto_type);
}

ParseResult ARPParser::parse(ParseContext& context) noexcept {
    return state_machine_.execute(context);
}

void ARPParser::reset() noexcept {
    result_ = ARPParseResult{};
    state_machine_.set_state(ParserState::Initial);
    error_message_.clear();
}

double ARPParser::get_progress() const noexcept {
    switch (state_machine_.current_state) {
        case ParserState::Initial: return 0.0;
        case ParserState::Parsing: return 0.7;
        case ParserState::Complete: return 1.0;
        case ParserState::Error: return 0.0;
        default: return 0.0;
    }
}

void ARPParser::setup_state_machine() {
    state_machine_.transitions[ParserState::Initial] = [this](ParseContext& ctx) {
        return parse_header(ctx);
    };
    
    state_machine_.transitions[ParserState::Parsing] = [this](ParseContext& ctx) {
        return parse_extra_data(ctx);
    };
}

ParseResult ARPParser::parse_header(ParseContext& context) noexcept {
    auto header_result = ARPHeader::parse(context.buffer.substr(context.offset));
    if (!header_result) {
        error_message_ = "Failed to parse ARP header";
        state_machine_.set_state(ParserState::Error);
        return header_result.error();
    }
    
    result_.header = header_result.value();
    
    // 验证ARP头部
    if (!result_.header.is_valid()) {
        error_message_ = "Invalid ARP header";
        state_machine_.set_state(ParserState::Error);
        return ParseResult::InvalidFormat;
    }
    
    // 检查是否支持的硬件和协议类型
    if (!is_supported_hardware_type(result_.header.hardware_type) ||
        !is_supported_protocol_type(result_.header.protocol_type)) {
        error_message_ = "Unsupported ARP hardware or protocol type";
        state_machine_.set_state(ParserState::Error);
        return ParseResult::UnsupportedVersion;
    }
    
    context.offset += ARPHeader::SIZE;
    result_.total_length = ARPHeader::SIZE;
    
    state_machine_.set_state(ParserState::Parsing);
    return ParseResult::Success;
}

ParseResult ARPParser::parse_extra_data(ParseContext& context) noexcept {
    // ARP包通常只包含标准头部，但可能有填充数据
    size_t remaining = context.buffer.size() - context.offset;
    
    if (remaining > 0) {
        result_.extra_data = context.buffer.substr(context.offset, remaining);
        result_.total_length += remaining;
    }
    
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

bool ARPParser::is_supported_hardware_type(uint16_t hw_type) const noexcept {
    return hw_type == ARPHardwareType::ETHERNET ||
           hw_type == ARPHardwareType::IEEE802 ||
           hw_type == ARPHardwareType::FRAME_RELAY ||
           hw_type == ARPHardwareType::ATM;
}

bool ARPParser::is_supported_protocol_type(uint16_t proto_type) const noexcept {
    return proto_type == ARPProtocolType::IPV4 ||
           proto_type == ARPProtocolType::IPV6;
}

// ARP工具函数实现
namespace arp_utils {

std::string format_mac_address(const MacAddress& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return oss.str();
}

std::optional<MacAddress> parse_mac_address(const std::string& mac_str) {
    MacAddress mac;
    std::istringstream iss(mac_str);
    std::string token;
    size_t index = 0;
    
    while (std::getline(iss, token, ':') && index < 6) {
        if (token.length() != 2) {
            return std::nullopt;
        }
        
        try {
            unsigned long value = std::stoul(token, nullptr, 16);
            if (value > 255) {
                return std::nullopt;
            }
            mac[index++] = static_cast<uint8_t>(value);
        } catch (...) {
            return std::nullopt;
        }
    }
    
    return index == 6 ? std::optional<MacAddress>(mac) : std::nullopt;
}

std::string format_ipv4_address(const IPv4Address& ip) {
    std::ostringstream oss;
    for (size_t i = 0; i < ip.size(); ++i) {
        if (i > 0) oss << ".";
        oss << static_cast<unsigned>(ip[i]);
    }
    return oss.str();
}

std::optional<IPv4Address> parse_ipv4_address(const std::string& ip_str) {
    IPv4Address ip;
    std::istringstream iss(ip_str);
    std::string token;
    size_t index = 0;
    
    while (std::getline(iss, token, '.') && index < 4) {
        try {
            unsigned long value = std::stoul(token);
            if (value > 255) {
                return std::nullopt;
            }
            ip[index++] = static_cast<uint8_t>(value);
        } catch (...) {
            return std::nullopt;
        }
    }
    
    return index == 4 ? std::optional<IPv4Address>(ip) : std::nullopt;
}

std::string get_hardware_type_name(uint16_t hw_type) {
    switch (hw_type) {
        case ARPHardwareType::ETHERNET: return "Ethernet";
        case ARPHardwareType::IEEE802: return "IEEE 802";
        case ARPHardwareType::ARCNET: return "ARCNET";
        case ARPHardwareType::FRAME_RELAY: return "Frame Relay";
        case ARPHardwareType::ATM: return "ATM";
        case ARPHardwareType::HDLC: return "HDLC";
        case ARPHardwareType::FIBRE_CHANNEL: return "Fibre Channel";
        default: return "Unknown (" + std::to_string(hw_type) + ")";
    }
}

std::string get_protocol_type_name(uint16_t proto_type) {
    switch (proto_type) {
        case ARPProtocolType::IPV4: return "IPv4";
        case ARPProtocolType::IPV6: return "IPv6";
        default: return "Unknown (0x" + std::to_string(proto_type) + ")";
    }
}

std::string get_opcode_name(uint16_t opcode) {
    switch (opcode) {
        case ARPOpcode::REQUEST: return "ARP Request";
        case ARPOpcode::REPLY: return "ARP Reply";
        case ARPOpcode::RARP_REQUEST: return "RARP Request";
        case ARPOpcode::RARP_REPLY: return "RARP Reply";
        default: return "Unknown (" + std::to_string(opcode) + ")";
    }
}

bool is_broadcast_mac(const MacAddress& mac) {
    return std::all_of(mac.begin(), mac.end(), [](uint8_t byte) {
        return byte == 0xFF;
    });
}

bool is_zero_mac(const MacAddress& mac) {
    return std::all_of(mac.begin(), mac.end(), [](uint8_t byte) {
        return byte == 0x00;
    });
}

bool is_zero_ip(const IPv4Address& ip) {
    return std::all_of(ip.begin(), ip.end(), [](uint8_t byte) {
        return byte == 0x00;
    });
}

std::vector<uint8_t> create_arp_request(
    const MacAddress& sender_mac,
    const IPv4Address& sender_ip,
    const IPv4Address& target_ip
) {
    std::vector<uint8_t> packet(ARPHeader::SIZE);
    size_t offset = 0;
    
    // 硬件类型（以太网）
    packet[offset++] = (ARPHardwareType::ETHERNET >> 8) & 0xFF;
    packet[offset++] = ARPHardwareType::ETHERNET & 0xFF;
    
    // 协议类型（IPv4）
    packet[offset++] = (ARPProtocolType::IPV4 >> 8) & 0xFF;
    packet[offset++] = ARPProtocolType::IPV4 & 0xFF;
    
    // 硬件地址长度
    packet[offset++] = 6;
    
    // 协议地址长度
    packet[offset++] = 4;
    
    // 操作码（请求）
    packet[offset++] = (ARPOpcode::REQUEST >> 8) & 0xFF;
    packet[offset++] = ARPOpcode::REQUEST & 0xFF;
    
    // 发送方MAC地址
    std::memcpy(packet.data() + offset, sender_mac.data(), 6);
    offset += 6;
    
    // 发送方IP地址
    std::memcpy(packet.data() + offset, sender_ip.data(), 4);
    offset += 4;
    
    // 目标MAC地址（全零）
    std::memset(packet.data() + offset, 0, 6);
    offset += 6;
    
    // 目标IP地址
    std::memcpy(packet.data() + offset, target_ip.data(), 4);
    
    return packet;
}

std::vector<uint8_t> create_arp_reply(
    const MacAddress& sender_mac,
    const IPv4Address& sender_ip,
    const MacAddress& target_mac,
    const IPv4Address& target_ip
) {
    std::vector<uint8_t> packet(ARPHeader::SIZE);
    size_t offset = 0;
    
    // 硬件类型（以太网）
    packet[offset++] = (ARPHardwareType::ETHERNET >> 8) & 0xFF;
    packet[offset++] = ARPHardwareType::ETHERNET & 0xFF;
    
    // 协议类型（IPv4）
    packet[offset++] = (ARPProtocolType::IPV4 >> 8) & 0xFF;
    packet[offset++] = ARPProtocolType::IPV4 & 0xFF;
    
    // 硬件地址长度
    packet[offset++] = 6;
    
    // 协议地址长度
    packet[offset++] = 4;
    
    // 操作码（回复）
    packet[offset++] = (ARPOpcode::REPLY >> 8) & 0xFF;
    packet[offset++] = ARPOpcode::REPLY & 0xFF;
    
    // 发送方MAC地址
    std::memcpy(packet.data() + offset, sender_mac.data(), 6);
    offset += 6;
    
    // 发送方IP地址
    std::memcpy(packet.data() + offset, sender_ip.data(), 4);
    offset += 4;
    
    // 目标MAC地址
    std::memcpy(packet.data() + offset, target_mac.data(), 6);
    offset += 6;
    
    // 目标IP地址
    std::memcpy(packet.data() + offset, target_ip.data(), 4);
    
    return packet;
}

} // namespace arp_utils

// 注册解析器
REGISTER_PARSER(0x0806, ARPParserFactory);

} // namespace protocol_parser::parsers