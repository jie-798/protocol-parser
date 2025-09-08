#include "../../../include/parsers/datalink/ethernet_parser.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace protocol_parser::parsers {

// 协议信息定义
const ProtocolInfo EthernetParser::protocol_info_ = {
    .name = "Ethernet",
    .type = 0x0001,
    .header_size = EthernetHeader::SIZE,
    .min_packet_size = EthernetHeader::SIZE,
    .max_packet_size = 1518  // 标准以太网帧最大长度
};

// 以太网头解析
std::expected<EthernetHeader, ParseResult> EthernetHeader::parse(const core::BufferView& buffer) noexcept {
    if (buffer.size() < SIZE) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    EthernetHeader header;
    
    // 解析目标MAC地址
    std::memcpy(header.dst_mac.data(), buffer.data(), 6);
    
    // 解析源MAC地址
    std::memcpy(header.src_mac.data(), buffer.data() + 6, 6);
    
    // 解析以太网类型（大端序）
    header.ether_type = buffer.read_be<uint16_t>(12);
    
    return header;
}

bool EthernetHeader::is_broadcast() const noexcept {
    static const MacAddress broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return dst_mac == broadcast;
}

bool EthernetHeader::is_multicast() const noexcept {
    return (dst_mac[0] & 0x01) != 0;
}

std::string EthernetHeader::src_mac_string() const {
    return ethernet_utils::format_mac_address(src_mac);
}

std::string EthernetHeader::dst_mac_string() const {
    return ethernet_utils::format_mac_address(dst_mac);
}

// 以太网解析器实现
EthernetParser::EthernetParser() {
    setup_state_machine();
}

const ProtocolInfo& EthernetParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool EthernetParser::can_parse(const core::BufferView& buffer) const noexcept {
    return buffer.size() >= EthernetHeader::SIZE;
}

ParseResult EthernetParser::parse(ParseContext& context) noexcept {
    context.state = ParserState::Parsing;
    
    // 循环执行状态机直到完成或出错
    ParseResult result = ParseResult::Success;
    while (state_machine_.current_state != ParserState::Complete && 
           state_machine_.current_state != ParserState::Error) {
        result = state_machine_.execute(context);
        if (result != ParseResult::Success) {
            break;
        }
    }
    
    return result;
}

void EthernetParser::reset() noexcept {
    state_machine_.set_state(ParserState::Initial);
    result_ = EthernetParseResult{};
    error_message_.clear();
}

double EthernetParser::get_progress() const noexcept {
    switch (state_machine_.current_state) {
        case ParserState::Initial: return 0.0;
        case ParserState::Parsing: return 0.5;
        case ParserState::Complete: return 1.0;
        case ParserState::Error: return 0.0;
        default: return 0.0;
    }
}

std::string EthernetParser::get_error_message() const noexcept {
    return error_message_;
}

// 状态机设置
void EthernetParser::setup_state_machine() {
    state_machine_.transitions[ParserState::Initial] = 
        [this](ParseContext& ctx) { return parse_header(ctx); };
    
    state_machine_.transitions[ParserState::Parsing] = 
        [this](ParseContext& ctx) { 
            if (parse_vlan_ && result_.header.ether_type == EtherType::VLAN) {
                return parse_vlan(ctx);
            } else {
                return parse_payload(ctx);
            }
        };
}

// 解析以太网头
ParseResult EthernetParser::parse_header(ParseContext& context) noexcept {
    auto header_result = EthernetHeader::parse(context.buffer);
    if (!header_result) {
        error_message_ = "Failed to parse Ethernet header";
        state_machine_.set_state(ParserState::Error);
        return header_result.error();
    }
    
    result_.header = *header_result;
    
    // 验证以太网类型
    if (!is_valid_ether_type(result_.header.ether_type)) {
        error_message_ = "Invalid Ethernet type: " + std::to_string(result_.header.ether_type);
        state_machine_.set_state(ParserState::Error);
        return ParseResult::InvalidFormat;
    }
    
    context.offset += EthernetHeader::SIZE;
    state_machine_.set_state(ParserState::Parsing);
    return ParseResult::Success;
}

// 解析VLAN标签
ParseResult EthernetParser::parse_vlan(ParseContext& context) noexcept {
    if (!context.buffer.can_read(VlanTag::SIZE, context.offset)) {
        return ParseResult::NeedMoreData;
    }
    
    VlanTag vlan_tag;
    vlan_tag.tci = context.buffer.read_be<uint16_t>(context.offset);
    vlan_tag.ether_type = context.buffer.read_be<uint16_t>(context.offset + 2);
    
    result_.vlan_tag = vlan_tag;
    result_.next_protocol = vlan_tag.ether_type;
    
    context.offset += VlanTag::SIZE;
    return parse_payload(context);
}

// 解析载荷
ParseResult EthernetParser::parse_payload(ParseContext& context) noexcept {
    if (context.offset >= context.buffer.size()) {
        error_message_ = "No payload data available";
        state_machine_.set_state(ParserState::Error);
        return ParseResult::InvalidFormat;
    }
    
    result_.payload = context.buffer.substr(context.offset);
    result_.next_protocol = result_.vlan_tag ? 
        result_.vlan_tag->ether_type : result_.header.ether_type;
    
    // 将解析结果存储到metadata中
    context.metadata["ethernet_result"] = result_;
    
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

// 验证以太网类型
bool EthernetParser::is_valid_ether_type(uint16_t ether_type) const noexcept {
    // 以太网类型应该 >= 0x0600 或者是特殊的802.3长度字段
    return ether_type >= 0x0600 || ether_type <= 1500;
}

// 工具函数实现
namespace ethernet_utils {

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
        try {
            unsigned long value = std::stoul(token, nullptr, 16);
            if (value > 255) return std::nullopt;
            mac[index++] = static_cast<uint8_t>(value);
        } catch (...) {
            return std::nullopt;
        }
    }
    
    return index == 6 ? std::optional<MacAddress>(mac) : std::nullopt;
}

bool is_valid_ether_type(uint16_t ether_type) {
    return ether_type >= 0x0600 || ether_type <= 1500;
}

std::string get_ether_type_name(uint16_t ether_type) {
    switch (ether_type) {
        case EtherType::IPv4: return "IPv4";
        case EtherType::ARP: return "ARP";
        case EtherType::IPv6: return "IPv6";
        case EtherType::VLAN: return "VLAN";
        case EtherType::MPLS: return "MPLS";
        default: 
            if (ether_type <= 1500) {
                return "802.3 Length";
            } else {
                return "Unknown (0x" + std::to_string(ether_type) + ")";
            }
    }
}

} // namespace ethernet_utils

// 注册解析器
REGISTER_PARSER(0x0001, EthernetParserFactory);

} // namespace protocol_parser::parsers