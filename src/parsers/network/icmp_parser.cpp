#include "../../../include/parsers/network/icmp_parser.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace protocol_parser::parsers {

// 协议信息定义
const ProtocolInfo ICMPParser::protocol_info_ = {
    .name = "ICMP",
    .type = 1,
    .header_size = ICMPHeader::SIZE,
    .min_packet_size = ICMPHeader::SIZE,
    .max_packet_size = 65535
};

// ICMP头部解析
std::expected<ICMPHeader, ParseResult> ICMPHeader::parse(const core::BufferView& buffer) noexcept {
    if (buffer.size() < SIZE) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    ICMPHeader header;
    size_t offset = 0;
    
    header.type = buffer[offset++];
    header.code = buffer[offset++];
    
    // 读取校验和（网络字节序）
    header.checksum = (static_cast<uint16_t>(buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    
    // 读取剩余字段（网络字节序）
    header.rest = (static_cast<uint32_t>(buffer[offset]) << 24) |
                  (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
                  (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
                  static_cast<uint32_t>(buffer[offset + 3]);
    
    return header;
}

bool ICMPHeader::verify_checksum(const core::BufferView& packet_data) const noexcept {
    return calculate_checksum(packet_data) == 0;
}

uint16_t ICMPHeader::calculate_checksum(const core::BufferView& packet_data) const noexcept {
    return icmp_utils::calculate_checksum(packet_data.data(), packet_data.size());
}

// ICMP解析器实现
ICMPParser::ICMPParser() {
    setup_state_machine();
}

const ProtocolInfo& ICMPParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool ICMPParser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < ICMPHeader::SIZE) {
        return false;
    }
    
    uint8_t type = buffer[0];
    return is_valid_type(type);
}

ParseResult ICMPParser::parse(ParseContext& context) noexcept {
    return state_machine_.execute(context);
}

void ICMPParser::reset() noexcept {
    result_ = ICMPParseResult{};
    state_machine_.set_state(ParserState::Initial);
    error_message_.clear();
}

double ICMPParser::get_progress() const noexcept {
    switch (state_machine_.current_state) {
        case ParserState::Initial: return 0.0;
        case ParserState::Parsing: return 0.5;
        case ParserState::Complete: return 1.0;
        case ParserState::Error: return 0.0;
        default: return 0.0;
    }
}

void ICMPParser::setup_state_machine() {
    state_machine_.transitions[ParserState::Initial] = [this](ParseContext& ctx) {
        return parse_header(ctx);
    };
    
    state_machine_.transitions[ParserState::Parsing] = [this](ParseContext& ctx) {
        return parse_payload(ctx);
    };
}

ParseResult ICMPParser::parse_header(ParseContext& context) noexcept {
    auto header_result = ICMPHeader::parse(context.buffer.substr(context.offset));
    if (!header_result) {
        error_message_ = "Failed to parse ICMP header";
        state_machine_.set_state(ParserState::Error);
        return header_result.error();
    }
    
    result_.header = header_result.value();
    result_.is_ipv6 = is_ipv6_mode_;
    
    // 验证类型
    if (!is_valid_type(result_.header.type)) {
        error_message_ = "Invalid ICMP type: " + std::to_string(result_.header.type);
        state_machine_.set_state(ParserState::Error);
        return ParseResult::InvalidFormat;
    }
    
    context.offset += ICMPHeader::SIZE;
    state_machine_.set_state(ParserState::Parsing);
    return ParseResult::Success;
}

ParseResult ICMPParser::parse_payload(ParseContext& context) noexcept {
    // 计算载荷长度
    size_t remaining = context.buffer.size() - context.offset;
    result_.payload_length = remaining;
    
    if (remaining > 0) {
        result_.payload = context.buffer.substr(context.offset, remaining);
        
        // 验证校验和
        core::BufferView full_packet = context.buffer.substr(context.offset - ICMPHeader::SIZE);
        result_.checksum_valid = result_.header.verify_checksum(full_packet);
    } else {
        result_.checksum_valid = true; // 空载荷情况下认为校验和有效
    }
    
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

bool ICMPParser::is_valid_type(uint8_t type) const noexcept {
    if (is_ipv6_mode_) {
        // ICMPv6类型验证
        return (type >= 1 && type <= 4) ||    // 错误消息
               (type >= 128 && type <= 137);   // 信息消息
    } else {
        // ICMPv4类型验证
        return (type >= 0 && type <= 18) || type == 30;
    }
}

// ICMP工具函数实现
namespace icmp_utils {

std::string get_type_name(uint8_t type, bool is_ipv6) {
    if (is_ipv6) {
        switch (type) {
            case ICMPType::DEST_UNREACHABLE_V6: return "Destination Unreachable";
            case ICMPType::PACKET_TOO_BIG: return "Packet Too Big";
            case ICMPType::TIME_EXCEEDED_V6: return "Time Exceeded";
            case ICMPType::PARAM_PROBLEM_V6: return "Parameter Problem";
            case ICMPType::ECHO_REQUEST_V6: return "Echo Request";
            case ICMPType::ECHO_REPLY_V6: return "Echo Reply";
            case ICMPType::ROUTER_SOLICITATION: return "Router Solicitation";
            case ICMPType::ROUTER_ADVERTISEMENT: return "Router Advertisement";
            case ICMPType::NEIGHBOR_SOLICITATION: return "Neighbor Solicitation";
            case ICMPType::NEIGHBOR_ADVERTISEMENT: return "Neighbor Advertisement";
            case ICMPType::REDIRECT_V6: return "Redirect";
            default: return "Unknown ICMPv6 Type (" + std::to_string(type) + ")";
        }
    } else {
        switch (type) {
            case ICMPType::ECHO_REPLY: return "Echo Reply";
            case ICMPType::DEST_UNREACHABLE: return "Destination Unreachable";
            case ICMPType::SOURCE_QUENCH: return "Source Quench";
            case ICMPType::REDIRECT: return "Redirect";
            case ICMPType::ECHO_REQUEST: return "Echo Request";
            case ICMPType::TIME_EXCEEDED: return "Time Exceeded";
            case ICMPType::PARAM_PROBLEM: return "Parameter Problem";
            case ICMPType::TIMESTAMP_REQ: return "Timestamp Request";
        case ICMPType::TIMESTAMP_REP: return "Timestamp Reply";
        case ICMPType::INFO_REQ: return "Information Request";
        case ICMPType::INFO_REP: return "Information Reply";
            default: return "Unknown ICMP Type (" + std::to_string(type) + ")";
        }
    }
}

std::string get_code_name(uint8_t type, uint8_t code, bool is_ipv6) {
    if (type == ICMPType::DEST_UNREACHABLE || type == ICMPType::DEST_UNREACHABLE_V6) {
        switch (code) {
            case ICMPCode::NET_UNREACHABLE: return "Network Unreachable";
            case ICMPCode::HOST_UNREACHABLE: return "Host Unreachable";
            case ICMPCode::PROTOCOL_UNREACHABLE: return "Protocol Unreachable";
            case ICMPCode::PORT_UNREACHABLE: return "Port Unreachable";
            case ICMPCode::FRAGMENTATION_NEEDED: return "Fragmentation Needed";
            case ICMPCode::SOURCE_ROUTE_FAILED: return "Source Route Failed";
            default: return "Unknown Code (" + std::to_string(code) + ")";
        }
    } else if (type == ICMPType::TIME_EXCEEDED || type == ICMPType::TIME_EXCEEDED_V6) {
        switch (code) {
            case ICMPCode::TTL_EXCEEDED: return "TTL Exceeded";
            case ICMPCode::FRAGMENT_REASSEMBLY_TIME_EXCEEDED: return "Fragment Reassembly Time Exceeded";
            default: return "Unknown Code (" + std::to_string(code) + ")";
        }
    }
    
    return std::to_string(code);
}

bool is_error_message(uint8_t type, bool is_ipv6) {
    if (is_ipv6) {
        return type >= 1 && type <= 4;
    } else {
        return type == ICMPType::DEST_UNREACHABLE ||
               type == ICMPType::SOURCE_QUENCH ||
               type == ICMPType::REDIRECT ||
               type == ICMPType::TIME_EXCEEDED ||
               type == ICMPType::PARAM_PROBLEM;
    }
}

bool is_info_message(uint8_t type, bool is_ipv6) {
    if (is_ipv6) {
        return type >= 128 && type <= 137;
    } else {
        return type == ICMPType::ECHO_REPLY ||
               type == ICMPType::ECHO_REQUEST ||
               type == ICMPType::TIMESTAMP_REQ ||
               type == ICMPType::TIMESTAMP_REP ||
               type == ICMPType::INFO_REQ ||
               type == ICMPType::INFO_REP;
    }
}

uint16_t calculate_checksum(const void* data, size_t length) {
    const uint16_t* ptr = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    
    // 按16位累加
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    
    // 处理奇数字节
    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr) << 8;
    }
    
    // 处理进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return static_cast<uint16_t>(~sum);
}

bool verify_checksum(const void* data, size_t length, uint16_t expected_checksum) {
    return calculate_checksum(data, length) == expected_checksum;
}

} // namespace icmp_utils

// 注册解析器
REGISTER_PARSER(1, ICMPParserFactory);   // ICMP
// ICMPv6使用相同的解析器，但通过不同的协议号区分
// REGISTER_PARSER(58, ICMPParserFactory);  // ICMPv6 - 暂时注释掉避免重复注册

} // namespace protocol_parser::parsers