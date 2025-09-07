#include "parsers/icmpv6_parser.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace protocol_parser::parsers {

// ICMPv6协议信息
const ProtocolInfo ICMPv6Parser::protocol_info_ = {
    .name = "ICMPv6",
    .type = 58,
    .header_size = ICMPv6Header::SIZE,
    .min_packet_size = ICMPv6Header::SIZE,
    .max_packet_size = 65535
};

// ICMPv6头部解析
std::expected<ICMPv6Header, ParseResult> ICMPv6Header::parse(const core::BufferView& buffer) noexcept {
    if (buffer.size() < SIZE) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    ICMPv6Header header;
    header.type = buffer[0];
    header.code = buffer[1];
    header.checksum = (static_cast<uint16_t>(buffer[2]) << 8) | buffer[3];
    header.data = (static_cast<uint32_t>(buffer[4]) << 24) |
                  (static_cast<uint32_t>(buffer[5]) << 16) |
                  (static_cast<uint32_t>(buffer[6]) << 8) |
                  buffer[7];
    
    return header;
}

bool ICMPv6Header::verify_checksum(const core::BufferView& packet_data,
                                  const std::array<uint8_t, 16>& src_addr,
                                  const std::array<uint8_t, 16>& dst_addr,
                                  uint32_t payload_length) const noexcept {
    uint16_t calculated = calculate_checksum(packet_data, src_addr, dst_addr, payload_length);
    return calculated == 0;  // 校验和正确时计算结果应为0
}

uint16_t ICMPv6Header::calculate_checksum(const core::BufferView& packet_data,
                                         const std::array<uint8_t, 16>& src_addr,
                                         const std::array<uint8_t, 16>& dst_addr,
                                         uint32_t payload_length) const noexcept {
    return icmpv6_utils::calculate_checksum(packet_data.data(), packet_data.size(),
                                           src_addr, dst_addr, payload_length);
}

// ICMPv6解析器实现
ICMPv6Parser::ICMPv6Parser() {
    setup_state_machine();
}

const ProtocolInfo& ICMPv6Parser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool ICMPv6Parser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < ICMPv6Header::SIZE) {
        return false;
    }
    
    uint8_t type = buffer[0];
    return is_valid_type(type);
}

ParseResult ICMPv6Parser::parse(ParseContext& context) noexcept {
    return state_machine_.execute(context);
}

void ICMPv6Parser::reset() noexcept {
    result_ = ICMPv6ParseResult{};
    state_machine_.set_state(ParserState::Initial);
    error_message_.clear();
    has_addresses_ = false;
}

double ICMPv6Parser::get_progress() const noexcept {
    switch (state_machine_.current_state) {
        case ParserState::Initial: return 0.0;
        case ParserState::Parsing: return 0.5;
        case ParserState::Complete: return 1.0;
        case ParserState::Error: return 0.0;
        default: return 0.0;
    }
}

void ICMPv6Parser::setup_state_machine() {
    state_machine_.transitions[ParserState::Initial] = [this](ParseContext& ctx) {
        return parse_header(ctx);
    };
    
    state_machine_.transitions[ParserState::Parsing] = [this](ParseContext& ctx) {
        return parse_payload(ctx);
    };
}

ParseResult ICMPv6Parser::parse_header(ParseContext& context) noexcept {
    auto header_result = ICMPv6Header::parse(context.buffer.substr(context.offset));
    if (!header_result) {
        error_message_ = "Failed to parse ICMPv6 header";
        return header_result.error();
    }
    
    result_.header = *header_result;
    
    // 验证类型
    if (!is_valid_type(result_.header.type)) {
        error_message_ = "Invalid ICMPv6 type: " + std::to_string(result_.header.type);
        return ParseResult::InvalidFormat;
    }
    
    context.offset += ICMPv6Header::SIZE;
    state_machine_.set_state(ParserState::Parsing);
    return ParseResult::Success;
}

ParseResult ICMPv6Parser::parse_payload(ParseContext& context) noexcept {
    size_t remaining = context.buffer.size() - context.offset;
    result_.payload = context.buffer.substr(context.offset, remaining);
    result_.payload_length = remaining;
    
    // 验证校验和（如果有IPv6地址信息）
    if (has_addresses_) {
        result_.checksum_valid = result_.header.verify_checksum(
            context.buffer.substr(context.offset - ICMPv6Header::SIZE),
            src_addr_, dst_addr_, remaining + ICMPv6Header::SIZE
        );
    }
    
    // 解析邻居发现选项（如果适用）
    if (has_nd_options(result_.header.type)) {
        return parse_nd_options(context);
    }
    
    context.offset += remaining;
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

ParseResult ICMPv6Parser::parse_nd_options(ParseContext& context) noexcept {
    size_t option_start = context.offset;
    
    // 跳过固定部分（根据消息类型不同）
    switch (result_.header.type) {
        case ICMPv6Type::ROUTER_SOLICITATION:
            option_start += 4;  // 跳过保留字段
            break;
        case ICMPv6Type::ROUTER_ADVERTISEMENT:
            option_start += 12; // 跳过Hop Limit, Flags, Router Lifetime, Reachable Time, Retrans Timer
            break;
        case ICMPv6Type::NEIGHBOR_SOLICITATION:
            option_start += 20; // 跳过保留字段和目标地址
            break;
        case ICMPv6Type::NEIGHBOR_ADVERTISEMENT:
            option_start += 20; // 跳过标志和目标地址
            break;
        case ICMPv6Type::REDIRECT:
            option_start += 36; // 跳过保留字段、目标地址和目的地址
            break;
        default:
            // 其他类型不包含ND选项
            context.offset = context.buffer.size();
            state_machine_.set_state(ParserState::Complete);
            return ParseResult::Success;
    }
    
    // 解析选项
    while (option_start < context.buffer.size()) {
        if (option_start + 2 > context.buffer.size()) {
            break; // 不足以读取选项头部
        }
        
        NDOption option;
        option.type = context.buffer[option_start];
        option.length = context.buffer[option_start + 1];
        
        if (option.length == 0) {
            break; // 无效长度
        }
        
        size_t option_size = option.length * 8;
        if (option_start + option_size > context.buffer.size()) {
            break; // 选项超出缓冲区
        }
        
        result_.nd_options.push_back(option);
        option_start += option_size;
    }
    
    context.offset = context.buffer.size();
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

bool ICMPv6Parser::is_valid_type(uint8_t type) const noexcept {
    // 错误消息 (1-127)
    if (type >= 1 && type <= 4) {
        return true;
    }
    
    // 信息消息 (128-255)
    if (type >= 128) {
        return (type >= 128 && type <= 137) ||  // Echo和邻居发现
               (type >= 130 && type <= 132);    // MLD
    }
    
    return false;
}

bool ICMPv6Parser::is_error_message(uint8_t type) const noexcept {
    return type >= 1 && type <= 127;
}

bool ICMPv6Parser::is_info_message(uint8_t type) const noexcept {
    return type >= 128;
}

bool ICMPv6Parser::has_nd_options(uint8_t type) const noexcept {
    return type == ICMPv6Type::ROUTER_SOLICITATION ||
           type == ICMPv6Type::ROUTER_ADVERTISEMENT ||
           type == ICMPv6Type::NEIGHBOR_SOLICITATION ||
           type == ICMPv6Type::NEIGHBOR_ADVERTISEMENT ||
           type == ICMPv6Type::REDIRECT;
}

// ICMPv6工具函数实现
namespace icmpv6_utils {

std::string get_type_name(uint8_t type) {
    switch (type) {
        case ICMPv6Type::DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMPv6Type::PACKET_TOO_BIG: return "Packet Too Big";
        case ICMPv6Type::TIME_EXCEEDED: return "Time Exceeded";
        case ICMPv6Type::PARAM_PROBLEM: return "Parameter Problem";
        case ICMPv6Type::ECHO_REQUEST: return "Echo Request";
        case ICMPv6Type::ECHO_REPLY: return "Echo Reply";
        case ICMPv6Type::MLD_QUERY: return "Multicast Listener Query";
        case ICMPv6Type::MLD_REPORT: return "Multicast Listener Report";
        case ICMPv6Type::MLD_DONE: return "Multicast Listener Done";
        case ICMPv6Type::ROUTER_SOLICITATION: return "Router Solicitation";
        case ICMPv6Type::ROUTER_ADVERTISEMENT: return "Router Advertisement";
        case ICMPv6Type::NEIGHBOR_SOLICITATION: return "Neighbor Solicitation";
        case ICMPv6Type::NEIGHBOR_ADVERTISEMENT: return "Neighbor Advertisement";
        case ICMPv6Type::REDIRECT: return "Redirect";
        default: return "Unknown (" + std::to_string(type) + ")";
    }
}

std::string get_code_name(uint8_t type, uint8_t code) {
    switch (type) {
        case ICMPv6Type::DEST_UNREACHABLE:
            switch (code) {
                case ICMPv6Code::NO_ROUTE: return "No route to destination";
                case ICMPv6Code::ADMIN_PROHIBITED: return "Communication administratively prohibited";
                case ICMPv6Code::BEYOND_SCOPE: return "Beyond scope of source address";
                case ICMPv6Code::ADDR_UNREACHABLE: return "Address unreachable";
                case ICMPv6Code::PORT_UNREACHABLE: return "Port unreachable";
                case ICMPv6Code::SOURCE_ADDR_FAILED: return "Source address failed ingress/egress policy";
                case ICMPv6Code::REJECT_ROUTE: return "Reject route to destination";
                default: return "Unknown code (" + std::to_string(code) + ")";
            }
        case ICMPv6Type::TIME_EXCEEDED:
            switch (code) {
                case ICMPv6Code::HOP_LIMIT_EXCEEDED: return "Hop limit exceeded in transit";
                case ICMPv6Code::FRAGMENT_REASSEMBLY_TIME_EXCEEDED: return "Fragment reassembly time exceeded";
                default: return "Unknown code (" + std::to_string(code) + ")";
            }
        case ICMPv6Type::PARAM_PROBLEM:
            switch (code) {
                case ICMPv6Code::ERRONEOUS_HEADER_FIELD: return "Erroneous header field encountered";
                case ICMPv6Code::UNRECOGNIZED_NEXT_HEADER: return "Unrecognized Next Header type encountered";
                case ICMPv6Code::UNRECOGNIZED_IPV6_OPTION: return "Unrecognized IPv6 option encountered";
                default: return "Unknown code (" + std::to_string(code) + ")";
            }
        default:
            return code == 0 ? "" : "Code " + std::to_string(code);
    }
}

bool is_error_message(uint8_t type) {
    return type >= 1 && type <= 127;
}

bool is_info_message(uint8_t type) {
    return type >= 128;
}

uint16_t calculate_checksum(const void* data, size_t length,
                           const std::array<uint8_t, 16>& src_addr,
                           const std::array<uint8_t, 16>& dst_addr,
                           uint32_t payload_length) {
    uint32_t sum = 0;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    
    // IPv6伪头部校验和
    // 源地址
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint16_t>(src_addr[i]) << 8) | src_addr[i + 1];
    }
    
    // 目标地址
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint16_t>(dst_addr[i]) << 8) | dst_addr[i + 1];
    }
    
    // 载荷长度
    sum += (payload_length >> 16) & 0xFFFF;
    sum += payload_length & 0xFFFF;
    
    // 下一个头部（ICMPv6 = 58）
    sum += 58;
    
    // ICMPv6数据校验和
    for (size_t i = 0; i < length; i += 2) {
        if (i + 1 < length) {
            sum += (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
        } else {
            sum += static_cast<uint16_t>(bytes[i]) << 8;
        }
    }
    
    // 折叠进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return static_cast<uint16_t>(~sum);
}

bool verify_checksum(const void* data, size_t length,
                    const std::array<uint8_t, 16>& src_addr,
                    const std::array<uint8_t, 16>& dst_addr,
                    uint32_t payload_length,
                    uint16_t expected_checksum) {
    uint16_t calculated = calculate_checksum(data, length, src_addr, dst_addr, payload_length);
    return calculated == expected_checksum;
}

} // namespace icmpv6_utils

// 注册解析器
REGISTER_PARSER(58, ICMPv6ParserFactory);  // ICMPv6

} // namespace protocol_parser::parsers