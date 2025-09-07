#include "parsers/ipv4_parser.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace protocol_parser::parsers {

// 协议信息定义
const ProtocolInfo IPv4Parser::protocol_info_ = {
    .name = "IPv4",
    .type = 0x0800,
    .header_size = IPv4Header::MIN_SIZE,
    .min_packet_size = IPv4Header::MIN_SIZE,
    .max_packet_size = 65535
};

// IPv4头解析
std::expected<IPv4Header, ParseResult> IPv4Header::parse(const core::BufferView& buffer) noexcept {
    if (buffer.size() < MIN_SIZE) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    IPv4Header header;
    
    // 解析基本字段
    header.version_ihl = buffer[0];
    header.tos = buffer[1];
    header.total_length = buffer.read_be<uint16_t>(2);
    header.identification = buffer.read_be<uint16_t>(4);
    header.flags_fragment = buffer.read_be<uint16_t>(6);
    header.ttl = buffer[8];
    header.protocol = buffer[9];
    header.checksum = buffer.read_be<uint16_t>(10);
    
    // 解析IP地址
    std::memcpy(header.src_ip.data(), buffer.data() + 12, 4);
    std::memcpy(header.dst_ip.data(), buffer.data() + 16, 4);
    
    // 验证版本号
    if (header.get_version() != 4) {
        return std::unexpected(ParseResult::UnsupportedVersion);
    }
    
    // 验证头长度
    uint8_t header_len = header.get_header_length();
    if (header_len < MIN_SIZE || header_len > MAX_SIZE) {
        return std::unexpected(ParseResult::InvalidFormat);
    }
    
    if (buffer.size() < header_len) {
        return std::unexpected(ParseResult::BufferTooSmall);
    }
    
    return header;
}

bool IPv4Header::verify_checksum(const core::BufferView& header_data) const noexcept {
    return calculate_checksum(header_data) == 0;
}

uint16_t IPv4Header::calculate_checksum(const core::BufferView& header_data) const noexcept {
    return ipv4_utils::calculate_checksum(header_data.data(), get_header_length());
}

std::string IPv4Header::src_ip_string() const {
    return ipv4_utils::format_ipv4_address(src_ip);
}

std::string IPv4Header::dst_ip_string() const {
    return ipv4_utils::format_ipv4_address(dst_ip);
}

// IPv4解析器实现
IPv4Parser::IPv4Parser() {
    setup_state_machine();
}

const ProtocolInfo& IPv4Parser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool IPv4Parser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < IPv4Header::MIN_SIZE) {
        return false;
    }
    
    // 检查版本号
    uint8_t version = (buffer[0] >> 4) & 0x0F;
    return version == 4;
}

ParseResult IPv4Parser::parse(ParseContext& context) noexcept {
    context.state = ParserState::Parsing;
    
    // 执行状态机直到完成或出错
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

void IPv4Parser::reset() noexcept {
    state_machine_.set_state(ParserState::Initial);
    result_ = IPv4ParseResult{};
    error_message_.clear();
}

double IPv4Parser::get_progress() const noexcept {
    switch (state_machine_.current_state) {
        case ParserState::Initial: return 0.0;
        case ParserState::Parsing: return 0.5;
        case ParserState::Complete: return 1.0;
        case ParserState::Error: return 0.0;
        default: return 0.0;
    }
}

// 状态机设置
void IPv4Parser::setup_state_machine() {
    state_machine_.transitions[ParserState::Initial] = 
        [this](ParseContext& ctx) { return parse_header(ctx); };
    
    state_machine_.transitions[ParserState::Parsing] = 
        [this](ParseContext& ctx) {
            if (parse_options_ && result_.header.get_header_length() > IPv4Header::MIN_SIZE) {
                return parse_options(ctx);
            } else {
                return parse_payload(ctx);
            }
        };
}

// 解析IPv4头
ParseResult IPv4Parser::parse_header(ParseContext& context) noexcept {
    auto header_result = IPv4Header::parse(context.buffer);
    if (!header_result) {
        error_message_ = "Failed to parse IPv4 header";
        state_machine_.set_state(ParserState::Error);
        return header_result.error();
    }
    
    result_.header = *header_result;
    
    // 验证校验和
    if (verify_checksum_) {
        auto header_view = context.buffer.prefix(result_.header.get_header_length());
        result_.checksum_valid = result_.header.verify_checksum(header_view);
        
        if (!result_.checksum_valid) {
            error_message_ = "IPv4 header checksum verification failed";
            // 注意：校验和错误不一定是致命错误，继续解析
        }
    } else {
        result_.checksum_valid = true;  // 跳过验证时假设有效
    }
    
    context.offset += IPv4Header::MIN_SIZE;
    state_machine_.set_state(ParserState::Parsing);
    return ParseResult::Success;
}

// 解析IPv4选项
ParseResult IPv4Parser::parse_options(ParseContext& context) noexcept {
    uint8_t header_len = result_.header.get_header_length();
    size_t options_len = header_len - IPv4Header::MIN_SIZE;
    
    if (!context.buffer.can_read(options_len, context.offset)) {
        return ParseResult::NeedMoreData;
    }
    
    size_t options_offset = context.offset;
    size_t end_offset = context.offset + options_len;
    
    while (options_offset < end_offset) {
        IPv4Option option;
        auto parse_result = parse_single_option(context.buffer, options_offset, option);
        
        if (parse_result != ParseResult::Success) {
            error_message_ = "Failed to parse IPv4 option";
            state_machine_.set_state(ParserState::Error);
            return parse_result;
        }
        
        result_.options.push_back(std::move(option));
        
        // End of Options List
        if (option.type == 0) {
            break;
        }
    }
    
    context.offset = context.offset + options_len;
    return parse_payload(context);
}

// 解析单个IPv4选项
ParseResult IPv4Parser::parse_single_option(const core::BufferView& buffer, size_t& offset, IPv4Option& option) noexcept {
    if (!buffer.can_read(1, offset)) {
        return ParseResult::NeedMoreData;
    }
    
    option.type = buffer[offset++];
    
    // End of Options List 或 No Operation
    if (option.type == 0 || option.type == 1) {
        option.length = 1;
        return ParseResult::Success;
    }
    
    // 其他选项需要长度字段
    if (!buffer.can_read(1, offset)) {
        return ParseResult::NeedMoreData;
    }
    
    option.length = buffer[offset++];
    
    if (option.length < 2) {
        return ParseResult::InvalidFormat;
    }
    
    // 读取选项数据
    size_t data_len = option.length - 2;
    if (data_len > 0) {
        if (!buffer.can_read(data_len, offset)) {
            return ParseResult::NeedMoreData;
        }
        
        option.data.resize(data_len);
        std::memcpy(option.data.data(), buffer.data() + offset, data_len);
        offset += data_len;
    }
    
    return ParseResult::Success;
}

// 解析载荷
ParseResult IPv4Parser::parse_payload(ParseContext& context) noexcept {
    uint16_t total_len = result_.header.total_length;
    uint8_t header_len = result_.header.get_header_length();
    
    if (total_len < header_len) {
        error_message_ = "Invalid IPv4 total length";
        state_machine_.set_state(ParserState::Error);
        return ParseResult::InvalidFormat;
    }
    
    size_t payload_len = total_len - header_len;
    
    if (context.offset + payload_len > context.buffer.size()) {
        // 数据包可能被截断，使用可用的数据
        payload_len = context.buffer.size() - context.offset;
    }
    
    if (payload_len > 0) {
        result_.payload = context.buffer.substr(context.offset, payload_len);
    }
    
    // 将解析结果存储到metadata中
    context.metadata["ipv4_result"] = result_;
    
    state_machine_.set_state(ParserState::Complete);
    return ParseResult::Success;
}

// 工具函数实现
namespace ipv4_utils {

std::string format_ipv4_address(const IPv4Address& ip) {
    std::ostringstream oss;
    oss << static_cast<unsigned>(ip[0]) << "."
        << static_cast<unsigned>(ip[1]) << "."
        << static_cast<unsigned>(ip[2]) << "."
        << static_cast<unsigned>(ip[3]);
    return oss.str();
}

std::optional<IPv4Address> parse_ipv4_address(const std::string& ip_str) {
    IPv4Address ip;
    std::istringstream iss(ip_str);
    std::string token;
    size_t index = 0;
    
    while (std::getline(iss, token, '.') && index < 4) {
        try {
            int value = std::stoi(token);
            if (value < 0 || value > 255) return std::nullopt;
            ip[index++] = static_cast<uint8_t>(value);
        } catch (...) {
            return std::nullopt;
        }
    }
    
    return index == 4 ? std::optional<IPv4Address>(ip) : std::nullopt;
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

bool is_private_address(const IPv4Address& ip) {
    // 10.0.0.0/8
    if (ip[0] == 10) return true;
    
    // 172.16.0.0/12
    if (ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) return true;
    
    // 192.168.0.0/16
    if (ip[0] == 192 && ip[1] == 168) return true;
    
    return false;
}

bool is_multicast_address(const IPv4Address& ip) {
    // 224.0.0.0/4
    return (ip[0] >= 224 && ip[0] <= 239);
}

bool is_broadcast_address(const IPv4Address& ip) {
    return ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255;
}

bool is_loopback_address(const IPv4Address& ip) {
    // 127.0.0.0/8
    return ip[0] == 127;
}

std::string get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPProtocol::ICMP: return "ICMP";
        case IPProtocol::TCP: return "TCP";
        case IPProtocol::UDP: return "UDP";
        case IPProtocol::IPv6: return "IPv6";
        case IPProtocol::GRE: return "GRE";
        case IPProtocol::ESP: return "ESP";
        case IPProtocol::AH: return "AH";
        default: return "Unknown (" + std::to_string(protocol) + ")";
    }
}

std::string get_option_name(uint8_t option_type) {
    switch (option_type) {
        case 0: return "End of Options List";
        case 1: return "No Operation";
        case 2: return "Security";
        case 3: return "Loose Source Routing";
        case 4: return "Timestamp";
        case 7: return "Record Route";
        case 8: return "Stream ID";
        case 9: return "Strict Source Routing";
        default: return "Unknown (" + std::to_string(option_type) + ")";
    }
}

} // namespace ipv4_utils

// 注册解析器
REGISTER_PARSER(0x0800, IPv4ParserFactory);

} // namespace protocol_parser::parsers