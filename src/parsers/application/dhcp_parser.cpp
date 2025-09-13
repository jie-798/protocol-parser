#include "parsers/application/dhcp_parser.hpp"
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace ProtocolParser::Parsers::Application {

// DHCPOption 方法实现
uint32_t DHCPOption::as_uint32() const noexcept {
    if (data.size() >= 4) {
        return ntohl(*reinterpret_cast<const uint32_t*>(data.data()));
    }
    return 0;
}

uint16_t DHCPOption::as_uint16() const noexcept {
    if (data.size() >= 2) {
        return ntohs(*reinterpret_cast<const uint16_t*>(data.data()));
    }
    return 0;
}

uint8_t DHCPOption::as_uint8() const noexcept {
    return data.empty() ? 0 : data[0];
}

std::string DHCPOption::as_string() const {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<uint32_t> DHCPOption::as_ip_list() const {
    std::vector<uint32_t> ips;
    for (size_t i = 0; i + 3 < data.size(); i += 4) {
        ips.push_back(ntohl(*reinterpret_cast<const uint32_t*>(&data[i])));
    }
    return ips;
}

// DHCPMessage 方法实现
std::optional<DHCPOpcode> DHCPMessage::get_message_type() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DHCP_MESSAGE_TYPE && !option.data.empty()) {
            return static_cast<DHCPOpcode>(option.data[0]);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> DHCPMessage::get_server_identifier() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DHCP_SERVER_IDENTIFIER && option.data.size() >= 4) {
            return option.as_uint32();
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> DHCPMessage::get_requested_ip() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DHCP_REQUESTED_ADDRESS && option.data.size() >= 4) {
            return option.as_uint32();
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> DHCPMessage::get_lease_time() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DHCP_LEASE_TIME && option.data.size() >= 4) {
            return option.as_uint32();
        }
    }
    return std::nullopt;
}

std::optional<std::vector<uint32_t>> DHCPMessage::get_dns_servers() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DNS_SERVER && option.data.size() >= 4) {
            return option.as_ip_list();
        }
    }
    return std::nullopt;
}

std::optional<std::string> DHCPMessage::get_domain_name() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::DOMAIN_NAME && !option.data.empty()) {
            return option.as_string();
        }
    }
    return std::nullopt;
}

std::optional<std::string> DHCPMessage::get_hostname() const noexcept {
    for (const auto& option : options) {
        if (option.type == DHCPOptionType::HOST_NAME && !option.data.empty()) {
            return option.as_string();
        }
    }
    return std::nullopt;
}

bool DHCPMessage::is_broadcast() const noexcept {
    return (header.flags & DHCP_BROADCAST_FLAG) != 0;
}

// DHCPParser 方法实现
// DHCP解析器的主解析方法
ParseResult DHCPParser::parse(ParseContext& context) noexcept {
    return parse(context.buffer);
}

ParseResult DHCPParser::parse(const BufferView& buffer) noexcept {
    reset();
    
    try {
        const auto data = buffer.data();
        const auto size = buffer.size();
        
        if (size < DHCP_MIN_SIZE) {
            is_malformed_ = true;
            return ParseResult::NeedMoreData;
        }
        
        // 解析头部
        if (!parse_header(data, size)) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }
        
        // 检查魔数
        if (size >= DHCP_HEADER_SIZE + 4) {
            if (!is_valid_magic_cookie(data + DHCP_HEADER_SIZE)) {
                is_malformed_ = true;
                return ParseResult::InvalidFormat;
            }
            
            // 解析选项
            if (!parse_options(data, size, DHCP_HEADER_SIZE + 4)) {
                is_malformed_ = true;
                return ParseResult::InvalidFormat;
            }
        }
        
        // 验证消息
        if (!validate_message()) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }
        
        parsed_successfully_ = true;
        update_statistics(dhcp_message_);
        perform_security_analysis();
        
        return ParseResult::Success;
        
    } catch (const std::exception&) {
        reset();
        is_malformed_ = true;
        return ParseResult::InternalError;
    }
}

const ProtocolInfo& DHCPParser::get_protocol_info() const noexcept {
    static const ProtocolInfo info{
        "DHCP",         // name
        0x0800,         // type (IP)
        DHCP_HEADER_SIZE, // header_size
        DHCP_MIN_SIZE,    // min_packet_size
        1500              // max_packet_size
    };
    return info;
}

bool DHCPParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < DHCP_MIN_SIZE) {
        return false;
    }
    
    // 检查DHCP魔数
    if (buffer.size() >= DHCP_HEADER_SIZE + 4) {
        return is_valid_magic_cookie(buffer.data() + DHCP_HEADER_SIZE);
    }
    
    return true; // 仅有头部时也可能是DHCP
}

void DHCPParser::reset() noexcept {
    dhcp_message_ = DHCPMessage{};
    parsed_successfully_ = false;
    is_malformed_ = false;
}

const DHCPMessage& DHCPParser::get_dhcp_message() const noexcept {
    return dhcp_message_;
}

bool DHCPParser::is_dhcp_packet() const noexcept {
    return parsed_successfully_;
}

bool DHCPParser::validate_message() const noexcept {
    if (!validate_header(dhcp_message_.header)) {
        return false;
    }
    
    for (const auto& option : dhcp_message_.options) {
        if (!validate_option(option)) {
            return false;
        }
    }
    
    return true;
}

bool DHCPParser::is_malformed() const noexcept {
    return is_malformed_;
}

DHCPParser::DHCPAnalysis DHCPParser::analyze_message() const noexcept {
    DHCPAnalysis analysis;
    
    if (!parsed_successfully_) {
        return analysis;
    }
    
    // 分析消息类型
    const auto msg_type = dhcp_message_.get_message_type();
    if (msg_type) {
        switch (*msg_type) {
            case DHCPOpcode::DISCOVER:
            case DHCPOpcode::REQUEST:
            case DHCPOpcode::DECLINE:
            case DHCPOpcode::RELEASE:
            case DHCPOpcode::INFORM:
                analysis.is_client_request = true;
                break;
            case DHCPOpcode::OFFER:
            case DHCPOpcode::ACK:
            case DHCPOpcode::NAK:
                analysis.is_server_response = true;
                break;
            default:
                break;
        }
        
        analysis.is_renewal = (*msg_type == DHCPOpcode::REQUEST);
        analysis.is_rebinding = (*msg_type == DHCPOpcode::REQUEST && dhcp_message_.header.ciaddr != 0);
    }
    
    // 检查中继代理
    analysis.has_relay_agent = (dhcp_message_.header.giaddr != 0);
    
    // 分析选项
    analysis.total_options = dhcp_message_.options.size();
    
    for (const auto& option : dhcp_message_.options) {
        switch (option.type) {
            case DHCPOptionType::DHCP_VENDOR_CLASS_ID:
                if (!option.data.empty()) {
                    analysis.vendor_class = option.as_string();
                }
                break;
            case DHCPOptionType::DHCP_CLIENT_IDENTIFIER:
                if (!option.data.empty()) {
                    analysis.client_identifier = option.as_string();
                }
                break;
            case DHCPOptionType::DHCP_PARAMETER_REQUEST_LIST:
                for (uint8_t byte : option.data) {
                    analysis.requested_options.push_back(static_cast<DHCPOptionType>(byte));
                }
                break;
            default:
                // 检查未知选项
                if (static_cast<uint8_t>(option.type) > 76 && 
                    option.type != DHCPOptionType::DHCP_FQDN &&
                    option.type != DHCPOptionType::DHCP_AGENT_OPTIONS) {
                    analysis.unknown_options++;
                }
                break;
        }
    }
    
    return analysis;
}

const DHCPParser::DHCPStatistics& DHCPParser::get_statistics() const noexcept {
    return statistics_;
}

void DHCPParser::reset_statistics() noexcept {
    statistics_ = DHCPStatistics{};
}

std::string DHCPParser::ip_to_string(uint32_t ip) noexcept {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = htonl(ip);
    return inet_ntoa(addr.sin_addr);
}

std::string DHCPParser::mac_to_string(const std::array<uint8_t, 16>& mac, uint8_t len) noexcept {
    std::ostringstream oss;
    for (uint8_t i = 0; i < std::min(len, static_cast<uint8_t>(16)); ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string DHCPParser::option_type_to_string(DHCPOptionType type) noexcept {
    switch (type) {
        case DHCPOptionType::SUBNET_MASK: return "Subnet Mask";
        case DHCPOptionType::ROUTER: return "Router";
        case DHCPOptionType::DNS_SERVER: return "DNS Server";
        case DHCPOptionType::HOST_NAME: return "Host Name";
        case DHCPOptionType::DOMAIN_NAME: return "Domain Name";
        case DHCPOptionType::DHCP_MESSAGE_TYPE: return "DHCP Message Type";
        case DHCPOptionType::DHCP_SERVER_IDENTIFIER: return "DHCP Server Identifier";
        case DHCPOptionType::DHCP_LEASE_TIME: return "DHCP Lease Time";
        case DHCPOptionType::DHCP_REQUESTED_ADDRESS: return "DHCP Requested Address";
        default: return "Unknown Option";
    }
}

std::string DHCPParser::message_type_to_string(DHCPOpcode type) noexcept {
    switch (type) {
        case DHCPOpcode::DISCOVER: return "DHCPDISCOVER";
        case DHCPOpcode::OFFER: return "DHCPOFFER";
        case DHCPOpcode::REQUEST: return "DHCPREQUEST";
        case DHCPOpcode::DECLINE: return "DHCPDECLINE";
        case DHCPOpcode::ACK: return "DHCPACK";
        case DHCPOpcode::NAK: return "DHCPNAK";
        case DHCPOpcode::RELEASE: return "DHCPRELEASE";
        case DHCPOpcode::INFORM: return "DHCPINFORM";
        default: return "Unknown";
    }
}

bool DHCPParser::is_valid_magic_cookie(const uint8_t* data) noexcept {
    const uint32_t cookie = ntohl(*reinterpret_cast<const uint32_t*>(data));
    return cookie == DHCP_MAGIC_COOKIE;
}

bool DHCPParser::parse_header(const uint8_t* data, size_t size) noexcept {
    if (size < DHCP_HEADER_SIZE) {
        return false;
    }
    
    const uint8_t* ptr = data;
    
    // 解析固定头部字段
    dhcp_message_.header.op = static_cast<DHCPMessageType>(*ptr++);
    dhcp_message_.header.htype = static_cast<DHCPHardwareType>(*ptr++);
    dhcp_message_.header.hlen = *ptr++;
    dhcp_message_.header.hops = *ptr++;
    
    dhcp_message_.header.xid = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
    ptr += 4;
    
    dhcp_message_.header.secs = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
    ptr += 2;
    
    dhcp_message_.header.flags = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
    ptr += 2;
    
    dhcp_message_.header.ciaddr = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
    ptr += 4;
    
    dhcp_message_.header.yiaddr = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
    ptr += 4;
    
    dhcp_message_.header.siaddr = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
    ptr += 4;
    
    dhcp_message_.header.giaddr = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
    ptr += 4;
    
    // 复制硬件地址
    std::memcpy(dhcp_message_.header.chaddr.data(), ptr, 16);
    ptr += 16;
    
    // 复制服务器名称
    std::memcpy(dhcp_message_.header.sname.data(), ptr, 64);
    ptr += 64;
    
    // 复制文件名
    std::memcpy(dhcp_message_.header.file.data(), ptr, 128);
    
    return true;
}

bool DHCPParser::parse_options(const uint8_t* data, size_t size, size_t offset) noexcept {
    size_t current_offset = offset;
    
    while (current_offset < size) {
        if (!parse_single_option(data, size, current_offset)) {
            return false;
        }
        
        // 检查是否遇到END选项
        if (current_offset > offset && 
            data[current_offset - dhcp_message_.options.back().length - 2] == static_cast<uint8_t>(DHCPOptionType::END)) {
            break;
        }
    }
    
    return true;
}

bool DHCPParser::parse_single_option(const uint8_t* data, size_t size, size_t& offset) noexcept {
    if (offset >= size) {
        return false;
    }
    
    DHCPOption option;
    option.type = static_cast<DHCPOptionType>(data[offset++]);
    
    // PAD和END选项没有长度字段
    if (option.type == DHCPOptionType::PAD) {
        dhcp_message_.options.push_back(option);
        return true;
    }
    
    if (option.type == DHCPOptionType::END) {
        dhcp_message_.options.push_back(option);
        return true;
    }
    
    // 读取长度字段
    if (offset >= size) {
        return false;
    }
    
    option.length = data[offset++];
    
    // 读取数据
    if (offset + option.length > size) {
        return false;
    }
    
    option.data.assign(data + offset, data + offset + option.length);
    offset += option.length;
    
    dhcp_message_.options.push_back(option);
    return true;
}

bool DHCPParser::validate_header(const DHCPHeader& header) const noexcept {
    // 验证操作码
    if (header.op != DHCPMessageType::BOOTREQUEST && header.op != DHCPMessageType::BOOTREPLY) {
        return false;
    }
    
    // 验证硬件类型
    if (header.htype == DHCPHardwareType::ETHERNET && header.hlen != 6) {
        return false;
    }
    
    // 验证跳数限制
    if (header.hops > 16) {
        return false;
    }
    
    return true;
}

bool DHCPParser::validate_option(const DHCPOption& option) const noexcept {
    switch (option.type) {
        case DHCPOptionType::SUBNET_MASK:
        case DHCPOptionType::ROUTER:
        case DHCPOptionType::DNS_SERVER:
        case DHCPOptionType::DHCP_SERVER_IDENTIFIER:
        case DHCPOptionType::DHCP_REQUESTED_ADDRESS:
            return option.data.size() % 4 == 0 && !option.data.empty();
            
        case DHCPOptionType::DHCP_MESSAGE_TYPE:
            return option.data.size() == 1;
            
        case DHCPOptionType::DHCP_LEASE_TIME:
        case DHCPOptionType::DHCP_RENEWAL_TIME:
        case DHCPOptionType::DHCP_REBINDING_TIME:
            return option.data.size() == 4;
            
        case DHCPOptionType::PAD:
        case DHCPOptionType::END:
            return option.data.empty();
            
        default:
            return true; // 未知选项默认有效
    }
}

void DHCPParser::perform_security_analysis() noexcept {
    // 在实际实现中，这里会进行安全分析
    // 例如检测异常长的选项、无效的IP地址、恶意的魔数等
}

void DHCPParser::update_statistics(const DHCPMessage& message) noexcept {
    statistics_.total_messages++;
    
    const auto msg_type = message.get_message_type();
    if (msg_type) {
        switch (*msg_type) {
            case DHCPOpcode::DISCOVER: statistics_.discover_count++; break;
            case DHCPOpcode::OFFER: statistics_.offer_count++; break;
            case DHCPOpcode::REQUEST: statistics_.request_count++; break;
            case DHCPOpcode::ACK: statistics_.ack_count++; break;
            case DHCPOpcode::NAK: statistics_.nak_count++; break;
            case DHCPOpcode::RELEASE: statistics_.release_count++; break;
            case DHCPOpcode::INFORM: statistics_.inform_count++; break;
            default: break;
        }
    }
    
    // 统计选项使用情况
    for (const auto& option : message.options) {
        statistics_.option_usage[option.type]++;
    }
    
    if (is_malformed_) {
        statistics_.malformed_count++;
    }
}

} // namespace ProtocolParser::Parsers::Application