#include "../../../include/parsers/application/ssh_parser.hpp"
#include <algorithm>
#include <sstream>
#include <cstring>

namespace protocol_parser::parsers {

// 类型引用已在头文件中简化
// SSH相关类型已在头文件中定义

ParseResult SSHParser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;
    if (buffer.size() < 4) {
        return ParseResult::NeedMoreData;
    }
    
    if (!validate_ssh_packet(buffer)) {
        return ParseResult::InvalidFormat;
    }
    
    // Determine parsing based on connection state
    switch (ssh_connection_.state) {
        case SSHConnectionState::VERSION_EXCHANGE:
        case SSHConnectionState::UNKNOWN:
            return parse_version_exchange(buffer);
            
        case SSHConnectionState::KEY_EXCHANGE:
        case SSHConnectionState::AUTHENTICATION:
        case SSHConnectionState::CONNECTION:
            return parse_binary_packet(buffer);
            
        case SSHConnectionState::DISCONNECTED:
            return ParseResult::InvalidFormat;
            
        default:
            return ParseResult::InvalidFormat;
    }
}

ParseResult SSHParser::parse_version_exchange(const BufferView& buffer) {
    if (!is_version_line_complete(buffer)) {
        return ParseResult::NeedMoreData;
    }
    
    // Convert buffer to string
    std::string data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    
    // Find the end of the version line
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) {
        line_end = data.find('\n');
        if (line_end == std::string::npos) {
            return ParseResult::NeedMoreData;
        }
    }
    
    std::string version_line = data.substr(0, line_end);
    
    if (!validate_version_string(version_line)) {
        return ParseResult::InvalidFormat;
    }
    
    // Parse version string: "SSH-protoversion-softwareversion SP comments"
    SSHVersionExchange version_info;
    
    // Split by spaces to separate version and comments
    size_t space_pos = version_line.find(' ');
    std::string version_part = (space_pos != std::string::npos) ? 
                              version_line.substr(0, space_pos) : version_line;
    
    if (space_pos != std::string::npos && space_pos + 1 < version_line.length()) {
        version_info.comments = version_line.substr(space_pos + 1);
    }
    
    // Parse version part: "SSH-protoversion-softwareversion"
    std::vector<std::string> parts;
    std::istringstream iss(version_part);
    std::string part;
    
    while (std::getline(iss, part, '-')) {
        parts.push_back(part);
    }
    
    if (parts.size() < 3 || parts[0] != "SSH") {
        return ParseResult::InvalidFormat;
    }
    
    version_info.version_string = version_part;
    version_info.version = string_to_version(parts[1]);
    
    // Combine software version parts (everything after protocol version)
    for (size_t i = 2; i < parts.size(); ++i) {
        if (i > 2) version_info.software_version += "-";
        version_info.software_version += parts[i];
    }
    
    // Determine if this is client or server version
    if (!ssh_connection_.version_exchange_complete) {
        if (ssh_connection_.client_version.version_string.empty()) {
            ssh_connection_.client_version = version_info;
        } else {
            ssh_connection_.server_version = version_info;
            ssh_connection_.version_exchange_complete = true;
            update_connection_state();
        }
    }
    
    return ParseResult::Success;
}

ParseResult SSHParser::parse_binary_packet(const BufferView& buffer) {
    if (buffer.size() < 5) { // Minimum: packet_length(4) + padding_length(1)
        return ParseResult::NeedMoreData;
    }
    
    SSHBinaryPacket packet;
    
    // Read packet length (first 4 bytes, big-endian)
    packet.packet_length = (static_cast<uint32_t>(buffer.data()[0]) << 24) |
                          (static_cast<uint32_t>(buffer.data()[1]) << 16) |
                          (static_cast<uint32_t>(buffer.data()[2]) << 8) |
                          static_cast<uint32_t>(buffer.data()[3]);
    
    // Validate packet length
    if (packet.packet_length < 1 || packet.packet_length > 35000) {
        return ParseResult::InvalidFormat;
    }
    
    // Check if we have the complete packet
    size_t total_packet_size = 4 + packet.packet_length; // 4 bytes for length field
    if (buffer.size() < total_packet_size) {
        return ParseResult::NeedMoreData;
    }
    
    // Read padding length
    packet.padding_length = buffer.data()[4];
    
    // Validate padding length
    if (packet.padding_length < 4 || packet.padding_length >= packet.packet_length) {
        return ParseResult::InvalidFormat;
    }
    
    // Calculate payload size
    size_t payload_size = packet.packet_length - 1 - packet.padding_length;
    
    // Read payload
    packet.payload.resize(payload_size);
    std::memcpy(packet.payload.data(), buffer.data() + 5, payload_size);
    
    // Read padding
    packet.padding.resize(packet.padding_length);
    std::memcpy(packet.padding.data(), buffer.data() + 5 + payload_size, packet.padding_length);
    
    // For now, assume no MAC (would need encryption context to determine)
    packet.has_mac = false;
    
    return parse_ssh_message(packet);
}

ParseResult SSHParser::parse_ssh_message(const SSHBinaryPacket& packet) {
    if (packet.payload.empty()) {
        return ParseResult::InvalidFormat;
    }
    
    SSHMessage message;
    message.type = static_cast<SSHMessageType>(packet.payload[0]);
    
    // Copy message data (excluding message type byte)
    if (packet.payload.size() > 1) {
        message.data.assign(packet.payload.begin() + 1, packet.payload.end());
    }
    
    // Parse specific message types
    switch (message.type) {
        case SSHMessageType::SSH_MSG_KEXINIT: {
            SSHKeyExchangeInit kex_init_msg;
            ParseResult status = parse_kex_init(packet.payload, kex_init_msg);
            if (status != ParseResult::Success) {
                return status;
            }
            message.kex_init = kex_init_msg;
            break;
        }
        
        case SSHMessageType::SSH_MSG_DISCONNECT: {
            if (message.data.size() >= 4) {
                size_t offset = 0;
                SSHDisconnectMessage disconnect_msg;
                disconnect_msg.reason_code = read_uint32(message.data, offset);
                disconnect_msg.description = read_string(message.data, offset);
                if (offset < message.data.size()) {
                    disconnect_msg.language_tag = read_string(message.data, offset);
                }
                message.disconnect = disconnect_msg;
                ssh_connection_.state = SSHConnectionState::DISCONNECTED;
            }
            break;
        }
        
        case SSHMessageType::SSH_MSG_SERVICE_REQUEST: {
            if (!message.data.empty()) {
                size_t offset = 0;
                SSHServiceMessage service_msg;
                service_msg.service_name = read_string(message.data, offset);
                message.service_request = service_msg;
            }
            break;
        }
        
        case SSHMessageType::SSH_MSG_SERVICE_ACCEPT: {
            if (!message.data.empty()) {
                size_t offset = 0;
                SSHServiceMessage service_msg;
                service_msg.service_name = read_string(message.data, offset);
                message.service_accept = service_msg;
            }
            break;
        }
        
        case SSHMessageType::SSH_MSG_NEWKEYS:
            ssh_connection_.key_exchange_complete = true;
            update_connection_state();
            break;
            
        case SSHMessageType::SSH_MSG_USERAUTH_SUCCESS:
            ssh_connection_.authentication_complete = true;
            update_connection_state();
            break;
            
        default:
            // For other message types, just store the raw data
            break;
    }
    
    ssh_connection_.messages.push_back(message);
    return ParseResult::Success;
}

ParseResult SSHParser::parse_kex_init(const std::vector<uint8_t>& payload, SSHKeyExchangeInit& kex_init) {
    if (payload.size() < 17) { // 1 byte msg type + 16 bytes cookie
        return ParseResult::InvalidFormat;
    }
    
    size_t offset = 1; // Skip message type
    
    // Read cookie (16 bytes)
    std::memcpy(kex_init.cookie.data(), payload.data() + offset, 16);
    offset += 16;
    
    try {
        // Read algorithm lists
        kex_init.kex_algorithms = parse_name_list(payload, offset);
        kex_init.server_host_key_algorithms = parse_name_list(payload, offset);
        kex_init.encryption_algorithms_client_to_server = parse_name_list(payload, offset);
        kex_init.encryption_algorithms_server_to_client = parse_name_list(payload, offset);
        kex_init.mac_algorithms_client_to_server = parse_name_list(payload, offset);
        kex_init.mac_algorithms_server_to_client = parse_name_list(payload, offset);
        kex_init.compression_algorithms_client_to_server = parse_name_list(payload, offset);
        kex_init.compression_algorithms_server_to_client = parse_name_list(payload, offset);
        kex_init.languages_client_to_server = parse_name_list(payload, offset);
        kex_init.languages_server_to_client = parse_name_list(payload, offset);
        
        // Read boolean and reserved field
        if (offset < payload.size()) {
            kex_init.first_kex_packet_follows = (read_uint8(payload, offset) != 0);
        }
        if (offset + 3 < payload.size()) {
            kex_init.reserved = read_uint32(payload, offset);
        }
    } catch (...) {
        return ParseResult::InvalidFormat;
    }
    
    return ParseResult::Success;
}

bool SSHParser::is_version_line_complete(const BufferView& buffer) const {
    std::string data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return data.find('\n') != std::string::npos;
}

bool SSHParser::validate_version_string(const std::string& version_str) const {
    if (version_str.length() < 4 || version_str.substr(0, 4) != "SSH-") {
        return false;
    }
    
    // Check for valid characters (printable ASCII)
    for (char c : version_str) {
        if (c < 32 || c > 126) {
            return false;
        }
    }
    
    return true;
}

bool SSHParser::validate_ssh_packet(const BufferView& buffer) const {
    if (buffer.size() == 0) {
        return false;
    }
    
    // If we're in version exchange, check for SSH version string
    if (ssh_connection_.state == SSHConnectionState::VERSION_EXCHANGE || 
        ssh_connection_.state == SSHConnectionState::UNKNOWN) {
        std::string data(reinterpret_cast<const char*>(buffer.data()), 
                        std::min(buffer.size(), size_t(255)));
        return data.find("SSH-") == 0;
    }
    
    // For binary packets, basic validation
    return buffer.size() >= 5;
}

std::vector<std::string> SSHParser::parse_name_list(const std::vector<uint8_t>& data, size_t& offset) const {
    std::vector<std::string> names;
    std::string name_list = read_string(data, offset);
    
    if (name_list.empty()) {
        return names;
    }
    
    std::istringstream iss(name_list);
    std::string name;
    
    while (std::getline(iss, name, ',')) {
        if (!name.empty()) {
            names.push_back(name);
        }
    }
    
    return names;
}

std::string SSHParser::read_string(const std::vector<uint8_t>& data, size_t& offset) const {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Not enough data for string length");
    }
    
    uint32_t length = read_uint32(data, offset);
    
    if (offset + length > data.size()) {
        throw std::runtime_error("Not enough data for string content");
    }
    
    std::string result(reinterpret_cast<const char*>(data.data() + offset), length);
    offset += length;
    
    return result;
}

uint32_t SSHParser::read_uint32(const std::vector<uint8_t>& data, size_t& offset) const {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Not enough data for uint32");
    }
    
    uint32_t value = (static_cast<uint32_t>(data[offset]) << 24) |
                    (static_cast<uint32_t>(data[offset + 1]) << 16) |
                    (static_cast<uint32_t>(data[offset + 2]) << 8) |
                    static_cast<uint32_t>(data[offset + 3]);
    
    offset += 4;
    return value;
}

uint8_t SSHParser::read_uint8(const std::vector<uint8_t>& data, size_t& offset) const {
    if (offset >= data.size()) {
        throw std::runtime_error("Not enough data for uint8");
    }
    
    return data[offset++];
}

bool SSHParser::is_connection_established() const {
    return ssh_connection_.state == SSHConnectionState::CONNECTION &&
           ssh_connection_.version_exchange_complete &&
           ssh_connection_.key_exchange_complete &&
           ssh_connection_.authentication_complete;
}

SSHVersion SSHParser::get_negotiated_version() const {
    if (ssh_connection_.version_exchange_complete) {
        // Use the lower version between client and server
        SSHVersion client_ver = ssh_connection_.client_version.version;
        SSHVersion server_ver = ssh_connection_.server_version.version;
        
        if (client_ver == SSHVersion::SSH_2_0 && server_ver == SSHVersion::SSH_2_0) {
            return SSHVersion::SSH_2_0;
        } else if (client_ver != SSHVersion::UNKNOWN && server_ver != SSHVersion::UNKNOWN) {
            return (client_ver < server_ver) ? client_ver : server_ver;
        }
    }
    return SSHVersion::UNKNOWN;
}

bool SSHParser::is_ssh2() const {
    SSHVersion version = get_negotiated_version();
    return version == SSHVersion::SSH_2_0 || version == SSHVersion::SSH_1_99;
}

bool SSHParser::is_ssh1() const {
    SSHVersion version = get_negotiated_version();
    return version == SSHVersion::SSH_1_0 || version == SSHVersion::SSH_1_3 || version == SSHVersion::SSH_1_5;
}

SSHMessage SSHParser::get_last_message() const {
    if (!ssh_connection_.messages.empty()) {
        return ssh_connection_.messages.back();
    }
    return SSHMessage();
}

std::string SSHParser::version_to_string(SSHVersion version) const {
    switch (version) {
        case SSHVersion::SSH_1_0: return "1.0";
        case SSHVersion::SSH_1_3: return "1.3";
        case SSHVersion::SSH_1_5: return "1.5";
        case SSHVersion::SSH_1_99: return "1.99";
        case SSHVersion::SSH_2_0: return "2.0";
        default: return "Unknown";
    }
}

SSHVersion SSHParser::string_to_version(const std::string& version_str) const {
    if (version_str == "1.0") return SSHVersion::SSH_1_0;
    if (version_str == "1.3") return SSHVersion::SSH_1_3;
    if (version_str == "1.5") return SSHVersion::SSH_1_5;
    if (version_str == "1.99") return SSHVersion::SSH_1_99;
    if (version_str == "2.0") return SSHVersion::SSH_2_0;
    return SSHVersion::UNKNOWN;
}

std::string SSHParser::message_type_to_string(SSHMessageType type) const {
    switch (type) {
        case SSHMessageType::SSH_MSG_DISCONNECT: return "SSH_MSG_DISCONNECT";
        case SSHMessageType::SSH_MSG_IGNORE: return "SSH_MSG_IGNORE";
        case SSHMessageType::SSH_MSG_UNIMPLEMENTED: return "SSH_MSG_UNIMPLEMENTED";
        case SSHMessageType::SSH_MSG_DEBUG: return "SSH_MSG_DEBUG";
        case SSHMessageType::SSH_MSG_SERVICE_REQUEST: return "SSH_MSG_SERVICE_REQUEST";
        case SSHMessageType::SSH_MSG_SERVICE_ACCEPT: return "SSH_MSG_SERVICE_ACCEPT";
        case SSHMessageType::SSH_MSG_KEXINIT: return "SSH_MSG_KEXINIT";
        case SSHMessageType::SSH_MSG_NEWKEYS: return "SSH_MSG_NEWKEYS";
        case SSHMessageType::SSH_MSG_KEXDH_INIT: return "SSH_MSG_KEXDH_INIT";
        case SSHMessageType::SSH_MSG_KEXDH_REPLY: return "SSH_MSG_KEXDH_REPLY";
        case SSHMessageType::SSH_MSG_USERAUTH_REQUEST: return "SSH_MSG_USERAUTH_REQUEST";
        case SSHMessageType::SSH_MSG_USERAUTH_FAILURE: return "SSH_MSG_USERAUTH_FAILURE";
        case SSHMessageType::SSH_MSG_USERAUTH_SUCCESS: return "SSH_MSG_USERAUTH_SUCCESS";
        case SSHMessageType::SSH_MSG_USERAUTH_BANNER: return "SSH_MSG_USERAUTH_BANNER";
        case SSHMessageType::SSH_MSG_GLOBAL_REQUEST: return "SSH_MSG_GLOBAL_REQUEST";
        case SSHMessageType::SSH_MSG_REQUEST_SUCCESS: return "SSH_MSG_REQUEST_SUCCESS";
        case SSHMessageType::SSH_MSG_REQUEST_FAILURE: return "SSH_MSG_REQUEST_FAILURE";
        case SSHMessageType::SSH_MSG_CHANNEL_OPEN: return "SSH_MSG_CHANNEL_OPEN";
        case SSHMessageType::SSH_MSG_CHANNEL_OPEN_CONFIRMATION: return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
        case SSHMessageType::SSH_MSG_CHANNEL_OPEN_FAILURE: return "SSH_MSG_CHANNEL_OPEN_FAILURE";
        case SSHMessageType::SSH_MSG_CHANNEL_WINDOW_ADJUST: return "SSH_MSG_CHANNEL_WINDOW_ADJUST";
        case SSHMessageType::SSH_MSG_CHANNEL_DATA: return "SSH_MSG_CHANNEL_DATA";
        case SSHMessageType::SSH_MSG_CHANNEL_EXTENDED_DATA: return "SSH_MSG_CHANNEL_EXTENDED_DATA";
        case SSHMessageType::SSH_MSG_CHANNEL_EOF: return "SSH_MSG_CHANNEL_EOF";
        case SSHMessageType::SSH_MSG_CHANNEL_CLOSE: return "SSH_MSG_CHANNEL_CLOSE";
        case SSHMessageType::SSH_MSG_CHANNEL_REQUEST: return "SSH_MSG_CHANNEL_REQUEST";
        case SSHMessageType::SSH_MSG_CHANNEL_SUCCESS: return "SSH_MSG_CHANNEL_SUCCESS";
        case SSHMessageType::SSH_MSG_CHANNEL_FAILURE: return "SSH_MSG_CHANNEL_FAILURE";
        default: return "UNKNOWN_MESSAGE";
    }
}

std::string SSHParser::disconnect_reason_to_string(SSHDisconnectReason reason) const {
    switch (reason) {
        case SSHDisconnectReason::SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
            return "Host not allowed to connect";
        case SSHDisconnectReason::SSH_DISCONNECT_PROTOCOL_ERROR:
            return "Protocol error";
        case SSHDisconnectReason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
            return "Key exchange failed";
        case SSHDisconnectReason::SSH_DISCONNECT_RESERVED:
            return "Reserved";
        case SSHDisconnectReason::SSH_DISCONNECT_MAC_ERROR:
            return "MAC error";
        case SSHDisconnectReason::SSH_DISCONNECT_COMPRESSION_ERROR:
            return "Compression error";
        case SSHDisconnectReason::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
            return "Service not available";
        case SSHDisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
            return "Protocol version not supported";
        case SSHDisconnectReason::SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
            return "Host key not verifiable";
        case SSHDisconnectReason::SSH_DISCONNECT_CONNECTION_LOST:
            return "Connection lost";
        case SSHDisconnectReason::SSH_DISCONNECT_BY_APPLICATION:
            return "Disconnected by application";
        case SSHDisconnectReason::SSH_DISCONNECT_TOO_MANY_CONNECTIONS:
            return "Too many connections";
        case SSHDisconnectReason::SSH_DISCONNECT_AUTH_CANCELLED_BY_USER:
            return "Authentication cancelled by user";
        case SSHDisconnectReason::SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
            return "No more authentication methods available";
        case SSHDisconnectReason::SSH_DISCONNECT_ILLEGAL_USER_NAME:
            return "Illegal user name";
        default:
            return "Unknown disconnect reason";
    }
}

void SSHParser::reset() noexcept {
    ssh_connection_ = SSHConnection();
    ssh_connection_.state = SSHConnectionState::VERSION_EXCHANGE;
}

void SSHParser::update_connection_state() {
    if (ssh_connection_.state == SSHConnectionState::DISCONNECTED) {
        return;
    }
    
    if (!ssh_connection_.version_exchange_complete) {
        ssh_connection_.state = SSHConnectionState::VERSION_EXCHANGE;
    } else if (!ssh_connection_.key_exchange_complete) {
        ssh_connection_.state = SSHConnectionState::KEY_EXCHANGE;
    } else if (!ssh_connection_.authentication_complete) {
        ssh_connection_.state = SSHConnectionState::AUTHENTICATION;
    } else {
        ssh_connection_.state = SSHConnectionState::CONNECTION;
    }
}

} // namespace protocol_parser::parsers