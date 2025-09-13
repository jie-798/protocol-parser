#include "parsers/application/websocket_parser.hpp"
#include <algorithm>
#include <sstream>
#include <string>
#include <cstring>
#include <regex>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// 简化的SHA1和Base64实现（生产环境应使用标准库）
namespace {
    // Base64编码表
    const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string base64_encode(const std::vector<uint8_t>& data) {
        std::string result;
        int val = 0, valb = -6;
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        while (result.size() % 4) {
            result.push_back('=');
        }
        return result;
    }

    // 简化的SHA1实现（仅用于演示）
    std::vector<uint8_t> simple_sha1(const std::string& input) {
        // 这是一个简化版本，生产环境应使用正确的SHA1实现
        std::vector<uint8_t> hash(20, 0);
        std::hash<std::string> hasher;
        size_t h = hasher(input);
        memcpy(hash.data(), &h, std::min(sizeof(h), hash.size()));
        return hash;
    }
}

namespace ProtocolParser::Parsers::Application {

WebSocketParser::WebSocketParser() : BaseParser() {
    // WebSocket解析器初始化
}

ParseResult WebSocketParser::parse(ParseContext& context) noexcept {
    const auto& buffer = context.buffer;
    
    if (buffer.size() < 2) {
        return ParseResult::NeedMoreData;
    }

    try {
        WebSocketMessage message;
        
        // 检测是握手还是帧数据
        if (is_websocket_handshake(buffer)) {
            message.is_handshake = true;
            auto result = parse_handshake(buffer, message.handshake);
            if (result == ParseResult::Success) {
                collect_statistics(message);
            }
            return result;
        } else if (is_websocket_frame(buffer)) {
            message.is_handshake = false;
            auto result = parse_frame(buffer, message.frame);
            if (result == ParseResult::Success) {
                collect_statistics(message);
            }
            return result;
        }
        
        return ParseResult::InvalidFormat;
        
    } catch (const std::exception&) {
        return ParseResult::InternalError;
    }
}

const ProtocolInfo& WebSocketParser::get_protocol_info() const noexcept {
    static const ProtocolInfo info{
        "WebSocket",    // name
        0x0800,         // type (IP)
        2,              // header_size (minimum frame header)
        2,              // min_packet_size
        MAX_FRAME_SIZE  // max_packet_size
    };
    return info;
}

bool WebSocketParser::can_parse(const BufferView& buffer) const noexcept {
    return is_websocket_handshake(buffer) || is_websocket_frame(buffer);
}

void WebSocketParser::reset() noexcept {
    // 重置解析器状态
}

bool WebSocketParser::is_websocket_handshake(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 16) {
        return false;
    }
    
    std::string data(reinterpret_cast<const char*>(buffer.data()), 
                    std::min(buffer.size(), static_cast<size_t>(200)));
    
    // 检查HTTP升级请求特征
    return (data.find("GET ") == 0 || data.find("HTTP/1.1 101") == 0) &&
           (data.find("Upgrade: websocket") != std::string::npos ||
            data.find("upgrade: websocket") != std::string::npos ||
            data.find("Connection: Upgrade") != std::string::npos ||
            data.find("connection: upgrade") != std::string::npos);
}

bool WebSocketParser::is_websocket_frame(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 2) {
        return false;
    }
    
    uint8_t first_byte = buffer[0];
    uint8_t second_byte = buffer[1];
    
    // 检查操作码是否有效
    uint8_t opcode = first_byte & 0x0F;
    if (opcode > 0x2 && opcode < 0x8) {
        return false; // 保留操作码
    }
    if (opcode > 0xA) {
        return false; // 无效操作码
    }
    
    // 检查RSV位（在没有扩展的情况下应该为0）
    if ((first_byte & 0x70) != 0) {
        return false;
    }
    
    // 控制帧必须设置FIN位
    if (is_control_frame(static_cast<WebSocketOpcode>(opcode)) && !(first_byte & 0x80)) {
        return false;
    }
    
    return true;
}

ParseResult WebSocketParser::parse_handshake(const protocol_parser::core::BufferView& buffer, 
                                            WebSocketHandshake& handshake) const {
    std::string data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    
    // 查找HTTP头部结束标记
    size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return ParseResult::NeedMoreData;
    }
    
    std::istringstream stream(data.substr(0, header_end));
    std::string line;
    bool first_line = true;
    
    while (std::getline(stream, line)) {
        // 移除回车符
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (first_line) {
            auto result = parse_request_line(line, handshake);
            if (result != ParseResult::Success) {
                return result;
            }
            first_line = false;
        } else if (!line.empty()) {
            auto result = parse_header_line(line, handshake);
            if (result != ParseResult::Success) {
                return result;
            }
        }
    }
    
    // 验证握手
    if (!validate_handshake(handshake)) {
        return ParseResult::InvalidFormat;
    }
    
    handshake.is_valid = true;
    return ParseResult::Success;
}

ParseResult WebSocketParser::parse_frame(const protocol_parser::core::BufferView& buffer, 
                                        WebSocketFrame& frame) const {
    if (buffer.size() < 2) {
        return ParseResult::NeedMoreData;
    }
    
    // 解析帧头
    auto result = parse_frame_header(buffer, frame.header);
    if (result != ParseResult::Success) {
        return result;
    }
    
    // 检查数据是否足够
    size_t total_length = frame.header.header_length + frame.header.payload_length;
    if (buffer.size() < total_length) {
        return ParseResult::NeedMoreData;
    }
    
    // 提取载荷数据
    if (frame.header.payload_length > 0) {
        frame.payload.resize(frame.header.payload_length);
        memcpy(frame.payload.data(), 
               buffer.data() + frame.header.header_length, 
               frame.header.payload_length);
        
        // 应用掩码（如果存在）
        if (frame.header.mask) {
            apply_mask(frame.payload, frame.header.masking_key);
        }
    }
    
    // 处理特定帧类型
    switch (frame.header.opcode) {
        case WebSocketOpcode::TEXT:
            if (!is_valid_utf8(frame.payload)) {
                return ParseResult::InvalidFormat;
            }
            frame.text_data = std::string(frame.payload.begin(), frame.payload.end());
            break;
            
        case WebSocketOpcode::CLOSE:
            if (frame.payload.size() >= 2) {
                frame.close_code = static_cast<WebSocketCloseCode>(
                    ntohs(*reinterpret_cast<const uint16_t*>(frame.payload.data())));
                if (frame.payload.size() > 2) {
                    frame.close_reason = std::string(frame.payload.begin() + 2, frame.payload.end());
                    if (!is_valid_utf8(std::vector<uint8_t>(frame.payload.begin() + 2, frame.payload.end()))) {
                        return ParseResult::InvalidFormat;
                    }
                }
            }
            break;
            
        default:
            break;
    }
    
    // 验证帧
    if (!validate_frame(frame)) {
        return ParseResult::InvalidFormat;
    }
    
    frame.is_valid = true;
    return ParseResult::Success;
}

std::string WebSocketParser::calculate_accept_key(const std::string& key) const {
    std::string combined = key + WEBSOCKET_GUID;
    auto hash = simple_sha1(combined);
    return base64_encode(hash);
}

void WebSocketParser::apply_mask(std::vector<uint8_t>& data, uint32_t mask) const {
    uint8_t mask_bytes[4];
    mask_bytes[0] = (mask >> 24) & 0xFF;
    mask_bytes[1] = (mask >> 16) & 0xFF;
    mask_bytes[2] = (mask >> 8) & 0xFF;
    mask_bytes[3] = mask & 0xFF;
    
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= mask_bytes[i % 4];
    }
}

bool WebSocketParser::is_valid_utf8(const std::vector<uint8_t>& data) const {
    // 简化的UTF-8验证
    size_t i = 0;
    while (i < data.size()) {
        uint8_t byte = data[i];
        
        if (byte < 0x80) {
            // ASCII字符
            i++;
        } else if ((byte & 0xE0) == 0xC0) {
            // 2字节序列
            if (i + 1 >= data.size() || (data[i + 1] & 0xC0) != 0x80) {
                return false;
            }
            i += 2;
        } else if ((byte & 0xF0) == 0xE0) {
            // 3字节序列
            if (i + 2 >= data.size() || 
                (data[i + 1] & 0xC0) != 0x80 || 
                (data[i + 2] & 0xC0) != 0x80) {
                return false;
            }
            i += 3;
        } else if ((byte & 0xF8) == 0xF0) {
            // 4字节序列
            if (i + 3 >= data.size() || 
                (data[i + 1] & 0xC0) != 0x80 || 
                (data[i + 2] & 0xC0) != 0x80 || 
                (data[i + 3] & 0xC0) != 0x80) {
                return false;
            }
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

std::vector<WebSocketExtension> WebSocketParser::parse_extensions(const std::string& extension_header) const {
    std::vector<WebSocketExtension> extensions;
    
    std::istringstream stream(extension_header);
    std::string extension_str;
    
    while (std::getline(stream, extension_str, ',')) {
        // 移除前后空格
        extension_str.erase(0, extension_str.find_first_not_of(" \t"));
        extension_str.erase(extension_str.find_last_not_of(" \t") + 1);
        
        WebSocketExtension ext;
        
        size_t semicolon_pos = extension_str.find(';');
        if (semicolon_pos == std::string::npos) {
            ext.name = extension_str;
        } else {
            ext.name = extension_str.substr(0, semicolon_pos);
            
            // 解析参数
            std::string params = extension_str.substr(semicolon_pos + 1);
            std::istringstream param_stream(params);
            std::string param;
            
            while (std::getline(param_stream, param, ';')) {
                param.erase(0, param.find_first_not_of(" \t"));
                param.erase(param.find_last_not_of(" \t") + 1);
                
                size_t eq_pos = param.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = param.substr(0, eq_pos);
                    std::string value = param.substr(eq_pos + 1);
                    ext.parameters[key] = value;
                } else {
                    ext.parameters[param] = "";
                }
            }
        }
        
        extensions.push_back(ext);
    }
    
    return extensions;
}

bool WebSocketParser::validate_frame(const WebSocketFrame& frame) const {
    // 检查控制帧约束
    if (is_control_frame(frame.header.opcode)) {
        // 控制帧不能分片
        if (!frame.header.fin) {
            return false;
        }
        
        // 控制帧载荷不能超过125字节
        if (frame.header.payload_length > 125) {
            return false;
        }
    }
    
    // 检查载荷长度限制
    if (frame.header.payload_length > MAX_FRAME_SIZE) {
        return false;
    }
    
    // 检查关闭帧
    if (frame.header.opcode == WebSocketOpcode::CLOSE) {
        if (frame.payload.size() == 1) {
            return false; // 关闭码必须是2字节
        }
        if (frame.payload.size() >= 2) {
            uint16_t code = ntohs(*reinterpret_cast<const uint16_t*>(frame.payload.data()));
            // 检查关闭码是否有效
            if (code < 1000 || (code >= 1004 && code <= 1006) || 
                (code >= 1012 && code <= 1014) || code == 1100) {
                return false;
            }
        }
    }
    
    return true;
}

std::string WebSocketParser::opcode_to_string(WebSocketOpcode opcode) const {
    switch (opcode) {
        case WebSocketOpcode::CONTINUATION: return "CONTINUATION";
        case WebSocketOpcode::TEXT: return "TEXT";
        case WebSocketOpcode::BINARY: return "BINARY";
        case WebSocketOpcode::CLOSE: return "CLOSE";
        case WebSocketOpcode::PING: return "PING";
        case WebSocketOpcode::PONG: return "PONG";
        default: return "RESERVED";
    }
}

std::string WebSocketParser::state_to_string(WebSocketState state) const {
    switch (state) {
        case WebSocketState::HANDSHAKE: return "HANDSHAKE";
        case WebSocketState::CONNECTED: return "CONNECTED";
        case WebSocketState::CLOSING: return "CLOSING";
        case WebSocketState::CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

std::string WebSocketParser::close_code_to_string(WebSocketCloseCode code) const {
    switch (code) {
        case WebSocketCloseCode::NORMAL_CLOSURE: return "NORMAL_CLOSURE";
        case WebSocketCloseCode::GOING_AWAY: return "GOING_AWAY";
        case WebSocketCloseCode::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
        case WebSocketCloseCode::UNSUPPORTED_DATA: return "UNSUPPORTED_DATA";
        case WebSocketCloseCode::NO_STATUS_RECEIVED: return "NO_STATUS_RECEIVED";
        case WebSocketCloseCode::ABNORMAL_CLOSURE: return "ABNORMAL_CLOSURE";
        case WebSocketCloseCode::INVALID_FRAME_PAYLOAD_DATA: return "INVALID_FRAME_PAYLOAD_DATA";
        case WebSocketCloseCode::POLICY_VIOLATION: return "POLICY_VIOLATION";
        case WebSocketCloseCode::MESSAGE_TOO_BIG: return "MESSAGE_TOO_BIG";
        case WebSocketCloseCode::MANDATORY_EXTENSION: return "MANDATORY_EXTENSION";
        case WebSocketCloseCode::INTERNAL_SERVER_ERROR: return "INTERNAL_SERVER_ERROR";
        case WebSocketCloseCode::TLS_HANDSHAKE: return "TLS_HANDSHAKE";
        default: return "UNKNOWN";
    }
}

ParseResult WebSocketParser::parse_request_line(const std::string& line, 
                                               WebSocketHandshake& handshake) const {
    std::istringstream stream(line);
    if (!(stream >> handshake.method >> handshake.uri >> handshake.version)) {
        return ParseResult::InvalidFormat;
    }
    
    // 检查是否为WebSocket握手请求
    if (handshake.method == "GET" || line.find("HTTP/1.1 101") == 0) {
        return ParseResult::Success;
    }
    
    return ParseResult::InvalidFormat;
}

ParseResult WebSocketParser::parse_header_line(const std::string& line, 
                                              WebSocketHandshake& handshake) const {
    size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos) {
        return ParseResult::InvalidFormat;
    }
    
    std::string key = line.substr(0, colon_pos);
    std::string value = line.substr(colon_pos + 1);
    
    // 移除前后空格
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);
    
    // 转换为小写进行比较
    std::string lower_key = key;
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
    
    handshake.headers[key] = value;
    
    // 处理特殊头部
    if (lower_key == "upgrade") {
        std::string lower_value = value;
        std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
        if (lower_value == "websocket") {
            handshake.is_upgrade = true;
        }
    } else if (lower_key == "sec-websocket-key") {
        handshake.websocket_key = value;
    } else if (lower_key == "sec-websocket-accept") {
        handshake.websocket_accept = value;
    } else if (lower_key == "sec-websocket-protocol") {
        std::istringstream stream(value);
        std::string protocol;
        while (std::getline(stream, protocol, ',')) {
            protocol.erase(0, protocol.find_first_not_of(" \t"));
            protocol.erase(protocol.find_last_not_of(" \t") + 1);
            handshake.protocols.push_back(protocol);
        }
    } else if (lower_key == "sec-websocket-extensions") {
        auto extensions = parse_extensions(value);
        for (const auto& ext : extensions) {
            handshake.extensions.push_back(ext.name);
        }
    }
    
    return ParseResult::Success;
}

ParseResult WebSocketParser::parse_frame_header(const protocol_parser::core::BufferView& buffer, 
                                               WebSocketFrameHeader& header) const {
    if (buffer.size() < 2) {
        return ParseResult::NeedMoreData;
    }
    
    size_t offset = 0;
    
    // 解析第一个字节
    uint8_t first_byte = buffer[offset++];
    header.fin = (first_byte & 0x80) != 0;
    header.rsv1 = (first_byte & 0x40) != 0;
    header.rsv2 = (first_byte & 0x20) != 0;
    header.rsv3 = (first_byte & 0x10) != 0;
    header.opcode = static_cast<WebSocketOpcode>(first_byte & 0x0F);
    
    // 解析第二个字节
    uint8_t second_byte = buffer[offset++];
    header.mask = (second_byte & 0x80) != 0;
    uint8_t payload_len = second_byte & 0x7F;
    
    // 解析载荷长度
    size_t length_bytes = parse_payload_length(buffer, offset, header.payload_length);
    if (length_bytes == 0) {
        return ParseResult::NeedMoreData;
    }
    offset += length_bytes;
    
    // 如果有掩码，读取掩码键
    if (header.mask) {
        if (offset + 4 > buffer.size()) {
            return ParseResult::NeedMoreData;
        }
        header.masking_key = *reinterpret_cast<const uint32_t*>(buffer.data() + offset);
        offset += 4;
    }
    
    header.header_length = offset;
    return ParseResult::Success;
}

size_t WebSocketParser::parse_payload_length(const protocol_parser::core::BufferView& buffer, 
                                            size_t offset, uint64_t& length) const {
    if (offset >= buffer.size()) {
        return 0;
    }
    
    uint8_t initial_length = buffer[offset - 1] & 0x7F;
    
    if (initial_length < 126) {
        length = initial_length;
        return 0;
    } else if (initial_length == 126) {
        if (offset + 2 > buffer.size()) {
            return 0;
        }
        length = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        return 2;
    } else { // initial_length == 127
        if (offset + 8 > buffer.size()) {
            return 0;
        }
#ifndef be64toh
#define be64toh(x) _byteswap_uint64(x)
#endif
        length = be64toh(*reinterpret_cast<const uint64_t*>(buffer.data() + offset));
        return 8;
    }
}

bool WebSocketParser::validate_handshake(const WebSocketHandshake& handshake) const {
    // 检查必要的头部
    if (!handshake.is_upgrade) {
        return false;
    }
    
    auto it = handshake.headers.find("Connection");
    if (it == handshake.headers.end()) {
        return false;
    }
    
    std::string connection = it->second;
    std::transform(connection.begin(), connection.end(), connection.begin(), ::tolower);
    if (connection.find("upgrade") == std::string::npos) {
        return false;
    }
    
    // 检查WebSocket版本
    it = handshake.headers.find("Sec-WebSocket-Version");
    if (it != handshake.headers.end()) {
        try {
            int version = std::stoi(it->second);
            if (version != WEBSOCKET_VERSION) {
                return false;
            }
        } catch (...) {
            return false;
        }
    }
    
    return true;
}

void WebSocketParser::collect_statistics(const WebSocketMessage& message) const {
    // 统计握手和帧信息
    if (message.is_handshake) {
        // 统计握手成功率
    } else {
        // 统计帧类型分布
        auto opcode_str = opcode_to_string(message.frame.header.opcode);
        
        // 统计载荷大小分布
        // 统计QoS相关指标
    }
}

} // namespace ProtocolParser::Parsers::Application