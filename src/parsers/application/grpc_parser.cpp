#include "parsers/application/grpc_parser.hpp"
#include <algorithm>
#include <sstream>
#include <string>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#ifndef be64toh
#define be64toh(x) _byteswap_uint64(x)
#endif
#else
#include <arpa/inet.h>
#endif

namespace ProtocolParser::Parsers::Application {

GRPCParser::GRPCParser() : BaseParser() {
    // 初始化gRPC/HTTP2签名模式
    signatures_ = {
        {0x50, 0xFF, "HTTP/2 PRI"},
        {0x00, 0xFF, "HTTP/2 DATA Frame"},
        {0x01, 0xFF, "HTTP/2 HEADERS Frame"},
        {0x04, 0xFF, "HTTP/2 SETTINGS Frame"},
        {0x06, 0xFF, "HTTP/2 PING Frame"},
        {0x08, 0xFF, "HTTP/2 WINDOW_UPDATE Frame"}
    };
}

ParseResult GRPCParser::parse(const ParseContext& context) {
    const auto& buffer = context.buffer;
    
    if (buffer.size() < 9) { // HTTP/2最小帧大小
        return ParseResult::INSUFFICIENT_DATA;
    }

    try {
        GRPCMessage message;
        
        // 检测HTTP/2连接前导
        if (is_http2_preface(buffer)) {
            return ParseResult::SUCCESS; // 连接前导解析成功
        }
        
        // 检测是否为gRPC流量
        if (!is_grpc_traffic(buffer)) {
            return ParseResult::INVALID_FORMAT;
        }
        
        // 解析HTTP/2帧
        auto result = parse_http2_frame(buffer, message);
        if (result == ParseResult::SUCCESS) {
            collect_metrics(message);
        }
        
        return result;
        
    } catch (const std::exception&) {
        return ParseResult::PARSING_ERROR;
    }
}

std::string GRPCParser::get_info() const {
    return "gRPC Protocol Parser - HTTP/2 based RPC framework with Protocol Buffers support";
}

bool GRPCParser::is_grpc_traffic(const ProtocolParser::Core::BufferView& buffer) const {
    if (buffer.size() < 9) {
        return false;
    }
    
    // 检查HTTP/2帧头格式
    uint32_t length = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
    uint8_t type = buffer[3];
    uint8_t flags = buffer[4];
    uint32_t stream_id = ntohl(*reinterpret_cast<const uint32_t*>(buffer.data() + 5)) & 0x7FFFFFFF;
    
    // 基本有效性检查
    if (length > MAX_FRAME_SIZE) {
        return false;
    }
    
    // 检查帧类型是否有效
    if (type > static_cast<uint8_t>(HTTP2FrameType::CONTINUATION)) {
        return false;
    }
    
    // 流ID 0只能用于连接级别的帧
    if (stream_id == 0 && type != static_cast<uint8_t>(HTTP2FrameType::SETTINGS) &&
        type != static_cast<uint8_t>(HTTP2FrameType::PING) &&
        type != static_cast<uint8_t>(HTTP2FrameType::GOAWAY) &&
        type != static_cast<uint8_t>(HTTP2FrameType::WINDOW_UPDATE)) {
        return false;
    }
    
    return true;
}

bool GRPCParser::is_http2_preface(const ProtocolParser::Core::BufferView& buffer) const {
    const size_t preface_len = strlen(HTTP2_PREFACE);
    if (buffer.size() < preface_len) {
        return false;
    }
    
    return memcmp(buffer.data(), HTTP2_PREFACE, preface_len) == 0;
}

ParseResult GRPCParser::parse_http2_frame(const ProtocolParser::Core::BufferView& buffer, 
                                         GRPCMessage& message) const {
    // 解析帧头部
    auto result = parse_frame_header(buffer, message.frame_header);
    if (result != ParseResult::SUCCESS) {
        return result;
    }
    
    // 检查数据是否足够
    size_t total_length = 9 + message.frame_header.length;
    if (buffer.size() < total_length) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    message.total_length = total_length;
    
    // 根据帧类型进行解析
    ProtocolParser::Core::BufferView frame_payload(
        buffer.data() + 9, 
        message.frame_header.length
    );
    
    switch (message.frame_header.type) {
        case HTTP2FrameType::HEADERS:
            return parse_headers_frame(frame_payload, message);
        case HTTP2FrameType::DATA:
            return parse_data_frame(frame_payload, message);
        case HTTP2FrameType::SETTINGS:
        case HTTP2FrameType::PING:
        case HTTP2FrameType::WINDOW_UPDATE:
        case HTTP2FrameType::RST_STREAM:
        case HTTP2FrameType::GOAWAY:
            // 控制帧，解析成功但不需要进一步处理gRPC消息
            message.is_valid = true;
            return ParseResult::SUCCESS;
        default:
            return ParseResult::SUCCESS; // 其他帧类型暂时跳过
    }
}

ParseResult GRPCParser::parse_grpc_message(const ProtocolParser::Core::BufferView& buffer, 
                                          GRPCMessage& message) const {
    if (buffer.size() < 5) { // gRPC消息头最小长度
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    // 解析gRPC消息头部
    auto result = parse_message_header(buffer, message.message_header);
    if (result != ParseResult::SUCCESS) {
        return result;
    }
    
    // 检查载荷数据是否足够
    if (buffer.size() < 5 + message.message_header.length) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    // 提取载荷数据
    if (message.message_header.length > 0) {
        message.payload.resize(message.message_header.length);
        memcpy(message.payload.data(), buffer.data() + 5, message.message_header.length);
        
        // 检测是否为Protocol Buffers消息
        if (is_protobuf_message(message.payload)) {
            message.is_valid = true;
        }
    }
    
    return ParseResult::SUCCESS;
}

ParseResult GRPCParser::parse_headers_frame(const ProtocolParser::Core::BufferView& buffer, 
                                           GRPCMessage& message) const {
    if (buffer.empty()) {
        return ParseResult::SUCCESS;
    }
    
    size_t offset = 0;
    
    // 如果有优先级信息，跳过5字节
    if (message.frame_header.flags & 0x20) { // PRIORITY flag
        if (buffer.size() < 5) {
            return ParseResult::INSUFFICIENT_DATA;
        }
        offset = 5;
    }
    
    // 如果有填充，读取填充长度
    if (message.frame_header.flags & 0x08) { // PADDED flag
        if (offset >= buffer.size()) {
            return ParseResult::INSUFFICIENT_DATA;
        }
        uint8_t pad_length = buffer[offset++];
        if (offset + pad_length > buffer.size()) {
            return ParseResult::INSUFFICIENT_DATA;
        }
    }
    
    // 提取头部块片段
    std::vector<uint8_t> header_block(
        buffer.data() + offset, 
        buffer.data() + buffer.size()
    );
    
    // 简化的HPACK解码
    auto result = simple_hpack_decode(header_block, message.call_info.request_headers);
    if (result != ParseResult::SUCCESS) {
        return result;
    }
    
    // 提取服务和方法信息
    if (!message.call_info.request_headers.path.empty()) {
        extract_service_method(message.call_info.request_headers.path,
                              message.call_info.service,
                              message.call_info.method);
    }
    
    // 检测流类型
    message.call_info.stream_type = detect_stream_type(message.call_info.request_headers);
    
    // 检查是否为gRPC请求
    if (message.call_info.request_headers.content_type.find(GRPC_CONTENT_TYPE) != std::string::npos) {
        message.is_valid = true;
        message.type = GRPCMessageType::REQUEST;
    }
    
    // 设置流结束标志
    message.is_end_stream = (message.frame_header.flags & 0x01) != 0;
    message.is_end_headers = (message.frame_header.flags & 0x04) != 0;
    
    return ParseResult::SUCCESS;
}

ParseResult GRPCParser::parse_data_frame(const ProtocolParser::Core::BufferView& buffer, 
                                        GRPCMessage& message) const {
    if (buffer.empty()) {
        return ParseResult::SUCCESS;
    }
    
    size_t offset = 0;
    
    // 如果有填充，读取填充长度
    if (message.frame_header.flags & 0x08) { // PADDED flag
        if (buffer.size() < 1) {
            return ParseResult::INSUFFICIENT_DATA;
        }
        uint8_t pad_length = buffer[offset++];
        if (offset + pad_length > buffer.size()) {
            return ParseResult::INSUFFICIENT_DATA;
        }
    }
    
    // 提取数据载荷
    size_t data_length = buffer.size() - offset;
    if (data_length > 0) {
        ProtocolParser::Core::BufferView data_buffer(buffer.data() + offset, data_length);
        
        // 尝试解析gRPC消息
        auto result = parse_grpc_message(data_buffer, message);
        if (result == ParseResult::SUCCESS && message.is_valid) {
            message.type = (message.frame_header.stream_id % 2 == 1) ? 
                          GRPCMessageType::REQUEST : GRPCMessageType::RESPONSE;
        }
    }
    
    // 设置流结束标志
    message.is_end_stream = (message.frame_header.flags & 0x01) != 0;
    
    return ParseResult::SUCCESS;
}

ParseResult GRPCParser::parse_message_header(const ProtocolParser::Core::BufferView& buffer, 
                                            GRPCMessageHeader& header) const {
    if (buffer.size() < 5) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    // 第一个字节包含压缩标志
    uint8_t flags = buffer[0];
    header.compressed = (flags & 0x01) != 0;
    
    // 接下来4字节是消息长度（大端序）
    header.length = ntohl(*reinterpret_cast<const uint32_t*>(buffer.data() + 1));
    
    // 检测压缩类型（如果压缩）
    if (header.compressed && buffer.size() > 5) {
        std::vector<uint8_t> sample(buffer.data() + 5, 
                                   buffer.data() + std::min(buffer.size(), static_cast<size_t>(5 + 16)));
        header.compression = detect_compression(sample);
    }
    
    return ParseResult::SUCCESS;
}

GRPCCompression GRPCParser::detect_compression(const std::vector<uint8_t>& data) const {
    if (data.size() < 3) {
        return GRPCCompression::NONE;
    }
    
    // GZIP魔术数字
    if (data[0] == 0x1F && data[1] == 0x8B) {
        return GRPCCompression::GZIP;
    }
    
    // DEFLATE检测
    if ((data[0] & 0x0F) == 0x08 && (data[0] & 0xF0) <= 0x70) {
        return GRPCCompression::DEFLATE;
    }
    
    // Snappy魔术数字（流格式）
    if (data.size() >= 6 && data[0] == 0xFF && data[1] == 0x06 &&
        data[2] == 0x00 && data[3] == 0x00 && data[4] == 0x73 && data[5] == 0x4E) {
        return GRPCCompression::SNAPPY;
    }
    
    // LZ4魔术数字
    if (data.size() >= 4 && data[0] == 0x04 && data[1] == 0x22 &&
        data[2] == 0x4D && data[3] == 0x18) {
        return GRPCCompression::LZ4;
    }
    
    return GRPCCompression::NONE;
}

bool GRPCParser::is_protobuf_message(const std::vector<uint8_t>& data) const {
    if (data.empty()) {
        return false;
    }
    
    // Protocol Buffers使用varint编码
    // 检查第一个字节是否为有效的字段标识符
    uint8_t first_byte = data[0];
    
    // 字段号不能为0，且wire type必须有效
    uint32_t field_number = first_byte >> 3;
    uint32_t wire_type = first_byte & 0x07;
    
    if (field_number == 0 || wire_type > 5) {
        return false;
    }
    
    // 简单启发式：检查是否包含典型的protobuf模式
    // 这是一个简化的检测，实际应该更复杂
    return true;
}

bool GRPCParser::extract_service_method(const std::string& path, 
                                       std::string& service, 
                                       std::string& method) const {
    // gRPC路径格式: /package.Service/Method
    if (path.empty() || path[0] != '/') {
        return false;
    }
    
    size_t slash_pos = path.find('/', 1);
    if (slash_pos == std::string::npos) {
        return false;
    }
    
    std::string service_path = path.substr(1, slash_pos - 1);
    method = path.substr(slash_pos + 1);
    
    // 提取服务名（去除包名）
    size_t dot_pos = service_path.find_last_of('.');
    if (dot_pos != std::string::npos) {
        service = service_path.substr(dot_pos + 1);
    } else {
        service = service_path;
    }
    
    return !service.empty() && !method.empty();
}

bool GRPCParser::validate_grpc_message(const GRPCMessage& message) const {
    // 基本验证
    if (!message.is_valid) {
        return false;
    }
    
    // 检查帧头部
    if (message.frame_header.length > MAX_FRAME_SIZE) {
        return false;
    }
    
    // 检查流ID
    if (message.frame_header.stream_id == 0 && 
        (message.frame_header.type == HTTP2FrameType::HEADERS ||
         message.frame_header.type == HTTP2FrameType::DATA)) {
        return false;
    }
    
    // 检查gRPC消息长度
    if (message.message_header.length > message.frame_header.length) {
        return false;
    }
    
    return true;
}

std::string GRPCParser::frame_type_to_string(HTTP2FrameType type) const {
    switch (type) {
        case HTTP2FrameType::DATA: return "DATA";
        case HTTP2FrameType::HEADERS: return "HEADERS";
        case HTTP2FrameType::PRIORITY: return "PRIORITY";
        case HTTP2FrameType::RST_STREAM: return "RST_STREAM";
        case HTTP2FrameType::SETTINGS: return "SETTINGS";
        case HTTP2FrameType::PUSH_PROMISE: return "PUSH_PROMISE";
        case HTTP2FrameType::PING: return "PING";
        case HTTP2FrameType::GOAWAY: return "GOAWAY";
        case HTTP2FrameType::WINDOW_UPDATE: return "WINDOW_UPDATE";
        case HTTP2FrameType::CONTINUATION: return "CONTINUATION";
        default: return "UNKNOWN";
    }
}

std::string GRPCParser::status_code_to_string(GRPCStatusCode code) const {
    switch (code) {
        case GRPCStatusCode::OK: return "OK";
        case GRPCStatusCode::CANCELLED: return "CANCELLED";
        case GRPCStatusCode::UNKNOWN: return "UNKNOWN";
        case GRPCStatusCode::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case GRPCStatusCode::DEADLINE_EXCEEDED: return "DEADLINE_EXCEEDED";
        case GRPCStatusCode::NOT_FOUND: return "NOT_FOUND";
        case GRPCStatusCode::ALREADY_EXISTS: return "ALREADY_EXISTS";
        case GRPCStatusCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
        case GRPCStatusCode::RESOURCE_EXHAUSTED: return "RESOURCE_EXHAUSTED";
        case GRPCStatusCode::FAILED_PRECONDITION: return "FAILED_PRECONDITION";
        case GRPCStatusCode::ABORTED: return "ABORTED";
        case GRPCStatusCode::OUT_OF_RANGE: return "OUT_OF_RANGE";
        case GRPCStatusCode::UNIMPLEMENTED: return "UNIMPLEMENTED";
        case GRPCStatusCode::INTERNAL: return "INTERNAL";
        case GRPCStatusCode::UNAVAILABLE: return "UNAVAILABLE";
        case GRPCStatusCode::DATA_LOSS: return "DATA_LOSS";
        case GRPCStatusCode::UNAUTHENTICATED: return "UNAUTHENTICATED";
        default: return "UNKNOWN";
    }
}

std::string GRPCParser::stream_type_to_string(GRPCStreamType type) const {
    switch (type) {
        case GRPCStreamType::UNARY: return "UNARY";
        case GRPCStreamType::CLIENT_STREAMING: return "CLIENT_STREAMING";
        case GRPCStreamType::SERVER_STREAMING: return "SERVER_STREAMING";
        case GRPCStreamType::BIDIRECTIONAL: return "BIDIRECTIONAL";
        default: return "UNKNOWN";
    }
}

std::string GRPCParser::compression_to_string(GRPCCompression compression) const {
    switch (compression) {
        case GRPCCompression::NONE: return "NONE";
        case GRPCCompression::GZIP: return "GZIP";
        case GRPCCompression::DEFLATE: return "DEFLATE";
        case GRPCCompression::SNAPPY: return "SNAPPY";
        case GRPCCompression::LZ4: return "LZ4";
        default: return "UNKNOWN";
    }
}

ParseResult GRPCParser::parse_frame_header(const ProtocolParser::Core::BufferView& buffer, 
                                          HTTP2FrameHeader& header) const {
    if (buffer.size() < 9) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    // 解析帧长度（24位）
    header.length = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
    
    // 解析帧类型
    header.type = static_cast<HTTP2FrameType>(buffer[3]);
    
    // 解析标志
    header.flags = buffer[4];
    
    // 解析流ID（31位）
    header.stream_id = ntohl(*reinterpret_cast<const uint32_t*>(buffer.data() + 5)) & 0x7FFFFFFF;
    
    return ParseResult::SUCCESS;
}

ParseResult GRPCParser::simple_hpack_decode(const std::vector<uint8_t>& data, 
                                           GRPCHeaders& headers) const {
    // 这是一个极简的HPACK解码实现
    // 实际的HPACK实现要复杂得多，包括动态表、霍夫曼编码等
    
    size_t offset = 0;
    while (offset < data.size()) {
        uint8_t byte = data[offset++];
        
        // 简化处理：假设是字面量头部字段
        if ((byte & 0x40) == 0x40) { // 字面量头部字段，增量索引
            // 跳过索引部分（简化）
            if (byte & 0x3F) {
                // 有索引值，跳过
            }
            
            // 读取名称长度和名称（简化）
            if (offset >= data.size()) break;
            uint8_t name_len = data[offset++] & 0x7F;
            if (offset + name_len > data.size()) break;
            
            std::string name(reinterpret_cast<const char*>(data.data() + offset), name_len);
            offset += name_len;
            
            // 读取值长度和值（简化）
            if (offset >= data.size()) break;
            uint8_t value_len = data[offset++] & 0x7F;
            if (offset + value_len > data.size()) break;
            
            std::string value(reinterpret_cast<const char*>(data.data() + offset), value_len);
            offset += value_len;
            
            // 处理伪头部
            if (name[0] == ':') {
                parse_pseudo_header(name, value, headers);
            } else {
                // 处理普通头部
                std::string lower_name = name;
                std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
                
                if (lower_name == "content-type") {
                    headers.content_type = value;
                } else if (lower_name == "user-agent") {
                    headers.user_agent = value;
                } else if (lower_name == "grpc-encoding") {
                    headers.grpc_encoding = value;
                } else if (lower_name == "grpc-accept-encoding") {
                    headers.grpc_accept_encoding = value;
                } else if (lower_name == "grpc-timeout") {
                    headers.grpc_timeout = value;
                } else if (lower_name == "grpc-status") {
                    headers.grpc_status = value;
                } else if (lower_name == "grpc-message") {
                    headers.grpc_message = value;
                } else {
                    headers.custom_headers[name] = value;
                }
            }
        } else {
            // 其他类型的头部字段，简化处理
            break;
        }
    }
    
    return ParseResult::SUCCESS;
}

void GRPCParser::parse_pseudo_header(const std::string& name, 
                                    const std::string& value, 
                                    GRPCHeaders& headers) const {
    if (name == ":method") {
        headers.method = value;
    } else if (name == ":path") {
        headers.path = value;
    } else if (name == ":authority") {
        headers.authority = value;
    }
}

GRPCStreamType GRPCParser::detect_stream_type(const GRPCHeaders& headers) const {
    // 基于头部信息简单推断流类型
    // 实际的流类型检测需要分析多个消息
    
    // 这是一个简化的检测逻辑
    return GRPCStreamType::UNARY; // 默认为一元RPC
}

void GRPCParser::collect_metrics(const GRPCMessage& message) const {
    if (message.is_valid) {
        metrics_.total_calls++;
        
        // 统计方法调用
        if (!message.call_info.method.empty()) {
            metrics_.method_counts[message.call_info.method]++;
        }
        
        // 统计数据量
        if (message.type == GRPCMessageType::REQUEST) {
            metrics_.total_request_bytes += message.payload.size();
        } else if (message.type == GRPCMessageType::RESPONSE) {
            metrics_.total_response_bytes += message.payload.size();
        }
    }
}

} // namespace ProtocolParser::Parsers::Application