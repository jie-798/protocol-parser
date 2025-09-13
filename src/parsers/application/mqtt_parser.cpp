#include "parsers/application/mqtt_parser.hpp"
#include <string>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace ProtocolParser::Parsers::Application {

MQTTParser::MQTTParser() : BaseParser() {
    // 初始化MQTT签名模式
    signatures_ = {
        {0x10, 0xFF, "MQTT CONNECT"},
        {0x20, 0xFF, "MQTT CONNACK"},
        {0x30, 0xF0, "MQTT PUBLISH"},
        {0x40, 0xFF, "MQTT PUBACK"},
        {0x50, 0xFF, "MQTT PUBREC"},
        {0x60, 0xFF, "MQTT PUBREL"},
        {0x70, 0xFF, "MQTT PUBCOMP"},
        {0x80, 0xFF, "MQTT SUBSCRIBE"},
        {0x90, 0xFF, "MQTT SUBACK"},
        {0xA0, 0xFF, "MQTT UNSUBSCRIBE"},
        {0xB0, 0xFF, "MQTT UNSUBACK"},
        {0xC0, 0xFF, "MQTT PINGREQ"},
        {0xD0, 0xFF, "MQTT PINGRESP"},
        {0xE0, 0xFF, "MQTT DISCONNECT"},
        {0xF0, 0xFF, "MQTT AUTH"}
    };
}

ParseResult MQTTParser::parse(const ParseContext& context) {
    const auto& buffer = context.buffer;
    
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }

    try {
        // 解析固定头部
        auto fixed_header_result = parse_fixed_header(buffer);
        if (fixed_header_result.type == MQTTMessageType::RESERVED) {
            return ParseResult::INVALID_FORMAT;
        }

        // 检查数据长度是否足够
        size_t total_length = 1 + fixed_header_result.remaining_length_size + 
                             fixed_header_result.remaining_length;
        if (buffer.size() < total_length) {
            return ParseResult::INSUFFICIENT_DATA;
        }

        // 解析可变头部和载荷
        size_t offset = 1 + fixed_header_result.remaining_length_size;
        ProtocolParser::Core::BufferView remaining_data(
            buffer.data() + offset, 
            fixed_header_result.remaining_length
        );

        MQTTMessage message;
        message.fixed_header = fixed_header_result;

        switch (fixed_header_result.type) {
            case MQTTMessageType::CONNECT:
                return parse_connect_message(remaining_data, message);
            case MQTTMessageType::CONNACK:
                return parse_connack_message(remaining_data, message);
            case MQTTMessageType::PUBLISH:
                return parse_publish_message(remaining_data, message, fixed_header_result);
            case MQTTMessageType::PUBACK:
            case MQTTMessageType::PUBREC:
            case MQTTMessageType::PUBREL:
            case MQTTMessageType::PUBCOMP:
                return parse_puback_message(remaining_data, message);
            case MQTTMessageType::SUBSCRIBE:
                return parse_subscribe_message(remaining_data, message);
            case MQTTMessageType::SUBACK:
                return parse_suback_message(remaining_data, message);
            case MQTTMessageType::UNSUBSCRIBE:
                return parse_unsubscribe_message(remaining_data, message);
            case MQTTMessageType::UNSUBACK:
                return parse_unsuback_message(remaining_data, message);
            case MQTTMessageType::PINGREQ:
            case MQTTMessageType::PINGRESP:
                return ParseResult::SUCCESS; // 无载荷消息
            case MQTTMessageType::DISCONNECT:
                return parse_disconnect_message(remaining_data, message);
            case MQTTMessageType::AUTH:
                return parse_auth_message(remaining_data, message);
            default:
                return ParseResult::INVALID_FORMAT;
        }

    } catch (const std::exception&) {
        return ParseResult::PARSING_ERROR;
    }
}

std::string MQTTParser::get_info() const {
    return "MQTT Protocol Parser - Supports MQTT 3.1, 3.1.1, and 5.0";
}

MQTTFixedHeader MQTTParser::parse_fixed_header(const ProtocolParser::Core::BufferView& buffer) {
    MQTTFixedHeader header;
    
    // 解析第一个字节
    uint8_t first_byte = buffer[0];
    header.type = static_cast<MQTTMessageType>((first_byte >> 4) & 0x0F);
    header.dup = (first_byte & 0x08) != 0;
    header.qos = static_cast<MQTTQoSLevel>((first_byte >> 1) & 0x03);
    header.retain = (first_byte & 0x01) != 0;

    // 解析剩余长度
    size_t offset = 1;
    header.remaining_length = 0;
    header.remaining_length_size = 0;
    uint32_t multiplier = 1;

    do {
        if (offset >= buffer.size()) {
            throw std::runtime_error("Insufficient data for remaining length");
        }
        
        uint8_t byte = buffer[offset++];
        header.remaining_length += (byte & 0x7F) * multiplier;
        header.remaining_length_size++;
        
        if ((byte & 0x80) == 0) {
            break;
        }
        
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) {
            throw std::runtime_error("Malformed remaining length");
        }
    } while (true);

    return header;
}

ParseResult MQTTParser::parse_connect_message(const ProtocolParser::Core::BufferView& buffer, 
                                            MQTTMessage& message) {
    if (buffer.size() < 10) { // 最小CONNECT消息长度
        return ParseResult::INSUFFICIENT_DATA;
    }

    size_t offset = 0;
    
    // 解析协议名称长度
    uint16_t protocol_name_length = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
    offset += 2;
    
    if (offset + protocol_name_length > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    // 检查协议名称
    std::string protocol_name(reinterpret_cast<const char*>(buffer.data() + offset), protocol_name_length);
    offset += protocol_name_length;
    
    if (protocol_name != "MQTT" && protocol_name != "MQIsdp") {
        return ParseResult::INVALID_FORMAT;
    }
    
    // 解析协议版本
    if (offset >= buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    uint8_t protocol_version = buffer[offset++];
    
    // 解析连接标志
    if (offset >= buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    uint8_t connect_flags = buffer[offset++];
    
    // 解析Keep Alive
    if (offset + 2 > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    uint16_t keep_alive = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
    offset += 2;
    
    // 解析客户端ID
    if (offset + 2 > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    uint16_t client_id_length = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
    offset += 2;
    
    if (offset + client_id_length > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    std::string client_id(reinterpret_cast<const char*>(buffer.data() + offset), client_id_length);
    offset += client_id_length;
    
    // 存储解析结果
    message.connect_info.protocol_name = protocol_name;
    message.connect_info.protocol_version = protocol_version;
    message.connect_info.connect_flags = connect_flags;
    message.connect_info.keep_alive = keep_alive;
    message.connect_info.client_id = client_id;
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_connack_message(const ProtocolParser::Core::BufferView& buffer, 
                                            MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    message.connack_info.session_present = (buffer[0] & 0x01) != 0;
    message.connack_info.return_code = buffer[1];
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_publish_message(const ProtocolParser::Core::BufferView& buffer, 
                                            MQTTMessage& message, 
                                            const MQTTFixedHeader& header) {
    size_t offset = 0;
    
    // 解析主题名称
    auto topic_result = parse_string_field(buffer, offset, message.publish_info.topic);
    if (topic_result != ParseResult::SUCCESS) {
        return topic_result;
    }
    
    // 如果QoS > 0，解析包ID
    if (header.qos > MQTTQoSLevel::AT_MOST_ONCE) {
        if (offset + 2 > buffer.size()) {
            return ParseResult::INSUFFICIENT_DATA;
        }
        message.publish_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;
    }
    
    // 剩余数据为载荷
    if (offset < buffer.size()) {
        message.publish_info.payload.assign(
            reinterpret_cast<const char*>(buffer.data() + offset),
            buffer.size() - offset
        );
    }
    
    message.publish_info.qos = header.qos;
    message.publish_info.retain = header.retain;
    message.publish_info.dup = header.dup;
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_puback_message(const ProtocolParser::Core::BufferView& buffer, 
                                           MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    message.puback_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data()));
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_subscribe_message(const ProtocolParser::Core::BufferView& buffer, 
                                              MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    size_t offset = 0;
    
    // 解析包ID
    message.subscribe_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data()));
    offset += 2;
    
    // 解析主题过滤器列表
    while (offset < buffer.size()) {
        MQTTTopicFilter filter;
        
        // 解析主题过滤器
        auto topic_result = parse_string_field(buffer, offset, filter.topic);
        if (topic_result != ParseResult::SUCCESS) {
            return topic_result;
        }
        
        // 解析QoS
        if (offset >= buffer.size()) {
            return ParseResult::INSUFFICIENT_DATA;
        }
        filter.qos = static_cast<MQTTQoSLevel>(buffer[offset++]);
        
        message.subscribe_info.topic_filters.push_back(filter);
    }
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_suback_message(const ProtocolParser::Core::BufferView& buffer, 
                                           MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    size_t offset = 0;
    
    // 解析包ID
    message.suback_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data()));
    offset += 2;
    
    // 解析返回码列表
    while (offset < buffer.size()) {
        message.suback_info.return_codes.push_back(buffer[offset++]);
    }
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_unsubscribe_message(const ProtocolParser::Core::BufferView& buffer, 
                                                 MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    size_t offset = 0;
    
    // 解析包ID
    message.unsubscribe_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data()));
    offset += 2;
    
    // 解析主题过滤器列表
    while (offset < buffer.size()) {
        std::string topic;
        auto topic_result = parse_string_field(buffer, offset, topic);
        if (topic_result != ParseResult::SUCCESS) {
            return topic_result;
        }
        message.unsubscribe_info.topic_filters.push_back(topic);
    }
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_unsuback_message(const ProtocolParser::Core::BufferView& buffer, 
                                             MQTTMessage& message) {
    if (buffer.size() < 2) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    message.unsuback_info.packet_id = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data()));
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_disconnect_message(const ProtocolParser::Core::BufferView& buffer, 
                                               MQTTMessage& message) {
    // MQTT 3.1.1 DISCONNECT消息没有载荷
    // MQTT 5.0可能有属性，但这里简化处理
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_auth_message(const ProtocolParser::Core::BufferView& buffer, 
                                         MQTTMessage& message) {
    // AUTH消息是MQTT 5.0的新功能
    // 简化实现，实际需要解析原因码和属性
    if (buffer.size() < 1) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    message.auth_info.reason_code = buffer[0];
    
    return ParseResult::SUCCESS;
}

ParseResult MQTTParser::parse_string_field(const ProtocolParser::Core::BufferView& buffer, 
                                         size_t& offset, 
                                         std::string& result) {
    if (offset + 2 > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    uint16_t length = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
    offset += 2;
    
    if (offset + length > buffer.size()) {
        return ParseResult::INSUFFICIENT_DATA;
    }
    
    result.assign(reinterpret_cast<const char*>(buffer.data() + offset), length);
    offset += length;
    
    return ParseResult::SUCCESS;
}

bool MQTTParser::is_valid_topic(const std::string& topic) const {
    if (topic.empty() || topic.length() > 65535) {
        return false;
    }
    
    // 检查非法字符
    for (char c : topic) {
        if (c == '\0' || c == '+' || c == '#') {
            return false;
        }
    }
    
    return true;
}

bool MQTTParser::is_valid_topic_filter(const std::string& filter) const {
    if (filter.empty() || filter.length() > 65535) {
        return false;
    }
    
    // 简化的主题过滤器验证
    // 实际应该检查通配符的正确使用
    for (char c : filter) {
        if (c == '\0') {
            return false;
        }
    }
    
    return true;
}

MQTTVersion MQTTParser::detect_version(uint8_t protocol_version) const {
    switch (protocol_version) {
        case 3:
            return MQTTVersion::V3_1;
        case 4:
            return MQTTVersion::V3_1_1;
        case 5:
            return MQTTVersion::V5_0;
        default:
            return MQTTVersion::UNKNOWN;
    }
}

bool MQTTParser::validate_message(const MQTTMessage& message) const {
    // 基本消息验证
    switch (message.fixed_header.type) {
        case MQTTMessageType::CONNECT:
            return !message.connect_info.client_id.empty();
        case MQTTMessageType::PUBLISH:
            return is_valid_topic(message.publish_info.topic);
        case MQTTMessageType::SUBSCRIBE:
            for (const auto& filter : message.subscribe_info.topic_filters) {
                if (!is_valid_topic_filter(filter.topic)) {
                    return false;
                }
            }
            return true;
        default:
            return true;
    }
}

void MQTTParser::collect_statistics(const MQTTMessage& message) {
    // 统计消息类型分布
    auto type_str = mqtt_message_type_to_string(message.fixed_header.type);
    // 这里可以与统计系统集成
    
    // 统计QoS分布
    if (message.fixed_header.type == MQTTMessageType::PUBLISH) {
        // 统计QoS级别
    }
    
    // 统计主题分布
    if (message.fixed_header.type == MQTTMessageType::PUBLISH) {
        // 统计主题使用情况
    }
}

std::string MQTTParser::mqtt_message_type_to_string(MQTTMessageType type) const {
    switch (type) {
        case MQTTMessageType::CONNECT: return "CONNECT";
        case MQTTMessageType::CONNACK: return "CONNACK";
        case MQTTMessageType::PUBLISH: return "PUBLISH";
        case MQTTMessageType::PUBACK: return "PUBACK";
        case MQTTMessageType::PUBREC: return "PUBREC";
        case MQTTMessageType::PUBREL: return "PUBREL";
        case MQTTMessageType::PUBCOMP: return "PUBCOMP";
        case MQTTMessageType::SUBSCRIBE: return "SUBSCRIBE";
        case MQTTMessageType::SUBACK: return "SUBACK";
        case MQTTMessageType::UNSUBSCRIBE: return "UNSUBSCRIBE";
        case MQTTMessageType::UNSUBACK: return "UNSUBACK";
        case MQTTMessageType::PINGREQ: return "PINGREQ";
        case MQTTMessageType::PINGRESP: return "PINGRESP";
        case MQTTMessageType::DISCONNECT: return "DISCONNECT";
        case MQTTMessageType::AUTH: return "AUTH";
        default: return "UNKNOWN";
    }
}

} // namespace ProtocolParser::Parsers::Application