#include "parsers/application/mqtt_parser.hpp"
#include <cstring>
#include <algorithm>

namespace protocol_parser::parsers {

// ============================================================================
// MQTTProperty 实现
// ============================================================================

std::string MQTTProperty::value_to_string() const {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, uint8_t>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, uint16_t>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            return "<binary>";
        } else if constexpr (std::is_same_v<T, std::pair<std::string, std::string>>) {
            return val.first + "=" + val.second;
        }
        return "<unknown>";
    }, value);
}

size_t MQTTProperty::get_size() const noexcept {
    size_t size = 1; // Property identifier
    std::visit([&size](const auto& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, uint8_t>) {
            size += 1;
        } else if constexpr (std::is_same_v<T, uint16_t>) {
            size += 2;
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            size += 4;
        } else if constexpr (std::is_same_v<T, std::string>) {
            size += 2 + val.size();
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            size += 2 + val.size();
        } else if constexpr (std::is_same_v<T, std::pair<std::string, std::string>>) {
            size += 2 + val.first.size() + 2 + val.second.size();
        }
    }, value);
    return size;
}

// ============================================================================
// MQTTFixedHeader 实现
// ============================================================================

size_t MQTTFixedHeader::get_header_size() const noexcept {
    size_t len = 1; // 控制包类型
    uint32_t len_val = remaining_length;
    do {
        len++;
        len_val >>= 7;
    } while (len_val > 0);
    return len;
}

bool MQTTFixedHeader::is_valid() const noexcept {
    return message_type != MQTTMessageType::RESERVED_0;
}

// ============================================================================
// MQTT CONNECT 消息实现
// ============================================================================

bool MQTTConnectMessage::validate() const noexcept {
    if (client_id.empty()) return false;
    if (will_flag && will_topic.empty()) return false;
    if (will_flag && will_qos == MQTTQoS::RESERVED) return false;
    return true;
}

// ============================================================================
// MQTT PUBLISH 消息实现
// ============================================================================

bool MQTTPublishMessage::validate() const noexcept {
    return !topic.empty();
}

std::string MQTTPublishMessage::payload_as_string() const {
    return std::string(payload.begin(), payload.end());
}

// ============================================================================
// MQTT SUBSCRIBE 消息实现
// ============================================================================

bool MQTTSubscribeMessage::validate() const noexcept {
    return packet_id != 0 && !topic_filters.empty();
}

// ============================================================================
// MQTT 数据包实现
// ============================================================================

bool MQTTPacket::is_valid() const noexcept {
    return fixed_header.is_valid();
}

size_t MQTTPacket::get_total_size() const noexcept {
    return fixed_header.get_header_size() + fixed_header.remaining_length;
}

// ============================================================================
// MQTTParser 实现
// ============================================================================

const ProtocolInfo& MQTTParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {
        "MQTT",
        0x0C01,  // MQTT protocol type
        2,       // Minimum header size
        2,       // Minimum packet size
        268435455  // Maximum packet size
    };
    return info;
}

bool MQTTParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 2) return false;

    // 检查MQTT控制包类型 (upper 4 bits)
    uint8_t first_byte = buffer[0];
    uint8_t msg_type = (first_byte >> 4) & 0x0F;

    return msg_type >= 1 && msg_type <= 15;
}

ParseResult MQTTParser::parse(ParseContext& context) noexcept {
    reset();

    const auto buffer = context.buffer;
    const auto data = buffer.data();
    const auto size = buffer.size();

    if (size < 2) {
        return ParseResult::NeedMoreData;
    }

    // 解析固定头部
    size_t offset = 0;
    auto result = parse_fixed_header(data, size, offset);
    if (result != ParseResult::Success) {
        return result;
    }

    // 解析可变头部
    result = parse_variable_header(data, size, offset);
    if (result != ParseResult::Success) {
        return result;
    }

    // 解析载荷
    result = parse_payload(data, size, offset);
    if (result != ParseResult::Success) {
        return result;
    }

    parsed_successfully_ = true;
    update_statistics(mqtt_packet_);
    perform_security_analysis();

    return ParseResult::Success;
}

void MQTTParser::reset() noexcept {
    mqtt_packet_ = MQTTPacket{};
    parsed_successfully_ = false;
    is_malformed_ = false;
}

std::string MQTTParser::get_protocol_name() const noexcept {
    return "MQTT";
}

uint16_t MQTTParser::get_default_port() const noexcept {
    return MQTT_DEFAULT_PORT;
}

std::vector<uint16_t> MQTTParser::get_supported_ports() const noexcept {
    return {MQTT_DEFAULT_PORT, MQTT_TLS_PORT, MQTT_WS_PORT, MQTT_WSS_PORT};
}

const MQTTPacket& MQTTParser::get_mqtt_packet() const noexcept {
    return mqtt_packet_;
}

bool MQTTParser::is_mqtt_packet() const noexcept {
    return parsed_successfully_;
}

bool MQTTParser::validate_packet() const noexcept {
    return mqtt_packet_.is_valid();
}

bool MQTTParser::is_malformed() const noexcept {
    return is_malformed_;
}

MQTTParser::MQTTAnalysis MQTTParser::analyze_packet() const noexcept {
    MQTTAnalysis analysis;
    analysis.detected_version = MQTTVersion::MQTT_3_1_1;

    if (mqtt_packet_.fixed_header.message_type == MQTTMessageType::CONNECT) {
        analysis.is_client_message = true;
        analysis.has_security_issues = !mqtt_packet_.message.index();
    } else if (mqtt_packet_.fixed_header.message_type == MQTTMessageType::CONNACK) {
        analysis.is_server_message = true;
    } else if (mqtt_packet_.fixed_header.message_type == MQTTMessageType::PUBLISH) {
        analysis.is_data_message = true;
        analysis.has_payload = true;
    }

    return analysis;
}

const MQTTParser::MQTTStatistics& MQTTParser::get_statistics() const noexcept {
    return statistics_;
}

void MQTTParser::reset_statistics() noexcept {
    statistics_ = MQTTStatistics{};
}

std::string MQTTParser::message_type_to_string(MQTTMessageType type) noexcept {
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

std::string MQTTParser::version_to_string(MQTTVersion version) noexcept {
    switch (version) {
        case MQTTVersion::MQTT_3_1: return "MQTT 3.1";
        case MQTTVersion::MQTT_3_1_1: return "MQTT 3.1.1";
        case MQTTVersion::MQTT_5_0: return "MQTT 5.0";
        default: return "UNKNOWN";
    }
}

std::string MQTTParser::qos_to_string(MQTTQoS qos) noexcept {
    switch (qos) {
        case MQTTQoS::AT_MOST_ONCE: return "QoS 0";
        case MQTTQoS::AT_LEAST_ONCE: return "QoS 1";
        case MQTTQoS::EXACTLY_ONCE: return "QoS 2";
        default: return "RESERVED";
    }
}

std::string MQTTParser::return_code_to_string(MQTTConnectReturnCode code) noexcept {
    switch (code) {
        case MQTTConnectReturnCode::CONNECTION_ACCEPTED: return "Accepted";
        case MQTTConnectReturnCode::UNACCEPTABLE_PROTOCOL_VERSION: return "Unacceptable Protocol Version";
        case MQTTConnectReturnCode::IDENTIFIER_REJECTED: return "Identifier Rejected";
        case MQTTConnectReturnCode::SERVER_UNAVAILABLE: return "Server Unavailable";
        case MQTTConnectReturnCode::BAD_USERNAME_OR_PASSWORD: return "Bad Username or Password";
        case MQTTConnectReturnCode::NOT_AUTHORIZED: return "Not Authorized";
        default: return "UNKNOWN";
    }
}

bool MQTTParser::is_valid_topic(const std::string& topic) noexcept {
    if (topic.empty() || topic.size() > MAX_TOPIC_LENGTH) {
        return false;
    }

    // 检查通配符
    if (topic.find('+') != std::string::npos || topic.find('#') != std::string::npos) {
        return false;
    }

    return true;
}

bool MQTTParser::is_wildcard_topic(const std::string& topic) noexcept {
    return topic.find('+') != std::string::npos || topic.find('#') != std::string::npos;
}

// ============================================================================
// 私有方法实现
// ============================================================================

ParseResult MQTTParser::parse_fixed_header(const uint8_t* data, size_t size, size_t& offset) noexcept {
    if (offset >= size) return ParseResult::NeedMoreData;

    uint8_t first_byte = data[offset++];
    mqtt_packet_.fixed_header.message_type = static_cast<MQTTMessageType>((first_byte >> 4) & 0x0F);
    mqtt_packet_.fixed_header.dup_flag = (first_byte & 0x08) != 0;
    mqtt_packet_.fixed_header.qos_level = static_cast<MQTTQoS>((first_byte >> 1) & 0x03);
    mqtt_packet_.fixed_header.retain_flag = (first_byte & 0x01) != 0;

    // 解析剩余长度
    mqtt_packet_.fixed_header.remaining_length = decode_remaining_length(data, size, offset);
    if (offset + mqtt_packet_.fixed_header.remaining_length > size) {
        return ParseResult::NeedMoreData;
    }

    return ParseResult::Success;
}

ParseResult MQTTParser::parse_variable_header(const uint8_t* data, size_t size, size_t& offset) noexcept {
    // 根据消息类型解析可变头部
    switch (mqtt_packet_.fixed_header.message_type) {
        case MQTTMessageType::CONNECT:
            return parse_connect_message(data, size, offset);
        case MQTTMessageType::CONNACK:
            return parse_connack_message(data, size, offset);
        case MQTTMessageType::PUBLISH:
            return parse_publish_message(data, size, offset);
        case MQTTMessageType::SUBSCRIBE:
            return parse_subscribe_message(data, size, offset);
        default:
            // 其他消息类型暂时跳过
            return ParseResult::Success;
    }
}

ParseResult MQTTParser::parse_payload(const uint8_t* data, size_t size, size_t& offset) noexcept {
    // 载荷解析在具体的消息处理中完成
    return ParseResult::Success;
}

ParseResult MQTTParser::parse_connect_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    MQTTConnectMessage connect_msg;

    // 协议名称
    connect_msg.protocol_name = read_utf8_string(data, size, offset);
    if (offset > size) return ParseResult::InvalidFormat;

    // 协议版本
    if (offset >= size) return ParseResult::NeedMoreData;
    connect_msg.protocol_version = static_cast<MQTTVersion>(data[offset++]);

    // 连接标志
    if (offset >= size) return ParseResult::NeedMoreData;
    uint8_t flags = data[offset++];
    connect_msg.clean_session = (flags & 0x02) != 0;
    connect_msg.will_flag = (flags & 0x04) != 0;
    connect_msg.will_qos = static_cast<MQTTQoS>((flags >> 3) & 0x03);
    connect_msg.will_retain = (flags & 0x20) != 0;
    connect_msg.password_flag = (flags & 0x40) != 0;
    connect_msg.username_flag = (flags & 0x80) != 0;

    // 保活
    if (offset + 2 > size) return ParseResult::NeedMoreData;
    connect_msg.keep_alive = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // Client ID
    connect_msg.client_id = read_utf8_string(data, size, offset);

    // Will Topic 和 Will Message
    if (connect_msg.will_flag) {
        connect_msg.will_topic = read_utf8_string(data, size, offset);
        connect_msg.will_message = read_utf8_string(data, size, offset);
    }

    // Username 和 Password
    if (connect_msg.username_flag) {
        connect_msg.username = read_utf8_string(data, size, offset);
    }
    if (connect_msg.password_flag) {
        connect_msg.password = read_utf8_string(data, size, offset);
    }

    mqtt_packet_.message = connect_msg;
    return ParseResult::Success;
}

ParseResult MQTTParser::parse_connack_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    if (offset + 2 > size) return ParseResult::NeedMoreData;

    MQTTConnackMessage connack;
    connack.session_present = (data[offset++] & 0x01) != 0;
    connack.return_code = static_cast<MQTTConnectReturnCode>(data[offset++]);

    mqtt_packet_.message = connack;
    return ParseResult::Success;
}

ParseResult MQTTParser::parse_publish_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    MQTTPublishMessage pub_msg;

    // Topic
    pub_msg.topic = read_utf8_string(data, size, offset);
    if (pub_msg.topic.empty()) return ParseResult::InvalidFormat;

    // Packet ID (if QoS > 0)
    if (mqtt_packet_.fixed_header.qos_level != MQTTQoS::AT_MOST_ONCE) {
        if (offset + 2 > size) return ParseResult::NeedMoreData;
        pub_msg.packet_id = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
    }

    // Payload
    size_t payload_size = mqtt_packet_.fixed_header.remaining_length - (offset - 2); // Adjust for header
    if (offset + payload_size <= size) {
        pub_msg.payload.assign(data + offset, data + offset + payload_size);
        offset += payload_size;
    }

    mqtt_packet_.message = pub_msg;
    return ParseResult::Success;
}

ParseResult MQTTParser::parse_subscribe_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    MQTTSubscribeMessage sub_msg;

    // Packet ID
    if (offset + 2 > size) return ParseResult::NeedMoreData;
    sub_msg.packet_id = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // Topics (简化：只读取第一个)
    while (offset + 2 <= size) {
        std::string topic = read_utf8_string(data, size, offset);
        if (topic.empty()) break;

        MQTTSubscribeMessage::TopicFilter filter;
        filter.topic = topic;

        if (offset < size) {
            uint8_t options = data[offset++];
            filter.max_qos = static_cast<MQTTQoS>(options & 0x03);
        }

        sub_msg.topic_filters.push_back(filter);
    }

    mqtt_packet_.message = sub_msg;
    return ParseResult::Success;
}

uint32_t MQTTParser::decode_remaining_length(const uint8_t* data, size_t size, size_t& offset) noexcept {
    uint32_t value = 0;
    uint8_t multiplier = 1;
    size_t index = offset;

    while (index < size) {
        uint8_t encoded_byte = data[index++];
        value += (encoded_byte & 0x7F) * multiplier;

        if ((encoded_byte & 0x80) == 0) {
            offset = index;
            return value;
        }

        multiplier *= 0x80;
        if (multiplier > 0x08000000) {
            offset = index;
            return value; // Invalid, but return what we have
        }
    }

    offset = index;
    return value;
}

std::string MQTTParser::read_utf8_string(const uint8_t* data, size_t size, size_t& offset) noexcept {
    if (offset + 2 > size) {
        offset = size;
        return "";
    }

    uint16_t len = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    if (offset + len > size) {
        offset = size;
        return "";
    }

    std::string result(reinterpret_cast<const char*>(data + offset), len);
    offset += len;
    return result;
}

ParseResult MQTTParser::parse_properties(const uint8_t* data, size_t size, size_t& offset,
                                        std::vector<MQTTProperty>& properties) noexcept {
    // 简化实现：跳过属性解析
    (void)data;
    (void)size;
    (void)offset;
    (void)properties;
    return ParseResult::Success;
}

bool MQTTParser::validate_fixed_header() const noexcept {
    return mqtt_packet_.fixed_header.is_valid();
}

bool MQTTParser::validate_topic_name(const std::string& topic) const noexcept {
    return is_valid_topic(topic);
}

bool MQTTParser::validate_client_id(const std::string& client_id) const noexcept {
    return !client_id.empty() && client_id.size() <= MAX_CLIENT_ID_LENGTH;
}

void MQTTParser::perform_security_analysis() noexcept {
    // 简化实现
}

void MQTTParser::update_statistics(const MQTTPacket& packet) noexcept {
    statistics_.total_packets++;

    switch (packet.fixed_header.message_type) {
        case MQTTMessageType::CONNECT:
            statistics_.connect_count++;
            break;
        case MQTTMessageType::CONNACK:
            statistics_.connack_count++;
            break;
        case MQTTMessageType::PUBLISH:
            statistics_.publish_count++;
            break;
        case MQTTMessageType::SUBSCRIBE:
            statistics_.subscribe_count++;
            break;
        case MQTTMessageType::PINGREQ:
            statistics_.pingreq_count++;
            break;
        case MQTTMessageType::PINGRESP:
            statistics_.pingresp_count++;
            break;
        case MQTTMessageType::DISCONNECT:
            statistics_.disconnect_count++;
            break;
        default:
            break;
    }
}

} // namespace protocol_parser::parsers
