#include "parsers/signaling/h323_parser.hpp"
#include <sstream>

namespace protocol_parser::signaling {

std::string H323CallInfo::get_message_name() const {
    switch (message_type) {
        case H323MessageType::Setup: return "Setup";
        case H323MessageType::CallProceeding: return "Call Proceeding";
        case H323MessageType::Alerting: return "Alerting";
        case H323MessageType::Connect: return "Connect";
        case H323MessageType::ReleaseComplete: return "Release Complete";
        case H323MessageType::Facility: return "Facility";
        case H323MessageType::Progress: return "Progress";
        default: return "Unknown";
    }
}

std::string H323CallInfo::to_string() const {
    std::ostringstream oss;
    oss << "H.323 " << get_message_name() << "\n";
    oss << "Protocol Discriminator: 0x" << std::hex << static_cast<int>(protocol_discriminator) << std::dec << "\n";
    
    if (calling_number.has_value()) {
        oss << "Calling Number: " << calling_number.value() << "\n";
    }
    if (called_number.has_value()) {
        oss << "Called Number: " << called_number.value() << "\n";
    }
    if (cause.has_value()) {
        oss << "Cause: " << static_cast<int>(cause.value()) << "\n";
    }
    
    return oss.str();
}

const ProtocolInfo& H323Parser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"H.323", 0x307, 4, 8, 8192};
    return info;
}

bool H323Parser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 4) return false;
    // Q.931协议鉴别器
    return buffer[0] == 0x08;
}

ParseResult H323Parser::parse(ParseContext& context) noexcept {
    reset();
    const auto& buffer = context.buffer;

    if (!can_parse(buffer)) {
        return ParseResult::InvalidFormat;
    }

    if (!parse_h323_message(buffer, current_info_)) {
        return ParseResult::InvalidFormat;
    }

    context.metadata["h323_info"] = current_info_;
    return ParseResult::Success;
}

void H323Parser::reset() noexcept {
    current_info_ = H323CallInfo{};
    parse_success_ = false;
}

bool H323Parser::parse_h323_message(const BufferView& buffer, H323CallInfo& info) {
    // 尝试解析为Q.931
    if (buffer.size() >= 4 && buffer[0] == 0x08) {
        return parse_q931_message(buffer, info);
    }
    
    // TODO: 添加H.245, H.225, RAS解析
    return false;
}

bool H323Parser::parse_q931_message(const BufferView& buffer, H323CallInfo& info) {
    if (buffer.size() < 5) return false;

    info.protocol_discriminator = buffer[0];
    info.call_reference_length = buffer[1] & 0x0F;
    
    size_t offset = 2;
    // 提取呼叫参考值
    if (offset + info.call_reference_length <= buffer.size()) {
        info.call_reference.assign(buffer.data() + offset, 
                                 buffer.data() + offset + info.call_reference_length);
        offset += info.call_reference_length;
    }

    // 消息类型
    if (offset < buffer.size()) {
        info.message_type_q931 = buffer[offset];
        info.message_type = static_cast<H323MessageType>(buffer[offset]);
        offset++;
    }

    // 简单设置标志
    info.is_setup = (info.message_type == H323MessageType::Setup);
    info.is_connect = (info.message_type == H323MessageType::Connect);
    info.is_release = (info.message_type == H323MessageType::ReleaseComplete);

    info.parse_timestamp = std::chrono::steady_clock::now();
    return true;
}

bool H323Parser::parse_h245_message(const BufferView& buffer, H323CallInfo& info) {
    // TODO: 实现H.245逻辑信道信令解析
    // H.245使用PER编码，比较复杂
    return false;
}

} // namespace protocol_parser::signaling
