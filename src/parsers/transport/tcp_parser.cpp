#include "../../../include/parsers/transport/tcp_parser.hpp"
#include <cstring>
#include <algorithm>

namespace protocol_parser::parsers {

// TCP协议信息
const ProtocolInfo TCPParser::protocol_info_ = {
    "TCP",
    6,      // IP协议号
    20,     // 最小头长度
    20,     // 最小包大小
    65535   // 最大包大小
};

TCPParser::TCPParser() : BaseParser() {
    reset();
}

const ProtocolInfo& TCPParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool TCPParser::can_parse(const core::BufferView& buffer) const noexcept {
    return buffer.size() >= TCPHeader::MIN_SIZE;
}

ParseResult TCPParser::parse(ParseContext& context) noexcept {
    reset();
    
    // 解析TCP头部
    auto header_result = parse_header(context);
    if (header_result != ParseResult::Success) {
        return header_result;
    }
    
    // 解析TCP选项
    auto options_result = parse_options(context);
    if (options_result != ParseResult::Success) {
        return options_result;
    }
    
    // 解析载荷
    auto payload_result = parse_payload(context);
    if (payload_result != ParseResult::Success) {
        return payload_result;
    }
    
    // 将解析结果存储到metadata中
    context.metadata["tcp_result"] = result_;
    
    context.state = ParserState::Complete;
    return ParseResult::Success;
}

void TCPParser::reset() noexcept {
    result_ = TCPParseResult{};
}

double TCPParser::get_progress() const noexcept {
    return 1.0; // 简单实现，总是返回100%
}

ParseResult TCPParser::parse_header(ParseContext& context) noexcept {
    if (context.buffer.size() < TCPHeader::MIN_SIZE) {
        return ParseResult::NeedMoreData;
    }
    
    const uint8_t* data = context.buffer.data();
    
    // 解析TCP头部字段
    result_.header.src_port = (data[0] << 8) | data[1];
    result_.header.dst_port = (data[2] << 8) | data[3];
    result_.header.seq_num = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    result_.header.ack_num = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    result_.header.data_offset_flags = data[12];
    result_.header.flags = data[13];
    result_.header.window_size = (data[14] << 8) | data[15];
    result_.header.checksum = (data[16] << 8) | data[17];
    result_.header.urgent_ptr = (data[18] << 8) | data[19];
    
    // 验证数据偏移
    uint8_t data_offset = result_.header.get_data_offset();
    if (data_offset < 5 || data_offset > 15) {
        return ParseResult::InvalidFormat;
    }
    
    size_t header_length = data_offset * 4;
    if (context.buffer.size() < header_length) {
        return ParseResult::NeedMoreData;
    }
    
    context.offset = TCPHeader::MIN_SIZE;
    return ParseResult::Success;
}

ParseResult TCPParser::parse_options(ParseContext& context) noexcept {
    uint8_t data_offset = result_.header.get_data_offset();
    size_t header_length = data_offset * 4;
    size_t options_length = header_length - TCPHeader::MIN_SIZE;
    
    if (options_length == 0) {
        context.offset = header_length;
        return ParseResult::Success;
    }
    
    if (context.buffer.size() < header_length) {
        return ParseResult::NeedMoreData;
    }
    
    const uint8_t* options_data = context.buffer.data() + TCPHeader::MIN_SIZE;
    size_t offset = 0;
    
    while (offset < options_length) {
        if (offset >= options_length) break;
        
        uint8_t option_type = options_data[offset];
        
        // 处理选项列表结束
        if (option_type == TCPOptionType::END_OF_OPTIONS) {
            break;
        }
        
        // 处理无操作选项
        if (option_type == TCPOptionType::NO_OPERATION) {
            offset++;
            continue;
        }
        
        // 处理其他选项
        if (offset + 1 >= options_length) {
            return ParseResult::InvalidFormat;
        }
        
        uint8_t option_length = options_data[offset + 1];
        if (option_length < 2 || offset + option_length > options_length) {
            return ParseResult::InvalidFormat;
        }
        
        TCPOption option;
        option.type = option_type;
        option.length = option_length;
        
        if (option_length > 2) {
            option.data.resize(option_length - 2);
            std::memcpy(option.data.data(), options_data + offset + 2, option_length - 2);
        }
        
        result_.options.push_back(std::move(option));
        offset += option_length;
    }
    
    context.offset = header_length;
    return ParseResult::Success;
}

ParseResult TCPParser::parse_payload(ParseContext& context) noexcept {
    size_t header_length = result_.header.get_data_offset() * 4;
    
    if (context.buffer.size() > header_length) {
        result_.payload = core::BufferView(
            context.buffer.data() + header_length,
            context.buffer.size() - header_length
        );
        result_.payload_length = result_.payload.size();
    } else {
        result_.payload = core::BufferView(nullptr, 0);
        result_.payload_length = 0;
    }
    
    // 简单的校验和验证（这里只是标记为有效）
    result_.checksum_valid = true;
    
    return ParseResult::Success;
}

// 注册TCP解析器
REGISTER_PARSER(6, TCPParserFactory);

} // namespace protocol_parser::parsers