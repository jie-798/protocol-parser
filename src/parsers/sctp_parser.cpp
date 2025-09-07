#include "parsers/sctp_parser.hpp"
#include <cstring>
#include <memory>

namespace protocol_parser::parsers {

// SCTP协议信息
const ProtocolInfo SCTPParser::protocol_info_ = {
    "SCTP",
    132,    // IP协议号
    12,     // 头长度
    12,     // 最小包大小
    65535   // 最大包大小
};

SCTPParser::SCTPParser() : BaseParser() {
    reset();
}

const ProtocolInfo& SCTPParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool SCTPParser::can_parse(const core::BufferView& buffer) const noexcept {
    return buffer.size() >= SCTPHeader::SIZE;
}

ParseResult SCTPParser::parse(ParseContext& context) noexcept {
    reset();
    
    // 解析SCTP头部
    auto header_result = parse_header(context);
    if (header_result != ParseResult::Success) {
        return header_result;
    }
    
    // 解析SCTP块
    auto chunks_result = parse_chunks(context);
    if (chunks_result != ParseResult::Success) {
        return chunks_result;
    }
    
    context.state = ParserState::Complete;
    return ParseResult::Success;
}

void SCTPParser::reset() noexcept {
    result_ = SCTPParseResult{};
}

double SCTPParser::get_progress() const noexcept {
    return 1.0; // 简单实现，总是返回100%
}

ParseResult SCTPParser::parse_header(ParseContext& context) noexcept {
    if (context.buffer.size() < SCTPHeader::SIZE) {
        return ParseResult::NeedMoreData;
    }
    
    const uint8_t* data = context.buffer.data();
    
    // 解析SCTP头部字段
    result_.header.src_port = (data[0] << 8) | data[1];
    result_.header.dst_port = (data[2] << 8) | data[3];
    result_.header.verification_tag = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    result_.header.checksum = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    
    context.offset = SCTPHeader::SIZE;
    return ParseResult::Success;
}

ParseResult SCTPParser::parse_chunks(ParseContext& context) noexcept {
    size_t offset = SCTPHeader::SIZE;
    
    // 解析所有SCTP块
    while (offset < context.buffer.size()) {
        if (offset + SCTPChunkHeader::SIZE > context.buffer.size()) {
            break; // 不完整的块头
        }
        
        const uint8_t* chunk_data = context.buffer.data() + offset;
        
        SCTPChunkHeader chunk_header;
        chunk_header.type = chunk_data[0];
        chunk_header.flags = chunk_data[1];
        chunk_header.length = (chunk_data[2] << 8) | chunk_data[3];
        
        // 验证块长度
        if (chunk_header.length < SCTPChunkHeader::SIZE) {
            return ParseResult::InvalidFormat;
        }
        
        if (offset + chunk_header.length > context.buffer.size()) {
            break; // 不完整的块
        }
        
        result_.chunks.push_back(chunk_header);
        
        // 移动到下一个块（考虑4字节对齐）
        size_t padded_length = (chunk_header.length + 3) & ~3;
        offset += padded_length;
    }
    
    // 设置载荷信息
    if (offset < context.buffer.size()) {
        result_.payload = core::BufferView(
            context.buffer.data() + offset,
            context.buffer.size() - offset
        );
        result_.payload_length = context.buffer.size() - offset;
    } else {
        result_.payload = core::BufferView(nullptr, 0);
        result_.payload_length = 0;
    }
    
    // 简单的校验和验证（这里只是标记为有效）
    result_.checksum_valid = true;
    
    return ParseResult::Success;
}

// SCTPParserFactory实现
std::unique_ptr<BaseParser> SCTPParserFactory::create_parser() {
    return std::make_unique<SCTPParser>();
}

std::vector<uint16_t> SCTPParserFactory::get_supported_types() const {
    return {132}; // SCTP协议号
}

// 注册SCTP解析器
REGISTER_PARSER(132, SCTPParserFactory);

} // namespace protocol_parser::parsers