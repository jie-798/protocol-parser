#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <vector>
#include <cstdint>
#include <memory>
#include <string>

namespace protocol_parser::parsers {

// SCTP块类型
enum class SCTPChunkType : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    SCTP_ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    SHUTDOWN_COMPLETE = 14
};

// SCTP通用头部
struct SCTPHeader {
    static constexpr size_t SIZE = 12;
    
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verification_tag;
    uint32_t checksum;
};

// SCTP块头部
struct SCTPChunkHeader {
    static constexpr size_t SIZE = 4;
    
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

// SCTP解析结果
struct SCTPParseResult {
    SCTPHeader header;
    std::vector<SCTPChunkHeader> chunks;
    core::BufferView payload;
    size_t payload_length = 0;
    bool checksum_valid = false;
};

class SCTPParser : public BaseParser {
public:
    SCTPParser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    [[nodiscard]] const SCTPParseResult& get_result() const noexcept {
        return result_;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    SCTPParseResult result_;
    
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_chunks(ParseContext& context) noexcept;
};

class SCTPParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override;
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override;
};

} // namespace protocol_parser::parsers