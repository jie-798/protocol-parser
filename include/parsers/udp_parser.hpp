#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <cstdint>

namespace protocol_parser::parsers {

/**
 * UDP头部结构
 */
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    
    static constexpr size_t SIZE = 8;
};

/**
 * UDP解析结果
 */
struct UDPParseResult {
    UDPHeader header;
    core::BufferView payload;
    bool checksum_valid = false;
    size_t payload_length = 0;
};

/**
 * UDP解析器
 */
class UDPParser : public BaseParser {
public:
    UDPParser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    [[nodiscard]] const UDPParseResult& get_result() const noexcept {
        return result_;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    UDPParseResult result_;
    
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
};

/**
 * UDP解析器工厂
 */
class UDPParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<UDPParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {17};
    }
};

} // namespace protocol_parser::parsers