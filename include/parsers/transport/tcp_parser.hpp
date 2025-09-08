#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <vector>
#include <array>
#include <cstdint>

namespace protocol_parser::parsers {

/**
 * TCP标志位
 */
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
    constexpr uint8_t ECE = 0x40;
    constexpr uint8_t CWR = 0x80;
}

/**
 * TCP选项类型
 */
namespace TCPOptionType {
    constexpr uint8_t END_OF_OPTIONS = 0;
    constexpr uint8_t NO_OPERATION = 1;
    constexpr uint8_t MSS = 2;
    constexpr uint8_t WINDOW_SCALE = 3;
    constexpr uint8_t SACK_PERMITTED = 4;
    constexpr uint8_t SACK = 5;
    constexpr uint8_t TIMESTAMP = 8;
}

/**
 * TCP选项结构
 */
struct TCPOption {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> data;
};

/**
 * TCP头部结构
 */
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    
    static constexpr size_t MIN_SIZE = 20;
    
    [[nodiscard]] uint8_t get_data_offset() const noexcept {
        return (data_offset_flags >> 4) & 0x0F;
    }
    
    [[nodiscard]] bool has_flag(uint8_t flag) const noexcept {
        return (flags & flag) != 0;
    }
};

/**
 * TCP解析结果
 */
struct TCPParseResult {
    TCPHeader header;
    std::vector<TCPOption> options;
    core::BufferView payload;
    bool checksum_valid = false;
    size_t payload_length = 0;
};

/**
 * TCP解析器
 */
class TCPParser : public BaseParser {
public:
    TCPParser();
    
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    
    [[nodiscard]] const TCPParseResult& get_result() const noexcept {
        return result_;
    }
    
private:
    static const ProtocolInfo protocol_info_;
    TCPParseResult result_;
    
    ParseResult parse_header(ParseContext& context) noexcept;
    ParseResult parse_options(ParseContext& context) noexcept;
    ParseResult parse_payload(ParseContext& context) noexcept;
};

/**
 * TCP解析器工厂
 */
class TCPParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<TCPParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const override {
        return {6};
    }
};

} // namespace protocol_parser::parsers