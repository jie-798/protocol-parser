#pragma once

#include "parsers/base_parser.hpp"
#include <cstdint>
#include <vector>
#include <optional>

namespace protocol_parser::parsers {

/**
 * QUIC 包类型
 */
enum class QuicPacketType : uint8_t {
    VersionNegotiation = 0,
    Initial = 1,
    Retry = 2,
    Handshake = 3,
    ZeroRTTProtected = 4,
    ShortHeader = 0x40  // 短包头包
};

/**
 * QUIC 长包头格式
 */
struct QuicLongHeader {
    uint8_t header_form;           // 1 = 长包头
    uint32_t version;              // QUIC 版本
    uint8_t destination_id_length; // 目的连接 ID 长度
    std::vector<uint8_t> destination_id;  // 目的连接 ID
    uint8_t source_id_length;      // 源连接 ID 长度
    std::vector<uint8_t> source_id;       // 源连接 ID
    QuicPacketType packet_type;
    std::optional<uint64_t> packet_number;  // 包号（可选，取决于类型）
};

/**
 * QUIC 短包头格式
 */
struct QuicShortHeader {
    uint8_t header_form;           // 0 = 短包头
    std::vector<uint8_t> connection_id;    // 连接 ID
    uint64_t packet_number;        // 包号
};

/**
 * QUIC 帧类型
 */
enum class QuicFrameType : uint64_t {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckECN = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,  // 实际上 0x08-0x0f 都是流帧
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    ApplicationClose = 0x1d
};

/**
 * QUIC 解析结果
 */
struct QuicParseResult {
    bool is_long_header;
    QuicLongHeader long_header;
    QuicShortHeader short_header;
    std::vector<uint8_t> payload;  // 帧数据

    // 解析的帧
    struct Frame {
        QuicFrameType type;
        std::vector<uint8_t> data;
    };
    std::vector<Frame> frames;
};

/**
 * QUIC 协议解析器
 *
 * QUIC (Quick UDP Internet Connections) 是基于 UDP 的传输协议
 * RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
 *
 * 特性：
 * - 多路复用
 * - 0-RTT 握手
 * - 连接迁移
 * - 内置安全性（TLS 1.3）
 */
class QuicParser : public BaseParser {
public:
    QuicParser();
    ~QuicParser() override = default;

    // BaseParser 接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    /**
     * 获取解析结果
     */
    [[nodiscard]] const QuicParseResult& get_result() const {
        return result_;
    }

    /**
     * 检查是否是 QUIC 包
     * @param buffer UDP 载荷
     */
    [[nodiscard]] static bool is_quic_packet(const BufferView& buffer) noexcept;

private:
    /**
     * 解析长包头
     */
    [[nodiscard]] bool parse_long_header(const BufferView& buffer, size_t& offset);

    /**
     * 解析短包头
     */
    [[nodiscard]] bool parse_short_header(const BufferView& buffer, size_t& offset);

    /**
     * 解析连接 ID
     */
    [[nodiscard]] bool parse_connection_id(const BufferView& buffer,
                                          size_t& offset,
                                          std::vector<uint8_t>& conn_id);

    /**
     * 解析包号
     * QUIC 使用可变长度整数编码
     */
    [[nodiscard]] std::optional<uint64_t> parse_packet_number(
        const BufferView& buffer,
        size_t& offset);

    /**
     * 解析可变长度整数（Variable-Length Integer）
     * RFC 9000 Section 16
     */
    [[nodiscard]] static std::optional<uint64_t> parse_varint(
        const BufferView& buffer,
        size_t& offset);

    /**
     * 解析帧
     */
    [[nodiscard]] bool parse_frames(const BufferView& buffer, size_t offset);

    ProtocolInfo protocol_info_;
    QuicParseResult result_;
    ParserState state_;
    size_t current_offset_;
};

} // namespace protocol_parser::parsers
