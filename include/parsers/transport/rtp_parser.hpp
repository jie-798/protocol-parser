#pragma once

#include "parsers/base_parser.hpp"
#include <cstdint>
#include <vector>
#include <optional>

namespace protocol_parser::parsers {

/**
 * RTP 解析结果
 */
struct RtpParseResult {
    // RTP 头部（RFC 3550）
    uint8_t version;           // V: 版本（2）
    bool padding;              // P: 填充位
    bool extension;            // X: 扩展位
    uint8_t csrc_count;        // CSRC count (CC)
    bool marker;               // M: 标记位
    uint8_t payload_type;      // PT: 载荷类型

    uint16_t sequence_number;  // 序列号
    uint32_t timestamp;        // 时间戳
    uint32_t ssrc;             // 同步源标识符

    // CSRC 列表（如果有）
    std::vector<uint32_t> csrc_list;

    // 扩展头部（如果有）
    struct ExtensionHeader {
        uint16_t profile;
        std::vector<uint32_t> extension_data;
    };
    std::optional<ExtensionHeader> extension_header;

    // 载荷
    std::vector<uint8_t> payload;

    // 常见载荷类型解释
    enum class PayloadType : uint8_t {
        PCMU = 0,          // G.711 μ-law
        GSM = 3,           // GSM
        G723 = 4,          // G.723
        PCMA = 8,          // G.711 A-law
        G722 = 9,          // G.722
        G729 = 18,         // G.729
        MP2T = 33,         // MPEG-2 TS
        H263 = 34,         // H.263
        Dynamic = 96       // 动态类型（96-127）
    };

    [[nodiscard]] const char* get_payload_type_name() const;
};

/**
 * RTCP 包类型
 */
enum class RtcpPacketType : uint8_t {
    SR = 200,   // Sender Report
    RR = 201,   // Receiver Report
    SDES = 202, // Source Description
    BYE = 203,  // Goodbye
    APP = 204   // Application-defined
};

/**
 * RTCP 解析结果
 */
struct RtcpParseResult {
    RtcpPacketType packet_type;
    uint8_t version;
    uint16_t length;
    std::vector<uint8_t> data;
};

/**
 * RTP/RTCP 协议解析器
 *
 * RTP (Real-time Transport Protocol) 用于传输实时媒体数据
 * RTCP (RTP Control Protocol) 用于传输控制信息
 *
 * RFC 3550: https://datatracker.ietf.org/doc/html/rfc3550
 *
 * 应用场景：
 * - VoIP 电话
 * - 视频会议
 * - 流媒体
 * - 在线游戏
 */
class RtpParser : public BaseParser {
public:
    RtpParser();
    ~RtpParser() override = default;

    // BaseParser 接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    /**
     * 获取 RTP 解析结果
     */
    [[nodiscard]] const RtpParseResult& get_rtp_result() const {
        return rtp_result_;
    }

    /**
     * 获取 RTCP 解析结果
     */
    [[nodiscard]] const RtcpParseResult& get_rtcp_result() const {
        return rtcp_result_;
    }

    /**
     * 检查是否是 RTP 包
     */
    [[nodiscard]] static bool is_rtp_packet(const BufferView& buffer) noexcept;

    /**
     * 检查是否是 RTCP 包
     */
    [[nodiscard]] static bool is_rtcp_packet(const BufferView& buffer) noexcept;

private:
    /**
     * 解析 RTP 头部
     */
    [[nodiscard]] bool parse_rtp_header(const BufferView& buffer, size_t& offset);

    /**
     * 解析 RTCP 包
     */
    [[nodiscard]] bool parse_rtcp_packet(const BufferView& buffer);

    /**
     * 解析 CSRC 列表
     */
    [[nodiscard]] bool parse_csrc_list(const BufferView& buffer,
                                       size_t& offset,
                                       uint8_t csrc_count);

    /**
     * 解析扩展头部
     */
    [[nodiscard]] bool parse_extension_header(const BufferView& buffer,
                                             size_t& offset);

    ProtocolInfo protocol_info_;
    RtpParseResult rtp_result_;
    RtcpParseResult rtcp_result_;
    ParserState state_;
    bool is_rtcp_;
};

} // namespace protocol_parser::parsers
