#pragma once

#include "parsers/base_parser.hpp"
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace protocol_parser::parsers {

/**
 * SIP 方法类型
 */
enum class SipMethod : uint8_t {
    INVITE,
    ACK,
    BYE,
    CANCEL,
    REGISTER,
    OPTIONS,
    PRACK,
    SUBSCRIBE,
    NOTIFY,
    PUBLISH,
    INFO,
    REFER,
    MESSAGE,
    UPDATE
};

/**
 * SIP 响应状态码
 */
enum class SipResponseCode : uint16_t {
    // 1xx: 临时响应
    Trying = 100,
    Ringing = 180,
    CallIsBeingForwarded = 181,
    Queued = 182,
    SessionProgress = 183,

    // 2xx: 成功
    OK = 200,
    Accepted = 202,

    // 3xx: 重定向
    MultipleChoices = 300,
    MovedPermanently = 301,
    MovedTemporarily = 302,
    UseProxy = 305,
    AlternativeService = 380,

    // 4xx: 客户端错误
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Gone = 410,
    RequestEntityTooLarge = 413,
    RequestURITooLong = 414,
    UnsupportedMediaType = 415,
    UnsupportedURIScheme = 416,
    UnknownResourcePriority = 417,
    BadExtension = 420,
    ExtensionRequired = 421,
    SessionIntervalTooSmall = 422,
    IntervalTooBrief = 423,
    BadLocationInformation = 424,
    UseIdentityHeader = 428,
    ProvideReferrerIdentity = 429,
    FlowFailed = 430,
    AnonymityDisallowed = 433,
    BadIdentityInfo = 436,
    UnsupportedCredential = 437,
    InvalidIdentityHeader = 438,
    FirstHopLacksOutboundSupport = 439,
    MaxBreadthExceeded = 440,
    BadInfoPackage = 469,
    ConsentNeeded = 470,
    TemporarilyUnavailable = 480,
    CallTransactionDoesNotExist = 481,
    LoopDetected = 482,
    TooManyHops = 483,
    AddressIncomplete = 484,
    Ambiguous = 485,
    BusyHere = 486,
    RequestTerminated = 487,
    NotAcceptableHere = 488,
    BadEvent = 489,
    RequestPending = 491,
    Undecipherable = 493,

    // 5xx: 服务器错误
    ServerInternalError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    ServerTimeout = 504,
    VersionNotSupported = 505,
    MessageTooLarge = 513,
    PushNotificationServiceNotSupported = 555,
    PreconditionFailure = 580,

    // 6xx: 全局失败
    BusyEverywhere = 600,
    Decline = 603,
    DoesNotExistAnywhere = 604,
    GlobalNotAcceptable = 606,
    Unwanted = 607
};

/**
 * SIP 头部字段
 */
struct SipHeader {
    std::string name;
    std::string value;
};

/**
 * SIP 消息体
 */
struct SipBody {
    std::string content_type;
    std::vector<uint8_t> data;
};

/**
 * SIP 解析结果
 */
struct SipParseResult {
    bool is_request;
    SipMethod method;
    SipResponseCode response_code;

    // 请求行
    std::string request_uri;
    std::string sip_version;  // SIP/2.0

    // 响应行
    std::string reason_phrase;

    // 头部
    std::vector<SipHeader> headers;

    // 关键头部（快速访问）
    std::string from;
    std::string to;
    std::string call_id;
    std::string cseq;
    std::string via;
    std::string contact;
    std::string content_type;
    size_t content_length;

    // 消息体
    std::optional<SipBody> body;
};

/**
 * SIP 协议解析器
 *
 * SIP (Session Initiation Protocol) 是用于建立、修改和终止多媒体会话的信令协议
 * RFC 3261: https://datatracker.ietf.org/doc/html/rfc3261
 *
 * 应用场景：
 * - VoIP 电话
 * - 视频会议
 * - 即时消息
 * - 在线游戏
 */
class SipParser : public BaseParser {
public:
    SipParser();
    ~SipParser() override = default;

    // BaseParser 接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    /**
     * 获取解析结果
     */
    [[nodiscard]] const SipParseResult& get_result() const {
        return result_;
    }

    /**
     * 检查是否是 SIP 消息
     */
    [[nodiscard]] static bool is_sip_message(const BufferView& buffer) noexcept;

private:
    /**
     * 解析请求行
     * METHOD Request-URI SIP-Version
     */
    [[nodiscard]] bool parse_request_line(const std::string& line);

    /**
     * 解析响应行
     * SIP-Version Status-Code Reason-Phrase
     */
    [[nodiscard]] bool parse_response_line(const std::string& line);

    /**
     * 解析头部
     */
    [[nodiscard]] bool parse_headers(const std::vector<std::string>& lines);

    /**
     * 解析消息体
     */
    [[nodiscard]] bool parse_body(const BufferView& buffer, size_t offset);

    /**
     * 查找头部值
     */
    [[nodiscard]] std::optional<std::string> find_header(
        const std::string& name) const;

    /**
     * 解析 SDP（会话描述协议）
     */
    void parse_sdp(const std::string& sdp);

    ProtocolInfo protocol_info_;
    SipParseResult result_;
    ParserState state_;
    std::vector<std::string> header_lines_;
};

} // namespace protocol_parser::parsers
