#pragma once

#include "../base_parser.hpp"
#include "../../core/buffer_view.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

using namespace protocol_parser::parsers;
using namespace protocol_parser::core;

namespace ProtocolParser::Parsers::Application {

/// WebSocket操作码
enum class WebSocketOpcode : uint8_t {
    CONTINUATION = 0x0,  ///< 继续帧
    TEXT = 0x1,          ///< 文本帧
    BINARY = 0x2,        ///< 二进制帧
    CLOSE = 0x8,         ///< 关闭帧
    PING = 0x9,          ///< Ping帧
    PONG = 0xA,          ///< Pong帧
    RESERVED_3 = 0x3,    ///< 保留
    RESERVED_4 = 0x4,    ///< 保留
    RESERVED_5 = 0x5,    ///< 保留
    RESERVED_6 = 0x6,    ///< 保留
    RESERVED_7 = 0x7,    ///< 保留
    RESERVED_B = 0xB,    ///< 保留
    RESERVED_C = 0xC,    ///< 保留
    RESERVED_D = 0xD,    ///< 保留
    RESERVED_E = 0xE,    ///< 保留
    RESERVED_F = 0xF     ///< 保留
};

/// WebSocket连接状态
enum class WebSocketState {
    HANDSHAKE,      ///< 握手阶段
    CONNECTED,      ///< 已连接
    CLOSING,        ///< 正在关闭
    CLOSED          ///< 已关闭
};

/// WebSocket关闭代码
enum class WebSocketCloseCode : uint16_t {
    NORMAL_CLOSURE = 1000,           ///< 正常关闭
    GOING_AWAY = 1001,               ///< 端点离开
    PROTOCOL_ERROR = 1002,           ///< 协议错误
    UNSUPPORTED_DATA = 1003,         ///< 不支持的数据类型
    NO_STATUS_RECEIVED = 1005,       ///< 未收到状态码
    ABNORMAL_CLOSURE = 1006,         ///< 异常关闭
    INVALID_FRAME_PAYLOAD_DATA = 1007, ///< 无效的帧载荷数据
    POLICY_VIOLATION = 1008,         ///< 策略违规
    MESSAGE_TOO_BIG = 1009,          ///< 消息过大
    MANDATORY_EXTENSION = 1010,      ///< 强制扩展
    INTERNAL_SERVER_ERROR = 1011,    ///< 内部服务器错误
    TLS_HANDSHAKE = 1015            ///< TLS握手失败
};

/// WebSocket帧头信息
struct WebSocketFrameHeader {
    bool fin = false;                    ///< 是否为最后一帧
    bool rsv1 = false;                   ///< 保留位1
    bool rsv2 = false;                   ///< 保留位2
    bool rsv3 = false;                   ///< 保留位3
    WebSocketOpcode opcode = WebSocketOpcode::CONTINUATION; ///< 操作码
    bool mask = false;                   ///< 是否有掩码
    uint64_t payload_length = 0;         ///< 载荷长度
    uint32_t masking_key = 0;            ///< 掩码键
    size_t header_length = 0;            ///< 头部长度
};

/// WebSocket握手信息
struct WebSocketHandshake {
    std::string method;                           ///< HTTP方法
    std::string uri;                             ///< 请求URI
    std::string version;                         ///< HTTP版本
    std::unordered_map<std::string, std::string> headers; ///< HTTP头部
    bool is_valid = false;                       ///< 握手是否有效
    bool is_upgrade = false;                     ///< 是否为升级请求
    std::string websocket_key;                   ///< WebSocket密钥
    std::string websocket_accept;                ///< WebSocket接受值
    std::vector<std::string> protocols;          ///< 子协议列表
    std::vector<std::string> extensions;         ///< 扩展列表
};

/// WebSocket帧信息
struct WebSocketFrame {
    WebSocketFrameHeader header;         ///< 帧头
    std::vector<uint8_t> payload;        ///< 载荷数据
    bool is_valid = false;               ///< 帧是否有效
    std::string text_data;               ///< 文本数据（如果是文本帧）
    WebSocketCloseCode close_code = WebSocketCloseCode::NORMAL_CLOSURE; ///< 关闭代码
    std::string close_reason;            ///< 关闭原因
};

/// WebSocket消息
struct WebSocketMessage {
    WebSocketHandshake handshake;        ///< 握手信息
    WebSocketFrame frame;                ///< 帧信息
    WebSocketState connection_state = WebSocketState::HANDSHAKE; ///< 连接状态
    size_t message_size = 0;             ///< 消息大小
    bool is_handshake = false;           ///< 是否为握手消息
    bool is_secure = false;              ///< 是否为安全连接(WSS)
    
    // 统计信息
    uint64_t frames_sent = 0;            ///< 发送帧数
    uint64_t frames_received = 0;        ///< 接收帧数
    uint64_t bytes_sent = 0;             ///< 发送字节数
    uint64_t bytes_received = 0;         ///< 接收字节数
    uint32_t ping_count = 0;             ///< Ping次数
    uint32_t pong_count = 0;             ///< Pong次数
};

/// WebSocket扩展信息
struct WebSocketExtension {
    std::string name;                    ///< 扩展名称
    std::unordered_map<std::string, std::string> parameters; ///< 扩展参数
};

/**
 * @brief WebSocket协议解析器
 * 
 * 实现WebSocket协议的完整解析功能，支持：
 * - WebSocket握手解析（HTTP升级请求）
 * - 帧格式解析（RFC 6455）
 * - 掩码处理
 * - 分片消息重组
 * - 控制帧处理（Ping/Pong/Close）
 * - 扩展和子协议支持
 * - 安全WebSocket(WSS)检测
 * - 实时流量统计
 * 
 * 特性：
 * - 零拷贝解析
 * - 高性能帧处理
 * - 完整的错误检测
 * - 现代C++23实现
 * - 跨平台兼容
 */
class WebSocketParser : public BaseParser {
public:
    /**
     * @brief 构造函数
     */
    WebSocketParser();
    
    /**
     * @brief 析构函数
     */
    ~WebSocketParser() override = default;
    
    /**
     * @brief 解析WebSocket数据
     * @param context 解析上下文
     * @return 解析结果
     */
    ParseResult parse(ParseContext& context) noexcept override;
    
    /**
     * @brief 获取解析器信息
     * @return 解析器描述信息
     */
    std::string get_protocol_name() const noexcept override;
    
    /**
     * @brief 检测是否为WebSocket握手
     * @param buffer 数据缓冲区
     * @return true if WebSocket handshake
     */
    bool is_websocket_handshake(const BufferView& buffer) const;
    
    /**
     * @brief 检测是否为WebSocket帧
     * @param buffer 数据缓冲区
     * @return true if WebSocket frame
     */
    bool is_websocket_frame(const BufferView& buffer) const;
    
    /**
     * @brief 解析WebSocket握手
     * @param buffer 数据缓冲区
     * @param handshake 握手信息输出
     * @return 解析结果
     */
    ParseResult parse_handshake(const BufferView& buffer, 
                               WebSocketHandshake& handshake) const;
    
    /**
     * @brief 解析WebSocket帧
     * @param buffer 数据缓冲区
     * @param frame 帧信息输出
     * @return 解析结果
     */
    ParseResult parse_frame(const BufferView& buffer, 
                           WebSocketFrame& frame) const;
    
    /**
     * @brief 验证WebSocket密钥
     * @param key WebSocket-Key值
     * @return 计算的WebSocket-Accept值
     */
    std::string calculate_accept_key(const std::string& key) const;
    
    /**
     * @brief 应用掩码
     * @param data 数据
     * @param mask 掩码
     */
    void apply_mask(std::vector<uint8_t>& data, uint32_t mask) const;
    
    /**
     * @brief 验证UTF-8编码
     * @param data 数据
     * @return true if valid UTF-8
     */
    bool is_valid_utf8(const std::vector<uint8_t>& data) const;
    
    /**
     * @brief 解析扩展头
     * @param extension_header 扩展头字符串
     * @return 扩展列表
     */
    std::vector<WebSocketExtension> parse_extensions(const std::string& extension_header) const;
    
    /**
     * @brief 验证帧
     * @param frame 帧信息
     * @return true if valid
     */
    bool validate_frame(const WebSocketFrame& frame) const;
    
    /**
     * @brief 检测是否为控制帧
     * @param opcode 操作码
     * @return true if control frame
     */
    constexpr bool is_control_frame(WebSocketOpcode opcode) const noexcept {
        return static_cast<uint8_t>(opcode) >= 0x8;
    }
    
    /**
     * @brief 检测是否为数据帧
     * @param opcode 操作码
     * @return true if data frame
     */
    constexpr bool is_data_frame(WebSocketOpcode opcode) const noexcept {
        return static_cast<uint8_t>(opcode) <= 0x2;
    }
    
    /**
     * @brief 获取操作码字符串
     * @param opcode 操作码
     * @return 操作码名称
     */
    std::string opcode_to_string(WebSocketOpcode opcode) const;
    
    /**
     * @brief 获取状态字符串
     * @param state 连接状态
     * @return 状态名称
     */
    std::string state_to_string(WebSocketState state) const;
    
    /**
     * @brief 获取关闭代码字符串
     * @param code 关闭代码
     * @return 关闭代码名称
     */
    std::string close_code_to_string(WebSocketCloseCode code) const;

private:
    /**
     * @brief 解析HTTP请求行
     * @param line 请求行
     * @param handshake 握手信息
     * @return 解析结果
     */
    ParseResult parse_request_line(const std::string& line, 
                                  WebSocketHandshake& handshake) const;
    
    /**
     * @brief 解析HTTP头部
     * @param line 头部行
     * @param handshake 握手信息
     * @return 解析结果
     */
    ParseResult parse_header_line(const std::string& line, 
                                 WebSocketHandshake& handshake) const;
    
    /**
     * @brief 解析帧头部
     * @param buffer 数据缓冲区
     * @param header 帧头输出
     * @return 解析结果
     */
    ParseResult parse_frame_header(const BufferView& buffer, 
                                  WebSocketFrameHeader& header) const;
    
    /**
     * @brief 解析载荷长度
     * @param buffer 数据缓冲区
     * @param offset 偏移量
     * @param length 长度输出
     * @return 使用的字节数
     */
    size_t parse_payload_length(const BufferView& buffer, 
                               size_t offset, uint64_t& length) const;
    
    /**
     * @brief 验证握手
     * @param handshake 握手信息
     * @return true if valid
     */
    bool validate_handshake(const WebSocketHandshake& handshake) const;
    
    /**
     * @brief 收集统计信息
     * @param message WebSocket消息
     */
    void collect_statistics(const WebSocketMessage& message) const;

private:
    /// WebSocket GUID常量
    static constexpr const char* WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    /// 最大帧大小
    static constexpr size_t MAX_FRAME_SIZE = 64 * 1024 * 1024; // 64MB
    
    /// 最大头部大小
    static constexpr size_t MAX_HEADER_SIZE = 8192;
    
    /// 支持的WebSocket版本
    static constexpr int WEBSOCKET_VERSION = 13;
};

} // namespace ProtocolParser::Application
