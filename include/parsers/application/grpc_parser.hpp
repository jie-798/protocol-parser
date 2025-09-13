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

/// gRPC消息类型
enum class GRPCMessageType : uint8_t {
    REQUEST = 0,         ///< 请求消息
    RESPONSE = 1,        ///< 响应消息
    ERROR = 2            ///< 错误消息
};

/// gRPC压缩类型
enum class GRPCCompression : uint8_t {
    NONE = 0,           ///< 无压缩
    GZIP = 1,           ///< GZIP压缩
    DEFLATE = 2,        ///< DEFLATE压缩
    SNAPPY = 3,         ///< Snappy压缩
    LZ4 = 4             ///< LZ4压缩
};

/// gRPC状态码
enum class GRPCStatusCode : uint32_t {
    OK = 0,                     ///< 成功
    CANCELLED = 1,              ///< 操作已取消
    UNKNOWN = 2,                ///< 未知错误
    INVALID_ARGUMENT = 3,       ///< 无效参数
    DEADLINE_EXCEEDED = 4,      ///< 超时
    NOT_FOUND = 5,              ///< 未找到
    ALREADY_EXISTS = 6,         ///< 已存在
    PERMISSION_DENIED = 7,      ///< 权限被拒绝
    RESOURCE_EXHAUSTED = 8,     ///< 资源耗尽
    FAILED_PRECONDITION = 9,    ///< 前置条件失败
    ABORTED = 10,               ///< 操作中止
    OUT_OF_RANGE = 11,          ///< 超出范围
    UNIMPLEMENTED = 12,         ///< 未实现
    INTERNAL = 13,              ///< 内部错误
    UNAVAILABLE = 14,           ///< 服务不可用
    DATA_LOSS = 15,             ///< 数据丢失
    UNAUTHENTICATED = 16        ///< 未认证
};

/// gRPC流类型
enum class GRPCStreamType {
    UNARY,              ///< 一元RPC
    CLIENT_STREAMING,   ///< 客户端流
    SERVER_STREAMING,   ///< 服务端流
    BIDIRECTIONAL      ///< 双向流
};

/// HTTP/2帧类型（gRPC基于HTTP/2）
enum class HTTP2FrameType : uint8_t {
    DATA = 0x0,         ///< 数据帧
    HEADERS = 0x1,      ///< 头部帧
    PRIORITY = 0x2,     ///< 优先级帧
    RST_STREAM = 0x3,   ///< 重置流帧
    SETTINGS = 0x4,     ///< 设置帧
    PUSH_PROMISE = 0x5, ///< 推送承诺帧
    PING = 0x6,         ///< Ping帧
    GOAWAY = 0x7,       ///< GoAway帧
    WINDOW_UPDATE = 0x8, ///< 窗口更新帧
    CONTINUATION = 0x9   ///< 继续帧
};

/// gRPC消息头部
struct GRPCMessageHeader {
    bool compressed = false;        ///< 是否压缩
    uint32_t length = 0;           ///< 消息长度
    GRPCCompression compression = GRPCCompression::NONE; ///< 压缩类型
};

/// HTTP/2帧头部
struct HTTP2FrameHeader {
    uint32_t length = 0;           ///< 帧长度
    HTTP2FrameType type = HTTP2FrameType::DATA; ///< 帧类型
    uint8_t flags = 0;             ///< 标志位
    uint32_t stream_id = 0;        ///< 流ID
};

/// gRPC头部字段
struct GRPCHeaders {
    std::string method;                          ///< 方法名
    std::string path;                           ///< 路径
    std::string authority;                      ///< 权威
    std::string content_type;                   ///< 内容类型
    std::string user_agent;                     ///< 用户代理
    std::string grpc_encoding;                  ///< gRPC编码
    std::string grpc_accept_encoding;           ///< gRPC接受编码
    std::string grpc_timeout;                   ///< gRPC超时
    std::string grpc_status;                    ///< gRPC状态
    std::string grpc_message;                   ///< gRPC消息
    std::unordered_map<std::string, std::string> custom_headers; ///< 自定义头部
};

/// gRPC调用信息
struct GRPCCall {
    std::string service;                        ///< 服务名
    std::string method;                         ///< 方法名
    GRPCStreamType stream_type = GRPCStreamType::UNARY; ///< 流类型
    uint32_t stream_id = 0;                     ///< 流ID
    bool is_client_to_server = true;            ///< 是否为客户端到服务端
    
    // 请求信息
    GRPCHeaders request_headers;                ///< 请求头部
    std::vector<uint8_t> request_payload;       ///< 请求载荷
    
    // 响应信息
    GRPCHeaders response_headers;               ///< 响应头部
    std::vector<uint8_t> response_payload;      ///< 响应载荷
    GRPCStatusCode status_code = GRPCStatusCode::OK; ///< 状态码
    std::string status_message;                 ///< 状态消息
    
    // 统计信息
    uint64_t request_size = 0;                  ///< 请求大小
    uint64_t response_size = 0;                 ///< 响应大小
    uint64_t start_time = 0;                    ///< 开始时间
    uint64_t end_time = 0;                      ///< 结束时间
    uint32_t message_count = 0;                 ///< 消息数量
};

/// gRPC消息
struct GRPCMessage {
    GRPCMessageType type = GRPCMessageType::REQUEST; ///< 消息类型
    HTTP2FrameHeader frame_header;              ///< HTTP/2帧头
    GRPCMessageHeader message_header;           ///< gRPC消息头
    GRPCCall call_info;                        ///< 调用信息
    std::vector<uint8_t> payload;              ///< 载荷数据
    bool is_valid = false;                     ///< 消息是否有效
    bool is_end_stream = false;                ///< 是否为流结束
    bool is_end_headers = false;               ///< 是否为头部结束
    size_t total_length = 0;                   ///< 总长度
};

/// gRPC性能指标
struct GRPCMetrics {
    uint64_t total_calls = 0;                  ///< 总调用数
    uint64_t successful_calls = 0;             ///< 成功调用数
    uint64_t failed_calls = 0;                ///< 失败调用数
    uint64_t total_request_bytes = 0;          ///< 总请求字节数
    uint64_t total_response_bytes = 0;         ///< 总响应字节数
    double average_latency = 0.0;              ///< 平均延迟
    uint32_t concurrent_streams = 0;           ///< 并发流数
    std::unordered_map<std::string, uint64_t> method_counts; ///< 方法调用统计
    std::unordered_map<uint32_t, uint64_t> status_counts;    ///< 状态码统计
};

/**
 * @brief gRPC协议解析器
 * 
 * 实现gRPC协议的完整解析功能，支持：
 * - HTTP/2帧解析
 * - gRPC消息格式解析
 * - 头部压缩(HPACK)检测
 * - 流控制分析
 * - 压缩算法检测
 * - 一元和流式RPC检测
 * - 性能指标收集
 * - 错误处理和状态码分析
 * 
 * 特性：
 * - 基于HTTP/2的gRPC协议解析
 * - 支持Protocol Buffers消息检测
 * - 流管理和状态跟踪
 * - 压缩和编码检测
 * - 现代C++23实现
 * - 高性能零拷贝设计
 */
class GRPCParser : public BaseParser {
public:
    /**
     * @brief 构造函数
     */
    GRPCParser();
    
    /**
     * @brief 析构函数
     */
    ~GRPCParser() override = default;
    
    /**
     * @brief 解析gRPC数据
     * @param context 解析上下文
     * @return 解析结果
     */
    ParseResult parse(ParseContext& context) noexcept override;
    
    /**
     * @brief 获取协议信息
     * @return 协议信息结构
     */
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    
    /**
     * @brief 检查是否可以解析给定的缓冲区  
     * @param buffer 数据缓冲区
     * @return 如果可以解析返回true，否则返回false
     */
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    
    /**
     * @brief 重置解析器状态
     */
    void reset() noexcept override;
    
    /**
     * @brief 检测是否为gRPC流量
     * @param buffer 数据缓冲区
     * @return true if gRPC traffic
     */
    bool is_grpc_traffic(const protocol_parser::core::BufferView& buffer) const;
    
    /**
     * @brief 检测是否为HTTP/2连接前导
     * @param buffer 数据缓冲区
     * @return true if HTTP/2 preface
     */
    bool is_http2_preface(const protocol_parser::core::BufferView& buffer) const;
    
    /**
     * @brief 解析HTTP/2帧
     * @param buffer 数据缓冲区
     * @param message gRPC消息输出
     * @return 解析结果
     */
    ParseResult parse_http2_frame(const protocol_parser::core::BufferView& buffer, 
                                 GRPCMessage& message) const;
    
    /**
     * @brief 解析gRPC消息
     * @param buffer 数据缓冲区
     * @param message gRPC消息输出
     * @return 解析结果
     */
    ParseResult parse_grpc_message(const protocol_parser::core::BufferView& buffer, 
                                  GRPCMessage& message) const;
    
    /**
     * @brief 解析HEADERS帧
     * @param buffer 数据缓冲区
     * @param message gRPC消息输出
     * @return 解析结果
     */
    ParseResult parse_headers_frame(const protocol_parser::core::BufferView& buffer, 
                                   GRPCMessage& message) const;
    
    /**
     * @brief 解析DATA帧
     * @param buffer 数据缓冲区
     * @param message gRPC消息输出
     * @return 解析结果
     */
    ParseResult parse_data_frame(const protocol_parser::core::BufferView& buffer, 
                                GRPCMessage& message) const;
    
    /**
     * @brief 解析gRPC消息头部
     * @param buffer 数据缓冲区
     * @param header 消息头部输出
     * @return 解析结果
     */
    ParseResult parse_message_header(const protocol_parser::core::BufferView& buffer, 
                                    GRPCMessageHeader& header) const;
    
    /**
     * @brief 检测压缩类型
     * @param data 数据
     * @return 压缩类型
     */
    GRPCCompression detect_compression(const std::vector<uint8_t>& data) const;
    
    /**
     * @brief 检测是否为Protocol Buffers消息
     * @param data 数据
     * @return true if protobuf message
     */
    bool is_protobuf_message(const std::vector<uint8_t>& data) const;
    
    /**
     * @brief 提取服务和方法名
     * @param path 路径
     * @param service 服务名输出
     * @param method 方法名输出
     * @return true if successful
     */
    bool extract_service_method(const std::string& path, 
                               std::string& service, 
                               std::string& method) const;
    
    /**
     * @brief 验证gRPC消息
     * @param message gRPC消息
     * @return true if valid
     */
    bool validate_grpc_message(const GRPCMessage& message) const;
    
    /**
     * @brief 获取HTTP/2帧类型字符串
     * @param type 帧类型
     * @return 帧类型名称
     */
    std::string frame_type_to_string(HTTP2FrameType type) const;
    
    /**
     * @brief 获取gRPC状态码字符串
     * @param code 状态码
     * @return 状态码名称
     */
    std::string status_code_to_string(GRPCStatusCode code) const;
    
    /**
     * @brief 获取流类型字符串
     * @param type 流类型
     * @return 流类型名称
     */
    std::string stream_type_to_string(GRPCStreamType type) const;
    
    /**
     * @brief 获取压缩类型字符串
     * @param compression 压缩类型
     * @return 压缩类型名称
     */
    std::string compression_to_string(GRPCCompression compression) const;

private:
    /**
     * @brief 解析HTTP/2帧头部
     * @param buffer 数据缓冲区
     * @param header 帧头部输出
     * @return 解析结果
     */
    ParseResult parse_frame_header(const protocol_parser::core::BufferView& buffer, 
                                  HTTP2FrameHeader& header) const;
    
    /**
     * @brief 简化的HPACK解码
     * @param data 编码数据
     * @param headers 头部输出
     * @return 解析结果
     */
    ParseResult simple_hpack_decode(const std::vector<uint8_t>& data, 
                                   GRPCHeaders& headers) const;
    
    /**
     * @brief 解析伪头部
     * @param name 头部名称
     * @param value 头部值
     * @param headers 头部信息
     */
    void parse_pseudo_header(const std::string& name, 
                            const std::string& value, 
                            GRPCHeaders& headers) const;
    
    /**
     * @brief 检测流类型
     * @param headers 请求头部
     * @return 流类型
     */
    GRPCStreamType detect_stream_type(const GRPCHeaders& headers) const;
    
    /**
     * @brief 收集性能指标
     * @param message gRPC消息
     */
    void collect_metrics(const GRPCMessage& message) const;

private:
    /// HTTP/2连接前导
    static constexpr const char* HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    
    /// gRPC内容类型
    static constexpr const char* GRPC_CONTENT_TYPE = "application/grpc";
    
    /// 最大帧大小
    static constexpr size_t MAX_FRAME_SIZE = 16384; // 16KB
    
    /// 最大头部表大小
    static constexpr size_t MAX_HEADER_TABLE_SIZE = 4096;
    
    /// 性能指标
    mutable GRPCMetrics metrics_;
};

} // namespace ProtocolParser::Application