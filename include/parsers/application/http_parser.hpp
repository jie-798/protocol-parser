#pragma once

#include "../base_parser.hpp"
#include "core/buffer_view.hpp" // BufferView for zero-copy body
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace protocol_parser::parsers {

// HTTP Method enumeration
enum class HTTPMethod {
    GET,
    POST,
    PUT,
    DELETE_METHOD,
    HEAD,
    OPTIONS,
    PATCH,
    TRACE,
    CONNECT,
    UNKNOWN
};

// HTTP Version enumeration
enum class HTTPVersion {
    HTTP_1_0,
    HTTP_1_1,
    HTTP_2_0,
    UNKNOWN
};

// HTTP Message Type enumeration
enum class HTTPMessageType {
    REQUEST,
    RESPONSE,
    UNKNOWN
};

// 大小写不敏感的哈希器（避免 to_lower 拷贝）
struct CaseInsensitiveHash {
    size_t operator()(const std::string& key) const noexcept;
};

struct CaseInsensitiveEqual {
    bool operator()(const std::string& lhs, const std::string& rhs) const noexcept;
};

using HeaderMap = std::unordered_map<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;

// HTTP Request structure
struct HTTPRequest {
    HTTPMethod method;
    std::string uri;
    HTTPVersion version;
    HeaderMap headers;
    core::BufferView body;   // 零拷贝：指向原始缓冲区
};

// HTTP Response structure
struct HTTPResponse {
    HTTPVersion version;
    uint16_t status_code;
    std::string reason_phrase;
    HeaderMap headers;
    core::BufferView body;   // 零拷贝：指向原始缓冲区
};

// HTTP Message structure
struct HTTPMessage {
    HTTPMessageType type = HTTPMessageType::UNKNOWN;
    HTTPRequest request;
    HTTPResponse response;

    HTTPMessage() = default;
    ~HTTPMessage() = default;
    HTTPMessage(const HTTPMessage&) = default;
    HTTPMessage& operator=(const HTTPMessage&) = default;
    HTTPMessage(HTTPMessage&&) = default;
    HTTPMessage& operator=(HTTPMessage&&) = default;
};

class HTTPParser : public BaseParser {
public:
    HTTPParser() = default;
    ~HTTPParser() = default;

    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    void reset() noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept;

    // HTTP-specific methods
    [[nodiscard]] HTTPMessageType get_message_type() const;
    [[nodiscard]] bool is_request() const;
    [[nodiscard]] bool is_response() const;
    [[nodiscard]] bool is_complete() const;

    // Request-specific methods
    [[nodiscard]] HTTPMethod get_method() const;
    [[nodiscard]] std::string get_uri() const;

    // Response-specific methods
    [[nodiscard]] uint16_t get_status_code() const;
    [[nodiscard]] std::string get_reason_phrase() const;

    // Common methods
    [[nodiscard]] HTTPVersion get_version() const;
    [[nodiscard]] std::string get_header(const std::string& name) const;
    [[nodiscard]] const HeaderMap& get_headers() const;
    [[nodiscard]] core::BufferView get_body() const noexcept;
    [[nodiscard]] size_t get_content_length() const;
    [[nodiscard]] bool is_chunked_encoding() const;
    [[nodiscard]] bool is_keep_alive() const;

    // Utility methods
    [[nodiscard]] static std::string method_to_string(HTTPMethod method);
    [[nodiscard]] static HTTPMethod string_to_method(const std::string& method_str);
    [[nodiscard]] static std::string version_to_string(HTTPVersion version);
    [[nodiscard]] static HTTPVersion string_to_version(const std::string& version_str);

private:
    HTTPMessage http_message_;
    bool is_complete_ = false;
    size_t expected_body_length_ = 0;
    bool is_chunked_ = false;
    std::string error_message_;

    // 对传入缓冲区零拷贝解析
    [[nodiscard]] ParseResult parse_request_line(std::string_view line);
    [[nodiscard]] ParseResult parse_status_line(std::string_view line);
    [[nodiscard]] ParseResult parse_headers(const BufferView& buffer, size_t headers_end);
    [[nodiscard]] ParseResult parse_body(const BufferView& buffer, size_t body_start);
    [[nodiscard]] ParseResult parse_chunked_body(const BufferView& buffer, size_t start_pos);

    [[nodiscard]] size_t find_headers_end(const BufferView& buffer) const noexcept;
    [[nodiscard]] static std::string_view trim_sv(std::string_view str) noexcept;
    [[nodiscard]] bool validate_http_message(const BufferView& buffer) const noexcept;
};

} // namespace protocol_parser::parsers
