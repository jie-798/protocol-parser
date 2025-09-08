#pragma once

#include "../base_parser.hpp"
#include <string>
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

// HTTP Request structure
struct HTTPRequest {
    HTTPMethod method;
    std::string uri;
    HTTPVersion version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

// HTTP Response structure
struct HTTPResponse {
    HTTPVersion version;
    uint16_t status_code;
    std::string reason_phrase;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
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
    [[nodiscard]] const std::unordered_map<std::string, std::string>& get_headers() const;
    [[nodiscard]] std::string get_body() const;
    [[nodiscard]] size_t get_content_length() const;
    [[nodiscard]] bool is_chunked_encoding() const;
    [[nodiscard]] bool is_keep_alive() const;

    // Utility methods
    [[nodiscard]] std::string method_to_string(HTTPMethod method) const;
    [[nodiscard]] HTTPMethod string_to_method(const std::string& method_str) const;
    [[nodiscard]] std::string version_to_string(HTTPVersion version) const;
    [[nodiscard]] HTTPVersion string_to_version(const std::string& version_str) const;

private:
    HTTPMessage http_message_;
    bool is_complete_ = false;
    size_t expected_body_length_ = 0;
    bool is_chunked_ = false;
    std::string error_message_;

    // Private parsing methods
    [[nodiscard]] ParseResult parse_request_line(const std::string& line);
    [[nodiscard]] ParseResult parse_status_line(const std::string& line);
    [[nodiscard]] ParseResult parse_headers(const std::vector<std::string>& header_lines);
    [[nodiscard]] ParseResult parse_body(const BufferView& buffer, size_t headers_end_pos);
    [[nodiscard]] ParseResult parse_chunked_body(const BufferView& buffer, size_t start_pos);

    [[nodiscard]] std::vector<std::string> split_lines(const std::string& data) const;
    [[nodiscard]] size_t find_headers_end(const BufferView& buffer) const;
    [[nodiscard]] std::string trim(const std::string& str) const;
    [[nodiscard]] std::string to_lower(const std::string& str) const;
    [[nodiscard]] bool validate_http_message(const BufferView& buffer) const;
};

} // namespace protocol_parser::parsers