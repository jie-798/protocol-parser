#include "../../../include/parsers/application/http_parser.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cctype>   // tolower for hash
#include <string_view>

namespace protocol_parser::parsers {

// =============================================================================
// 大小写不敏感的哈希 / 比较
// =============================================================================

size_t CaseInsensitiveHash::operator()(const std::string& key) const noexcept {
    // 对每个字符做 tolower 后混合哈希
    size_t h = 0;
    for (unsigned char c : key) {
        h = h * 131 + static_cast<size_t>(std::tolower(c));
    }
    return h;
}

bool CaseInsensitiveEqual::operator()(const std::string& lhs, const std::string& rhs) const noexcept {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(lhs[i])) !=
            std::tolower(static_cast<unsigned char>(rhs[i]))) {
            return false;
        }
    }
    return true;
}

// =============================================================================
// 协议信息（静态，避免每次 get_protocol_info 构造）
// =============================================================================

namespace {
    const ProtocolInfo kHTTPProtocolInfo{
        "HTTP",     // name
        80,         // type (HTTP port)
        0,          // header_size (variable)
        16,         // min_packet_size
        65535       // max_packet_size
    };
}

// =============================================================================
// parse — 主入口
// =============================================================================

ParseResult HTTPParser::parse(ParseContext& context) noexcept {
    if (!validate_http_message(context.buffer)) {
        return ParseResult::InvalidFormat;
    }

    reset();

    // 1. 查找 \r\n\r\n 头部结束位置
    const size_t headers_end = find_headers_end(context.buffer);
    if (headers_end == SIZE_MAX) {
        return ParseResult::NeedMoreData;
    }
    constexpr size_t kCRLFCRLF_LEN = 4;

    // 2. 从缓冲区直接读取第一行（string_view 零拷贝）
    const auto buffer_data = reinterpret_cast<const char*>(context.buffer.data());
    const size_t first_line_len = [&]{
        // 第一行以 \r\n 结束
        for (size_t i = 0; i < headers_end; ++i) {
            if (buffer_data[i] == '\r' && i + 1 < headers_end && buffer_data[i + 1] == '\n') {
                return i;
            }
        }
        return headers_end;
    }();

    const std::string_view first_line(buffer_data, first_line_len);

    // 判断是请求还是响应
    ParseResult status;
    if (first_line.starts_with("HTTP/")) {
        http_message_.type = HTTPMessageType::RESPONSE;
        status = parse_status_line(first_line);
    } else {
        http_message_.type = HTTPMessageType::REQUEST;
        status = parse_request_line(first_line);
    }
    if (status != ParseResult::Success) {
        return status;
    }

    // 3. 解析头部（直接从 buffer 中提取 string_view）
    //    跳过第一行及后续 \r\n
    size_t header_start = first_line_len;
    if (header_start + 2 <= headers_end) {
        header_start += 2; // 跳过第一行的 \r\n
    }
    status = parse_headers(context.buffer.substr(header_start, headers_end - header_start), 0);
    if (status != ParseResult::Success) {
        return status;
    }

    // 4. 解析 body
    status = parse_body(context.buffer, headers_end + kCRLFCRLF_LEN);

    // 5. 存入 metadata
    context.metadata["http_message_type"] = static_cast<int>(http_message_.type);
    context.metadata["http_version"] = version_to_string(get_version());

    if (is_request()) {
        context.metadata["http_method"] = method_to_string(get_method());
        context.metadata["http_uri"] = get_uri();
    } else if (is_response()) {
        context.metadata["http_status_code"] = static_cast<int>(get_status_code());
        context.metadata["http_reason_phrase"] = get_reason_phrase();
    }

    context.metadata["http_content_length"] = static_cast<uint64_t>(get_content_length());
    context.metadata["http_is_chunked"] = is_chunked_encoding();
    context.metadata["http_is_keep_alive"] = is_keep_alive();

    auto content_type = get_header("content-type");
    if (!content_type.empty()) {
        context.metadata["http_content_type"] = content_type;
    }

    auto user_agent = get_header("user-agent");
    if (!user_agent.empty()) {
        context.metadata["http_user_agent"] = user_agent;
    }

    auto host = get_header("host");
    if (!host.empty()) {
        context.metadata["http_host"] = host;
    }

    return status;
}

// =============================================================================
// find_headers_end — 使用 SIMD 加速搜索 \r\n\r\n
// =============================================================================

size_t HTTPParser::find_headers_end(const BufferView& buffer) const noexcept {
    // 用 find_simd 查找 "\r\n\r\n" 模式
    static constexpr char kCRLFCRLF[] = {'\r', '\n', '\r', '\n'};
    return buffer.find_simd(kCRLFCRLF, 4);
}

// =============================================================================
// parse_request_line — 解析 "METHOD URI VERSION"
// =============================================================================

ParseResult HTTPParser::parse_request_line(std::string_view line) {
    // 跳过开头的空白
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);

    // Method
    const size_t sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) return ParseResult::InvalidFormat;
    const std::string method_str(line.substr(0, sp1));
    http_message_.request.method = string_to_method(method_str);
    if (http_message_.request.method == HTTPMethod::UNKNOWN) {
        return ParseResult::InvalidFormat;
    }
    line.remove_prefix(sp1 + 1);

    // URI
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
    const size_t sp2 = line.find(' ');
    http_message_.request.uri = std::string(sp2 == std::string_view::npos ? line : line.substr(0, sp2));
    if (sp2 == std::string_view::npos) return ParseResult::InvalidFormat;
    line.remove_prefix(sp2 + 1);

    // Version
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
    const std::string version_str(line);
    http_message_.request.version = string_to_version(version_str);
    if (http_message_.request.version == HTTPVersion::UNKNOWN) {
        return ParseResult::InvalidFormat;
    }
    return ParseResult::Success;
}

// =============================================================================
// parse_status_line — 解析 "VERSION STATUS_CODE REASON"
// =============================================================================

ParseResult HTTPParser::parse_status_line(std::string_view line) {
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);

    // Version
    const size_t sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) return ParseResult::InvalidFormat;
    const std::string version_str(line.substr(0, sp1));
    http_message_.response.version = string_to_version(version_str);
    line.remove_prefix(sp1 + 1);

    // Status code
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
    const size_t sp2 = line.find(' ');
    const std::string status_str(sp2 == std::string_view::npos ? line : line.substr(0, sp2));

    char* end = nullptr;
    const long sc = std::strtol(status_str.data(), &end, 10);
    if (end == status_str.data() || sc < 100 || sc > 599) {
        return ParseResult::InvalidFormat;
    }
    http_message_.response.status_code = static_cast<uint16_t>(sc);

    // Reason phrase (rest of line)
    if (sp2 != std::string_view::npos) {
        auto reason = line.substr(sp2 + 1);
        reason = trim_sv(reason);
        http_message_.response.reason_phrase = std::string(reason);
    }

    if (http_message_.response.version == HTTPVersion::UNKNOWN) {
        return ParseResult::InvalidFormat;
    }
    return ParseResult::Success;
}

// =============================================================================
// parse_headers — 直接从缓冲区视图解析（零拷贝）
// =============================================================================

ParseResult HTTPParser::parse_headers(const BufferView& buffer, size_t /*unused*/) {
    auto& headers = (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.headers
        : http_message_.response.headers;

    const auto* data = reinterpret_cast<const char*>(buffer.data());
    const size_t size = buffer.size();
    size_t pos = 0;

    while (pos < size) {
        // 找到行尾 \r\n
        size_t line_end = pos;
        while (line_end < size && !(data[line_end] == '\r' && line_end + 1 < size && data[line_end + 1] == '\n')) {
            ++line_end;
        }
        if (line_end >= size) break;

        const std::string_view line(data + pos, line_end - pos);
        pos = line_end + 2; // 跳过 \r\n

        if (line.empty()) continue;

        // 解析 "Name: Value"
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;

        const std::string name(line.substr(0, colon));
        const std::string_view raw_value = trim_sv(line.substr(colon + 1));
        const std::string value(raw_value);
        if (!name.empty()) {
            headers[name] = value;
        }
    }

    // 确定 body 长度
    auto content_length_iter = headers.find("content-length");
    auto transfer_encoding_iter = headers.find("transfer-encoding");

    if (transfer_encoding_iter != headers.end()) {
        const auto& te = transfer_encoding_iter->second;
        if (te.find("chunked") != std::string::npos ||
            te.find("CHUNKED") != std::string::npos) {
            is_chunked_ = true;
        }
    }

    if (!is_chunked_ && content_length_iter != headers.end()) {
        char* end = nullptr;
        const unsigned long long cl = std::strtoull(content_length_iter->second.c_str(), &end, 10);
        if (end != content_length_iter->second.c_str()) {
            expected_body_length_ = static_cast<size_t>(cl);
        }
    }

    return ParseResult::Success;
}

// =============================================================================
// parse_body — 零拷贝 body
// =============================================================================

ParseResult HTTPParser::parse_body(const BufferView& buffer, size_t body_start) {
    if (body_start >= buffer.size()) {
        is_complete_ = true;
        return ParseResult::Success;
    }

    if (is_chunked_) {
        return parse_chunked_body(buffer, body_start);
    }

    // Fixed-length body
    const size_t available = buffer.size() - body_start;

    if (expected_body_length_ == 0) {
        is_complete_ = true;
        return ParseResult::Success;
    }

    if (available < expected_body_length_) {
        return ParseResult::NeedMoreData;
    }

    // 零拷贝：直接引用原始缓冲区
    auto body_view = buffer.substr(body_start, expected_body_length_);
    if (http_message_.type == HTTPMessageType::REQUEST) {
        http_message_.request.body = body_view;
    } else {
        http_message_.response.body = body_view;
    }

    is_complete_ = true;
    return ParseResult::Success;
}

// =============================================================================
// parse_chunked_body — 零拷贝分块 body
// =============================================================================

ParseResult HTTPParser::parse_chunked_body(const BufferView& buffer, size_t start_pos) {
    // 先计算总大小，再从原始缓冲区提取视图
    size_t pos = start_pos;
    const auto* data = reinterpret_cast<const char*>(buffer.data());
    const size_t buf_size = buffer.size();

    size_t total_chunk_size = 0;

    while (pos < buf_size) {
        // 查找 \r\n 结束的块大小行
        size_t line_end = pos;
        while (line_end < buf_size - 1 &&
               !(data[line_end] == '\r' && data[line_end + 1] == '\n')) {
            ++line_end;
        }
        if (line_end >= buf_size - 1) {
            return ParseResult::NeedMoreData;
        }

        const std::string_view chunk_size_str(data + pos, line_end - pos);

        // 解析十六进制块大小
        char* end = nullptr;
        const unsigned long long csize = std::strtoull(chunk_size_str.data(), &end, 16);
        if (end == chunk_size_str.data()) {
            return ParseResult::InvalidFormat;
        }
        const size_t chunk_size = static_cast<size_t>(csize);

        pos = line_end + 2; // 跳过 \r\n

        if (chunk_size == 0) break;

        if (pos + chunk_size + 2 > buf_size) {
            return ParseResult::NeedMoreData;
        }

        total_chunk_size += chunk_size;
        pos += chunk_size + 2;
    }

    // 零拷贝 body 视图
    auto body_view = buffer.substr(start_pos, total_chunk_size);
    if (http_message_.type == HTTPMessageType::REQUEST) {
        http_message_.request.body = body_view;
    } else {
        http_message_.response.body = body_view;
    }

    is_complete_ = true;
    return ParseResult::Success;
}

// =============================================================================
// 工具函数
// =============================================================================

std::string_view HTTPParser::trim_sv(std::string_view str) noexcept {
    while (!str.empty() && (str.front() == ' ' || str.front() == '\t' || str.front() == '\r' || str.front() == '\n')) {
        str.remove_prefix(1);
    }
    while (!str.empty() && (str.back() == ' ' || str.back() == '\t' || str.back() == '\r' || str.back() == '\n')) {
        str.remove_suffix(1);
    }
    return str;
}

bool HTTPParser::validate_http_message(const BufferView& buffer) const noexcept {
    if (buffer.size() < 16) return false;

    // 零拷贝：检查前 8 字节中的 HTTP 签名
    const auto* data = reinterpret_cast<const char*>(buffer.data());
    const std::string_view start(data, std::min(buffer.size(), size_t{8}));

    return start.starts_with("HTTP/") ||
           start.starts_with("GET ") ||
           start.starts_with("POST ") ||
           start.starts_with("PUT ") ||
           start.starts_with("DELETE ") ||
           start.starts_with("HEAD ") ||
           start.starts_with("OPTIONS ") ||
           start.starts_with("PATCH ");
}

// =============================================================================
// Getter 实现
// =============================================================================

HTTPMethod HTTPParser::get_method() const {
    return (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.method : HTTPMethod::UNKNOWN;
}

std::string HTTPParser::get_uri() const {
    return (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.uri : "";
}

uint16_t HTTPParser::get_status_code() const {
    return (http_message_.type == HTTPMessageType::RESPONSE)
        ? http_message_.response.status_code : 0;
}

std::string HTTPParser::get_reason_phrase() const {
    return (http_message_.type == HTTPMessageType::RESPONSE)
        ? http_message_.response.reason_phrase : "";
}

HTTPVersion HTTPParser::get_version() const {
    return (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.version
        : (http_message_.type == HTTPMessageType::RESPONSE)
            ? http_message_.response.version : HTTPVersion::UNKNOWN;
}

std::string HTTPParser::get_header(const std::string& name) const {
    const auto& headers = (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.headers : http_message_.response.headers;

    auto it = headers.find(name);
    return (it != headers.end()) ? it->second : "";
}

const HeaderMap& HTTPParser::get_headers() const {
    static const HeaderMap empty_headers;

    if (http_message_.type == HTTPMessageType::REQUEST) {
        return http_message_.request.headers;
    } else if (http_message_.type == HTTPMessageType::RESPONSE) {
        return http_message_.response.headers;
    }
    return empty_headers;
}

core::BufferView HTTPParser::get_body() const noexcept {
    return (http_message_.type == HTTPMessageType::REQUEST)
        ? http_message_.request.body
        : (http_message_.type == HTTPMessageType::RESPONSE)
            ? http_message_.response.body : core::BufferView{};
}

size_t HTTPParser::get_content_length() const {
    auto content_length_str = get_header("content-length");
    if (content_length_str.empty()) return 0;
    char* end = nullptr;
    const auto cl = std::strtoull(content_length_str.c_str(), &end, 10);
    return (end != content_length_str.c_str()) ? static_cast<size_t>(cl) : 0;
}

bool HTTPParser::is_chunked_encoding() const {
    auto transfer_encoding = get_header("transfer-encoding");
    return transfer_encoding.find("chunked") != std::string::npos ||
           transfer_encoding.find("CHUNKED") != std::string::npos;
}

bool HTTPParser::is_keep_alive() const {
    auto connection = get_header("connection");
    return connection.find("keep-alive") != std::string::npos ||
           connection.find("Keep-Alive") != std::string::npos;
}

// =============================================================================
// Utility method implementations
// =============================================================================

std::string HTTPParser::method_to_string(HTTPMethod method) {
    switch (method) {
        case HTTPMethod::GET: return "GET";
        case HTTPMethod::POST: return "POST";
        case HTTPMethod::PUT: return "PUT";
        case HTTPMethod::DELETE_METHOD: return "DELETE";
        case HTTPMethod::HEAD: return "HEAD";
        case HTTPMethod::OPTIONS: return "OPTIONS";
        case HTTPMethod::PATCH: return "PATCH";
        case HTTPMethod::TRACE: return "TRACE";
        case HTTPMethod::CONNECT: return "CONNECT";
        default: return "UNKNOWN";
    }
}

HTTPMethod HTTPParser::string_to_method(const std::string& method_str) {
    if (method_str == "GET") return HTTPMethod::GET;
    if (method_str == "POST") return HTTPMethod::POST;
    if (method_str == "PUT") return HTTPMethod::PUT;
    if (method_str == "DELETE") return HTTPMethod::DELETE_METHOD;
    if (method_str == "HEAD") return HTTPMethod::HEAD;
    if (method_str == "OPTIONS") return HTTPMethod::OPTIONS;
    if (method_str == "PATCH") return HTTPMethod::PATCH;
    if (method_str == "TRACE") return HTTPMethod::TRACE;
    if (method_str == "CONNECT") return HTTPMethod::CONNECT;
    return HTTPMethod::UNKNOWN;
}

std::string HTTPParser::version_to_string(HTTPVersion version) {
    switch (version) {
        case HTTPVersion::HTTP_1_0: return "HTTP/1.0";
        case HTTPVersion::HTTP_1_1: return "HTTP/1.1";
        case HTTPVersion::HTTP_2_0: return "HTTP/2.0";
        default: return "UNKNOWN";
    }
}

HTTPVersion HTTPParser::string_to_version(const std::string& version_str) {
    if (version_str == "HTTP/1.0") return HTTPVersion::HTTP_1_0;
    if (version_str == "HTTP/1.1") return HTTPVersion::HTTP_1_1;
    if (version_str == "HTTP/2.0") return HTTPVersion::HTTP_2_0;
    return HTTPVersion::UNKNOWN;
}

// =============================================================================
// BaseParser 接口
// =============================================================================

const ProtocolInfo& HTTPParser::get_protocol_info() const noexcept {
    return kHTTPProtocolInfo;
}

bool HTTPParser::can_parse(const BufferView& buffer) const noexcept {
    return validate_http_message(buffer);
}

void HTTPParser::reset() noexcept {
    http_message_.type = HTTPMessageType::UNKNOWN;
    http_message_.request.method = HTTPMethod::UNKNOWN;
    http_message_.request.uri.clear();
    http_message_.request.version = HTTPVersion::UNKNOWN;
    http_message_.request.headers.clear();
    http_message_.request.body = core::BufferView{};
    http_message_.response.version = HTTPVersion::UNKNOWN;
    http_message_.response.status_code = 0;
    http_message_.response.reason_phrase.clear();
    http_message_.response.headers.clear();
    http_message_.response.body = core::BufferView{};
    is_complete_ = false;
    expected_body_length_ = 0;
    is_chunked_ = false;
    error_message_.clear();
}

double HTTPParser::get_progress() const noexcept {
    return is_complete_ ? 1.0 : 0.5;
}

HTTPMessageType HTTPParser::get_message_type() const {
    return http_message_.type;
}

bool HTTPParser::is_request() const {
    return http_message_.type == HTTPMessageType::REQUEST;
}

bool HTTPParser::is_response() const {
    return http_message_.type == HTTPMessageType::RESPONSE;
}

bool HTTPParser::is_complete() const {
    return is_complete_;
}

std::string HTTPParser::get_error_message() const noexcept {
    return error_message_;
}

} // namespace protocol_parser::parsers
