#include "../../../include/parsers/application/http_parser.hpp"
#include <algorithm>
#include <sstream>
#include <cctype>
#include <cstring>

namespace protocol_parser::parsers {

ParseResult HTTPParser::parse(ParseContext& context) noexcept {
    if (!validate_http_message(context.buffer)) {
        return ParseResult::InvalidFormat;
    }

    reset();
    
    // Find the end of headers (\r\n\r\n)
    size_t headers_end = find_headers_end(context.buffer);
    if (headers_end == std::string::npos) {
        return ParseResult::NeedMoreData;
    }

    // Extract headers section
    std::string headers_section(reinterpret_cast<const char*>(context.buffer.data()), headers_end);
    auto lines = split_lines(headers_section);
    
    if (lines.empty()) {
        return ParseResult::InvalidFormat;
    }

    // Parse first line (request line or status line)
    ParseResult status;
    if (lines[0].find("HTTP/") == 0) {
        // Response (starts with HTTP/)
        http_message_.type = HTTPMessageType::RESPONSE;
        status = parse_status_line(lines[0]);
    } else {
        // Request (method URI HTTP/version)
        http_message_.type = HTTPMessageType::REQUEST;
        status = parse_request_line(lines[0]);
    }
    
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse headers
    std::vector<std::string> header_lines(lines.begin() + 1, lines.end());
    status = parse_headers(header_lines);
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse body if present
    status = parse_body(context.buffer, headers_end + 4); // +4 for \r\n\r\n
    // Store parsed data in context
    context.metadata["http_message_type"] = static_cast<int>(http_message_.type);
    context.metadata["http_version"] = version_to_string(get_version());
    
    if (is_request()) {
        context.metadata["http_method"] = method_to_string(get_method());
        context.metadata["http_uri"] = get_uri();
    } else if (is_response()) {
        context.metadata["http_status_code"] = get_status_code();
        context.metadata["http_reason_phrase"] = get_reason_phrase();
    }
    
    context.metadata["http_content_length"] = get_content_length();
    context.metadata["http_is_chunked"] = is_chunked_encoding();
    context.metadata["http_is_keep_alive"] = is_keep_alive();
    
    // Store important headers
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

    context.offset = context.buffer.size(); // HTTP parser consumes entire buffer
    return status;
}

ParseResult HTTPParser::parse_request_line(const std::string& line) {
    std::istringstream iss(line);
    std::string method_str, uri, version_str;
    
    if (!(iss >> method_str >> uri >> version_str)) {
        return ParseResult::InvalidFormat;
    }
    
    http_message_.request.method = string_to_method(method_str);
    http_message_.request.uri = uri;
    http_message_.request.version = string_to_version(version_str);
    
    if (http_message_.request.method == HTTPMethod::UNKNOWN || 
        http_message_.request.version == HTTPVersion::UNKNOWN) {
        return ParseResult::InvalidFormat;
    }
    
    return ParseResult::Success;
}

ParseResult HTTPParser::parse_status_line(const std::string& line) {
    std::istringstream iss(line);
    std::string version_str, status_code_str;
    
    if (!(iss >> version_str >> status_code_str)) {
        return ParseResult::InvalidFormat;
    }
    
    http_message_.response.version = string_to_version(version_str);
    
    try {
        http_message_.response.status_code = static_cast<uint16_t>(std::stoi(status_code_str));
    } catch (const std::exception&) {
        return ParseResult::InvalidFormat;
    }
    
    // Extract reason phrase (rest of the line)
    size_t pos = line.find(status_code_str) + status_code_str.length();
    if (pos < line.length()) {
        http_message_.response.reason_phrase = trim(line.substr(pos));
    }
    
    if (http_message_.response.version == HTTPVersion::UNKNOWN) {
        return ParseResult::InvalidFormat;
    }
    
    return ParseResult::Success;
}

ParseResult HTTPParser::parse_headers(const std::vector<std::string>& header_lines) {
    auto& headers = (http_message_.type == HTTPMessageType::REQUEST) ? 
                   http_message_.request.headers : http_message_.response.headers;
    
    for (const auto& line : header_lines) {
        if (line.empty()) continue;
        
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue; // Skip malformed headers
        }
        
        std::string name = trim(to_lower(line.substr(0, colon_pos)));
        std::string value = trim(line.substr(colon_pos + 1));
        
        headers[name] = value;
    }
    
    // Determine expected body length
    auto content_length_header = get_header("content-length");
    auto transfer_encoding_header = get_header("transfer-encoding");
    
    if (!transfer_encoding_header.empty() && 
        to_lower(transfer_encoding_header).find("chunked") != std::string::npos) {
        is_chunked_ = true;
    } else if (!content_length_header.empty()) {
        try {
            expected_body_length_ = std::stoull(content_length_header);
        } catch (const std::exception&) {
            expected_body_length_ = 0;
        }
    }
    
    return ParseResult::Success;
}

ParseResult HTTPParser::parse_body(const BufferView& buffer, size_t start_pos) {
    if (start_pos >= buffer.size()) {
        is_complete_ = true;
        return ParseResult::Success;
    }
    
    if (is_chunked_) {
        return parse_chunked_body(buffer, start_pos);
    }
    
    // Fixed-length body
    size_t available_body_length = buffer.size() - start_pos;
    
    if (expected_body_length_ == 0) {
        // No body expected
        is_complete_ = true;
        return ParseResult::Success;
    }
    
    if (available_body_length < expected_body_length_) {
        return ParseResult::NeedMoreData;
    }
    
    // Extract body
    std::string body(reinterpret_cast<const char*>(buffer.data() + start_pos), expected_body_length_);
    
    if (http_message_.type == HTTPMessageType::REQUEST) {
        http_message_.request.body = std::move(body);
    } else {
        http_message_.response.body = std::move(body);
    }
    
    is_complete_ = true;
    return ParseResult::Success;
}

ParseResult HTTPParser::parse_chunked_body(const BufferView& buffer, size_t start_pos) {
    // Simplified chunked encoding parser
    // In a full implementation, this would handle chunk sizes and trailers
    std::string body;
    size_t pos = start_pos;
    
    while (pos < buffer.size()) {
        // Find chunk size line
        size_t line_end = pos;
        while (line_end < buffer.size() - 1 && 
               !(buffer.data()[line_end] == '\r' && buffer.data()[line_end + 1] == '\n')) {
            line_end++;
        }
        
        if (line_end >= buffer.size() - 1) {
            return ParseResult::NeedMoreData;
        }
        
        std::string chunk_size_str(reinterpret_cast<const char*>(buffer.data() + pos), line_end - pos);
        
        // Parse chunk size (hexadecimal)
        size_t chunk_size;
        try {
            chunk_size = std::stoull(chunk_size_str, nullptr, 16);
        } catch (const std::exception&) {
            return ParseResult::InvalidFormat;
        }
        
        if (chunk_size == 0) {
            // End of chunks
            break;
        }
        
        pos = line_end + 2; // Skip \r\n
        
        // Read chunk data
        if (pos + chunk_size + 2 > buffer.size()) {
            return ParseResult::NeedMoreData;
        }
        
        body.append(reinterpret_cast<const char*>(buffer.data() + pos), chunk_size);
        pos += chunk_size + 2; // Skip chunk data and trailing \r\n
    }
    
    if (http_message_.type == HTTPMessageType::REQUEST) {
        http_message_.request.body = std::move(body);
    } else {
        http_message_.response.body = std::move(body);
    }
    
    is_complete_ = true;
    return ParseResult::Success;
}

std::vector<std::string> HTTPParser::split_lines(const std::string& data) const {
    std::vector<std::string> lines;
    std::istringstream stream(data);
    std::string line;
    
    while (std::getline(stream, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    
    return lines;
}

size_t HTTPParser::find_headers_end(const BufferView& buffer) const {
    const char* data = reinterpret_cast<const char*>(buffer.data());
    size_t size = buffer.size();
    
    for (size_t i = 0; i < size - 3; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n' && 
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i;
        }
    }
    
    return std::string::npos;
}

std::string HTTPParser::trim(const std::string& str) const {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string HTTPParser::to_lower(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool HTTPParser::validate_http_message(const BufferView& buffer) const {
    if (buffer.size() < 16) { // Minimum reasonable HTTP message size
        return false;
    }
    
    // Check for HTTP signature
    const char* data = reinterpret_cast<const char*>(buffer.data());
    std::string start(data, std::min(buffer.size(), size_t(8)));
    
    return start.find("HTTP/") != std::string::npos || 
           start.find("GET ") == 0 || start.find("POST ") == 0 || 
           start.find("PUT ") == 0 || start.find("DELETE ") == 0 ||
           start.find("HEAD ") == 0 || start.find("OPTIONS ") == 0;
}

// Getter implementations
HTTPMethod HTTPParser::get_method() const {
    return (http_message_.type == HTTPMessageType::REQUEST) ? 
           http_message_.request.method : HTTPMethod::UNKNOWN;
}

std::string HTTPParser::get_uri() const {
    return (http_message_.type == HTTPMessageType::REQUEST) ? 
           http_message_.request.uri : "";
}

uint16_t HTTPParser::get_status_code() const {
    return (http_message_.type == HTTPMessageType::RESPONSE) ? 
           http_message_.response.status_code : 0;
}

std::string HTTPParser::get_reason_phrase() const {
    return (http_message_.type == HTTPMessageType::RESPONSE) ? 
           http_message_.response.reason_phrase : "";
}

HTTPVersion HTTPParser::get_version() const {
    return (http_message_.type == HTTPMessageType::REQUEST) ? 
           http_message_.request.version : 
           (http_message_.type == HTTPMessageType::RESPONSE) ? 
           http_message_.response.version : HTTPVersion::UNKNOWN;
}

std::string HTTPParser::get_header(const std::string& name) const {
    const auto& headers = (http_message_.type == HTTPMessageType::REQUEST) ? 
                         http_message_.request.headers : http_message_.response.headers;
    
    auto it = headers.find(to_lower(name));
    return (it != headers.end()) ? it->second : "";
}

const std::unordered_map<std::string, std::string>& HTTPParser::get_headers() const {
    static const std::unordered_map<std::string, std::string> empty_headers;
    
    if (http_message_.type == HTTPMessageType::REQUEST) {
        return http_message_.request.headers;
    } else if (http_message_.type == HTTPMessageType::RESPONSE) {
        return http_message_.response.headers;
    }
    
    return empty_headers;
}

std::string HTTPParser::get_body() const {
    return (http_message_.type == HTTPMessageType::REQUEST) ? 
           http_message_.request.body : 
           (http_message_.type == HTTPMessageType::RESPONSE) ? 
           http_message_.response.body : "";
}

size_t HTTPParser::get_content_length() const {
    auto content_length_str = get_header("content-length");
    if (content_length_str.empty()) return 0;
    
    try {
        return std::stoull(content_length_str);
    } catch (const std::exception&) {
        return 0;
    }
}

bool HTTPParser::is_chunked_encoding() const {
    auto transfer_encoding = get_header("transfer-encoding");
    return to_lower(transfer_encoding).find("chunked") != std::string::npos;
}

bool HTTPParser::is_keep_alive() const {
    auto connection = get_header("connection");
    return to_lower(connection).find("keep-alive") != std::string::npos;
}

// Utility method implementations
std::string HTTPParser::method_to_string(HTTPMethod method) const {
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

HTTPMethod HTTPParser::string_to_method(const std::string& method_str) const {
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

std::string HTTPParser::version_to_string(HTTPVersion version) const {
    switch (version) {
        case HTTPVersion::HTTP_1_0: return "HTTP/1.0";
        case HTTPVersion::HTTP_1_1: return "HTTP/1.1";
        case HTTPVersion::HTTP_2_0: return "HTTP/2.0";
        default: return "UNKNOWN";
    }
}

HTTPVersion HTTPParser::string_to_version(const std::string& version_str) const {
    if (version_str == "HTTP/1.0") return HTTPVersion::HTTP_1_0;
    if (version_str == "HTTP/1.1") return HTTPVersion::HTTP_1_1;
    if (version_str == "HTTP/2.0") return HTTPVersion::HTTP_2_0;
    return HTTPVersion::UNKNOWN;
}

const ProtocolInfo& HTTPParser::get_protocol_info() const noexcept {
    static const ProtocolInfo info{
        "HTTP",     // name
        80,         // type (HTTP port)
        0,          // header_size (variable)
        16,         // min_packet_size
        65535       // max_packet_size
    };
    return info;
}

bool HTTPParser::can_parse(const BufferView& buffer) const noexcept {
    return validate_http_message(buffer);
}

void HTTPParser::reset() noexcept {
    http_message_.type = HTTPMessageType::UNKNOWN;
    
    // Reset request data
    http_message_.request.method = HTTPMethod::UNKNOWN;
    http_message_.request.uri.clear();
    http_message_.request.version = HTTPVersion::UNKNOWN;
    http_message_.request.headers.clear();
    http_message_.request.body.clear();
    
    // Reset response data
    http_message_.response.version = HTTPVersion::UNKNOWN;
    http_message_.response.status_code = 0;
    http_message_.response.reason_phrase.clear();
    http_message_.response.headers.clear();
    http_message_.response.body.clear();
    
    is_complete_ = false;
    expected_body_length_ = 0;
    is_chunked_ = false;
    error_message_.clear();
}

double HTTPParser::get_progress() const noexcept {
    return is_complete_ ? 1.0 : 0.5; // 简单的进度指示
}

bool HTTPParser::is_request() const {
    return http_message_.type == HTTPMessageType::REQUEST;
}

bool HTTPParser::is_response() const {
    return http_message_.type == HTTPMessageType::RESPONSE;
}

std::string HTTPParser::get_error_message() const noexcept {
    return error_message_;
}

} // namespace protocol_parser::parsers