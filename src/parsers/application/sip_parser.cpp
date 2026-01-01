#include "parsers/application/sip_parser.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace protocol_parser::parsers {

// ============================================================================
// SipParser 实现
// ============================================================================

SipParser::SipParser() {
    protocol_info_ = ProtocolInfo{
        .name = "SIP",
        .type = 0xFF,  // 运行在 TCP/UDP 之上
        .header_size = 0,  // 文本协议，无固定头部长度
        .min_packet_size = 50,  // 最小 SIP 消息
        .max_packet_size = 65535
    };

    reset();
}

const ProtocolInfo& SipParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool SipParser::is_sip_message(const BufferView& buffer) noexcept {
    // SIP 是文本协议，检查起始行
    if (buffer.size() < 5) {
        return false;
    }

    // 转换为字符串视图
    std::string_view sv(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    // 检查请求方法
    static constexpr const char* methods[] = {
        "INVITE", "ACK", "BYE", "CANCEL", "REGISTER",
        "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH",
        "INFO", "REFER", "MESSAGE", "UPDATE"
    };

    for (const char* method : methods) {
        if (sv.find(method) == 0) {
            return true;
        }
    }

    // 检查响应
    if (sv.find("SIP/2.0") == 0 || sv.find("\nSIP/2.0") != std::string_view::npos ||
        sv.find("\r\nSIP/2.0") != std::string_view::npos) {
        return true;
    }

    return false;
}

bool SipParser::can_parse(const BufferView& buffer) const noexcept {
    return is_sip_message(buffer);
}

ParseResult SipParser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;

    if (buffer.size() < protocol_info_.min_packet_size) {
        return ParseResult::BufferTooSmall;
    }

    reset();

    // 转换为字符串处理
    std::string_view sv(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    // 分割行
    std::vector<std::string> lines;
    std::string line;
    for (char c : sv) {
        if (c == '\n') {
            lines.push_back(line);
            line.clear();
        } else if (c != '\r') {
            line += c;
        }
    }
    if (!line.empty()) {
        lines.push_back(line);
    }

    if (lines.empty()) {
        return ParseResult::InvalidFormat;
    }

    // 解析起始行
    const std::string& start_line = lines[0];

    if (start_line.find("SIP/2.0") == 0) {
        // 响应行
        result_.is_request = false;
        if (!parse_response_line(start_line)) {
            return ParseResult::InvalidFormat;
        }
    } else {
        // 请求行
        result_.is_request = true;
        if (!parse_request_line(start_line)) {
            return ParseResult::InvalidFormat;
        }
    }

    // 查找空行（头部结束）
    size_t header_end = 1;
    for (size_t i = 1; i < lines.size(); ++i) {
        if (lines[i].empty()) {
            header_end = i;
            break;
        }
    }

    // 解析头部
    if (header_end > 1) {
        std::vector<std::string> header_lines(lines.begin() + 1, lines.begin() + header_end);
        if (!parse_headers(header_lines)) {
            return ParseResult::InvalidFormat;
        }
    }

    // 解析消息体
    if (result_.content_length > 0 && header_end + 1 < lines.size()) {
        // 计算消息体在原始缓冲区中的偏移
        size_t body_start = 0;
        for (size_t i = 0; i <= header_end; ++i) {
            body_start += lines[i].size() + 1;  // +1 for \n
            if (i > 0) {
                body_start += 1;  // +1 for \r if present
            }
        }

        if (!parse_body(buffer, body_start)) {
            return ParseResult::InvalidFormat;
        }
    }

    // 保存结果
    context.metadata["sip_result"] = result_;

    return ParseResult::Success;
}

bool SipParser::parse_request_line(const std::string& line) {
    // 格式: METHOD Request-URI SIP-Version
    std::istringstream iss(line);
    std::string method_str, request_uri, sip_version;

    if (!(iss >> method_str >> request_uri >> sip_version)) {
        return false;
    }

    // 解析方法
    static const std::map<std::string, SipMethod> method_map = {
        {"INVITE", SipMethod::INVITE},
        {"ACK", SipMethod::ACK},
        {"BYE", SipMethod::BYE},
        {"CANCEL", SipMethod::CANCEL},
        {"REGISTER", SipMethod::REGISTER},
        {"OPTIONS", SipMethod::OPTIONS},
        {"PRACK", SipMethod::PRACK},
        {"SUBSCRIBE", SipMethod::SUBSCRIBE},
        {"NOTIFY", SipMethod::NOTIFY},
        {"PUBLISH", SipMethod::PUBLISH},
        {"INFO", SipMethod::INFO},
        {"REFER", SipMethod::REFER},
        {"MESSAGE", SipMethod::MESSAGE},
        {"UPDATE", SipMethod::UPDATE}
    };

    auto it = method_map.find(method_str);
    if (it != method_map.end()) {
        result_.method = it->second;
    } else {
        return false;  // 未知方法
    }

    result_.request_uri = request_uri;
    result_.sip_version = sip_version;

    return true;
}

bool SipParser::parse_response_line(const std::string& line) {
    // 格式: SIP-Version Status-Code Reason-Phrase
    std::istringstream iss(line);
    std::string sip_version;
    int status_code;

    if (!(iss >> sip_version >> status_code)) {
        return false;
    }

    // 读取原因短语（剩余部分）
    std::string reason_phrase;
    std::getline(iss >> std::ws, reason_phrase);

    result_.sip_version = sip_version;
    result_.response_code = static_cast<SipResponseCode>(status_code);
    result_.reason_phrase = reason_phrase;

    return true;
}

bool SipParser::parse_headers(const std::vector<std::string>& lines) {
    for (const std::string& line : lines) {
        if (line.empty()) {
            continue;
        }

        // 查找冒号
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue;  // 跳过无效头部
        }

        // 提取头部名和值
        std::string name = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);

        // 去除空白
        while (!name.empty() && std::isspace(name.back())) {
            name.pop_back();
        }
        while (!value.empty() && std::isspace(value.front())) {
            value.erase(0, 1);
        }

        // 存储头部
        SipHeader header{name, value};
        result_.headers.push_back(header);

        // 提取关键头部（快速访问）
        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(),
                      lower_name.begin(), ::tolower);

        if (lower_name == "from") {
            result_.from = value;
        } else if (lower_name == "to") {
            result_.to = value;
        } else if (lower_name == "call-id" || lower_name == "i") {
            result_.call_id = value;
        } else if (lower_name == "cseq") {
            result_.cseq = value;
        } else if (lower_name == "via") {
            result_.via = value;
        } else if (lower_name == "contact") {
            result_.contact = value;
        } else if (lower_name == "content-type") {
            result_.content_type = value;
        } else if (lower_name == "content-length") {
            try {
                result_.content_length = std::stoul(value);
            } catch (...) {
                result_.content_length = 0;
            }
        }
    }

    return true;
}

bool SipParser::parse_body(const BufferView& buffer, size_t offset) {
    if (offset >= buffer.size()) {
        return false;
    }

    size_t body_size = std::min(result_.content_length, buffer.size() - offset);

    SipBody body;
    body.content_type = result_.content_type;
    body.data.assign(buffer.data() + offset, buffer.data() + offset + body_size);

    result_.body = body;

    // 如果是 SDP，解析
    if (body.content_type.find("application/sdp") != std::string::npos) {
        std::string sdp_str(body.data.begin(), body.data.end());
        parse_sdp(sdp_str);
    }

    return true;
}

std::optional<std::string> SipParser::find_header(const std::string& name) const {
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(),
                  lower_name.begin(), ::tolower);

    for (const auto& header : result_.headers) {
        std::string header_lower = header.name;
        std::transform(header_lower.begin(), header_lower.end(),
                      header_lower.begin(), ::tolower);

        if (header_lower == lower_name) {
            return header.value;
        }
    }

    return std::nullopt;
}

void SipParser::parse_sdp(const std::string& sdp) {
    // 简化：暂不解析 SDP
    // SDP 格式:
    // v=0 (protocol version)
    // o=<username> <session id> <version> <network type> <address type> <address>
    // s=<session name>
    // c=<network type> <address type> <connection address>
    // t=<start time> <stop time>
    // m=<media> <port> <transport> <fmt list>
    // a=<attribute>
    // ...
}

void SipParser::reset() noexcept {
    result_ = SipParseResult{};
    result_.is_request = true;
    result_.content_length = 0;
    state_ = ParserState::Initial;
    header_lines_.clear();
}

} // namespace protocol_parser::parsers
