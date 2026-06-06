#include "parsers/application/snmp_parser.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <iomanip>
#include <sstream>

namespace protocol_parser::parsers {

// OID 类实现
OID::OID(const std::vector<uint32_t>& components) : components_(components) {}

OID::OID(const std::string& dotted_notation) {
    std::istringstream iss(dotted_notation);
    std::string component;
    
    while (std::getline(iss, component, '.')) {
        try {
            components_.push_back(std::stoul(component));
        } catch (const std::exception&) {
            components_.clear();
            break;
        }
    }
}

const std::vector<uint32_t>& OID::components() const noexcept {
    return components_;
}

std::string OID::to_string() const {
    if (components_.empty()) {
        return "";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < components_.size(); ++i) {
        if (i > 0) oss << ".";
        oss << components_[i];
    }
    return oss.str();
}

bool OID::is_valid() const noexcept {
    if (components_.empty() || components_.size() < 2) {
        return false;
    }
    
    // 第一个组件必须是0, 1, 或2
    if (components_[0] > 2) {
        return false;
    }
    
    // 如果第一个组件是0或1，第二个组件必须小于40
    if (components_[0] < 2 && components_[1] >= 40) {
        return false;
    }
    
    return true;
}

bool OID::is_prefix_of(const OID& other) const noexcept {
    if (components_.size() > other.components_.size()) {
        return false;
    }
    
    return std::equal(components_.begin(), components_.end(), other.components_.begin());
}

bool OID::operator==(const OID& other) const noexcept {
    return components_ == other.components_;
}

bool OID::operator<(const OID& other) const noexcept {
    return components_ < other.components_;
}

// VarBind 方法实现
std::string VarBind::value_to_string() const {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "NULL";
        } else if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, OID>) {
            return val.to_string();
        } else if constexpr (std::is_arithmetic_v<T>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            std::ostringstream oss;
            oss << std::hex;
            for (uint8_t byte : val) {
                oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            return oss.str();
        } else {
            return "UNKNOWN";
        }
    }, value);
}

bool VarBind::is_null() const noexcept {
    return std::holds_alternative<std::monostate>(value);
}

bool VarBind::is_exception() const noexcept {
    // 在实际实现中检查异常值
    return false;
}

// SNMPMessage 方法实现
bool SNMPMessage::is_v3() const noexcept {
    return version == SNMPVersion::VERSION_3;
}

bool SNMPMessage::is_encrypted() const noexcept {
    return is_v3() && v3_header && v3_header->message_flags.privacy;
}

bool SNMPMessage::is_authenticated() const noexcept {
    return is_v3() && v3_header && v3_header->message_flags.authentication;
}

const SNMPPDU& SNMPMessage::get_pdu() const noexcept {
    if (is_v3() && v3_scoped_pdu) {
        return v3_scoped_pdu->pdu;
    }
    return pdu;
}

// SNMPParser 方法实现

const ProtocolInfo& SNMPParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {
        "SNMP",           // name
        0x0801,          // type (SNMP)
        4,                // header_size (approximate)
        10,               // min_packet_size
        65507             // max_packet_size
    };
    return info;
}

bool SNMPParser::can_parse(const BufferView& buffer) const noexcept {
    const auto data = buffer.data();
    const auto size = buffer.size();

    // 检查最小大小
    if (size < 10) return false;

    // 检查BER SEQUENCE标记 (0x30)
    if (data[0] != 0x30) return false;

    // 验证BER编码
    return true;
}

ParseResult SNMPParser::parse(ParseContext& context) noexcept {
    reset();

    const auto buffer = context.buffer;
    const auto data = buffer.data();
    const auto size = buffer.size();

    try {
        if (size < 10) {  // 最小SNMP消息大小
            is_malformed_ = true;
            return ParseResult::NeedMoreData;
        }

        if (size > MAX_MESSAGE_SIZE) {
            is_malformed_ = true;
            return ParseResult::BufferTooSmall;
        }

        size_t offset = 0;

        // 验证BER编码
        if (!validate_ber_encoding(data, size)) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }

        // 解析顶层序列
        if (!parse_ber_sequence(data, size, offset)) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }

        // 解析版本
        int64_t version_val;
        if (!parse_ber_integer(data, size, offset, version_val)) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }

        snmp_message_.version = static_cast<SNMPVersion>(version_val);

        // 根据版本解析剩余部分
        bool parse_success = false;
        switch (snmp_message_.version) {
            case SNMPVersion::VERSION_1:
            case SNMPVersion::VERSION_2C:
                parse_success = parse_v1_v2c_message(data, size, offset);
                break;
            case SNMPVersion::VERSION_3:
                parse_success = parse_v3_message(data, size, offset);
                break;
            default:
                is_malformed_ = true;
                return ParseResult::UnsupportedVersion;
        }

        if (!parse_success) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }

        // 验证消息
        if (!validate_message()) {
            is_malformed_ = true;
            return ParseResult::InvalidFormat;
        }

        parsed_successfully_ = true;
        update_statistics(snmp_message_);
        perform_security_analysis();

        return ParseResult::Success;

    } catch (const std::exception&) {
        reset();
        is_malformed_ = true;
        return ParseResult::InternalError;
    }
}

std::string SNMPParser::get_protocol_name() const noexcept {
    return "SNMP";
}

uint16_t SNMPParser::get_default_port() const noexcept {
    return SNMP_DEFAULT_PORT;
}

std::vector<uint16_t> SNMPParser::get_supported_ports() const noexcept {
    return {SNMP_DEFAULT_PORT, SNMP_TRAP_PORT};
}

void SNMPParser::reset() noexcept {
    snmp_message_ = SNMPMessage{};
    parsed_successfully_ = false;
    is_malformed_ = false;
}

const SNMPMessage& SNMPParser::get_snmp_message() const noexcept {
    return snmp_message_;
}

bool SNMPParser::is_snmp_packet() const noexcept {
    return parsed_successfully_;
}

bool SNMPParser::validate_message() const noexcept {
    // 验证版本
    if (snmp_message_.version != SNMPVersion::VERSION_1 &&
        snmp_message_.version != SNMPVersion::VERSION_2C &&
        snmp_message_.version != SNMPVersion::VERSION_3) {
        return false;
    }
    
    // 验证PDU
    return validate_pdu(snmp_message_.get_pdu());
}

bool SNMPParser::is_malformed() const noexcept {
    return is_malformed_;
}

SNMPParser::SNMPAnalysis SNMPParser::analyze_message() const noexcept {
    SNMPAnalysis analysis;
    
    if (!parsed_successfully_) {
        return analysis;
    }
    
    const auto& pdu = snmp_message_.get_pdu();
    
    // 分析PDU类型
    switch (pdu.type) {
        case SNMPPDUType::GET_REQUEST:
        case SNMPPDUType::GET_NEXT_REQUEST:
        case SNMPPDUType::SET_REQUEST:
        case SNMPPDUType::INFORM_REQUEST:
            analysis.is_request = true;
            break;
        case SNMPPDUType::GET_RESPONSE:
        case SNMPPDUType::REPORT:
            analysis.is_response = true;
            break;
        case SNMPPDUType::TRAP:
        case SNMPPDUType::TRAP_V2:
            analysis.is_trap = true;
            break;
        case SNMPPDUType::GET_BULK_REQUEST:
            analysis.is_request = true;
            analysis.is_bulk_request = true;
            break;
    }
    
    // 分析错误状态
    analysis.has_errors = (pdu.error_status != SNMPErrorStatus::NO_ERROR);
    
    // 安全分析
    analysis.is_encrypted = snmp_message_.is_encrypted();
    analysis.is_authenticated = snmp_message_.is_authenticated();
    
    // 变量分析
    analysis.variable_count = pdu.variable_bindings.size();
    
    // 计算OID复杂度
    for (const auto& vb : pdu.variable_bindings) {
        analysis.oid_complexity += vb.oid.components().size();
    }
    
    // 分析MIB模块
    for (const auto& vb : pdu.variable_bindings) {
        std::string module = classify_oid_by_prefix(vb.oid);
        if (!module.empty() && std::find(analysis.mib_modules.begin(), 
                                        analysis.mib_modules.end(), 
                                        module) == analysis.mib_modules.end()) {
            analysis.mib_modules.push_back(module);
        }
    }
    
    // 计算解析复杂度
    analysis.parse_complexity = analysis.variable_count * 0.1 + 
                                analysis.oid_complexity * 0.01 +
                                (analysis.is_encrypted ? 2.0 : 0.0);
    
    return analysis;
}

const SNMPParser::SNMPStatistics& SNMPParser::get_statistics() const noexcept {
    return statistics_;
}

void SNMPParser::reset_statistics() noexcept {
    statistics_ = SNMPStatistics{};
}

std::string SNMPParser::pdu_type_to_string(SNMPPDUType type) noexcept {
    switch (type) {
        case SNMPPDUType::GET_REQUEST: return "GetRequest";
        case SNMPPDUType::GET_NEXT_REQUEST: return "GetNextRequest";
        case SNMPPDUType::GET_RESPONSE: return "GetResponse";
        case SNMPPDUType::SET_REQUEST: return "SetRequest";
        case SNMPPDUType::TRAP: return "Trap";
        case SNMPPDUType::GET_BULK_REQUEST: return "GetBulkRequest";
        case SNMPPDUType::INFORM_REQUEST: return "InformRequest";
        case SNMPPDUType::TRAP_V2: return "TrapV2";
        case SNMPPDUType::REPORT: return "Report";
        default: return "Unknown";
    }
}

std::string SNMPParser::error_status_to_string(SNMPErrorStatus status) noexcept {
    switch (status) {
        case SNMPErrorStatus::NO_ERROR: return "noError";
        case SNMPErrorStatus::TOO_BIG: return "tooBig";
        case SNMPErrorStatus::NO_SUCH_NAME: return "noSuchName";
        case SNMPErrorStatus::BAD_VALUE: return "badValue";
        case SNMPErrorStatus::READ_ONLY: return "readOnly";
        case SNMPErrorStatus::GEN_ERR: return "genErr";
        case SNMPErrorStatus::NO_ACCESS: return "noAccess";
        case SNMPErrorStatus::WRONG_TYPE: return "wrongType";
        case SNMPErrorStatus::WRONG_LENGTH: return "wrongLength";
        case SNMPErrorStatus::WRONG_ENCODING: return "wrongEncoding";
        case SNMPErrorStatus::WRONG_VALUE: return "wrongValue";
        case SNMPErrorStatus::NO_CREATION: return "noCreation";
        case SNMPErrorStatus::INCONSISTENT_VALUE: return "inconsistentValue";
        case SNMPErrorStatus::RESOURCE_UNAVAILABLE: return "resourceUnavailable";
        case SNMPErrorStatus::COMMIT_FAILED: return "commitFailed";
        case SNMPErrorStatus::UNDO_FAILED: return "undoFailed";
        case SNMPErrorStatus::AUTHORIZATION_ERROR: return "authorizationError";
        case SNMPErrorStatus::NOT_WRITABLE: return "notWritable";
        case SNMPErrorStatus::INCONSISTENT_NAME: return "inconsistentName";
        default: return "unknown";
    }
}

std::string SNMPParser::version_to_string(SNMPVersion version) noexcept {
    switch (version) {
        case SNMPVersion::VERSION_1: return "SNMPv1";
        case SNMPVersion::VERSION_2C: return "SNMPv2c";
        case SNMPVersion::VERSION_3: return "SNMPv3";
        default: return "Unknown";
    }
}

std::string SNMPParser::ber_type_to_string(BERType type) noexcept {
    switch (type) {
        case BERType::INTEGER: return "INTEGER";
        case BERType::OCTET_STRING: return "OCTET STRING";
        case BERType::NULL_TYPE: return "NULL";
        case BERType::OBJECT_IDENTIFIER: return "OBJECT IDENTIFIER";
        case BERType::SEQUENCE: return "SEQUENCE";
        case BERType::IPADDRESS: return "IpAddress";
        case BERType::COUNTER32: return "Counter32";
        case BERType::GAUGE32: return "Gauge32";
        case BERType::TIMETICKS: return "TimeTicks";
        case BERType::OPAQUE: return "Opaque";
        case BERType::COUNTER64: return "Counter64";
        default: return "Unknown";
    }
}

bool SNMPParser::is_valid_community(const std::string& community) noexcept {
    return !community.empty() && community.size() <= 255;
}

uint32_t SNMPParser::ip_string_to_uint32(const std::string& ip) noexcept {
    try {
        std::istringstream stream(ip);
        std::string part;
        uint32_t result = 0;

        for (int i = 0; i < 4; ++i) {
            if (!std::getline(stream, part, '.') || part.empty()) {
                return 0;
            }

            const auto value = std::stoul(part);
            if (value > 255) {
                return 0;
            }

            result = (result << 8) | static_cast<uint32_t>(value);
        }

        return stream.eof() ? result : 0;
    } catch (const std::exception&) {
        return 0;
    }
}

std::optional<SNMPParser::MIBInfo> SNMPParser::lookup_oid(const OID& oid) const noexcept {
    try {
        const auto it = mib_database_.find(oid.to_string());
        if (it == mib_database_.end()) {
            return std::nullopt;
        }
        return it->second;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void SNMPParser::load_mib_database(const std::string& mib_file_path) {
    (void)mib_file_path;
}

// 私有方法实现（简化版）
bool SNMPParser::parse_ber_sequence(const uint8_t* data, size_t size, size_t& offset) noexcept {
    if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::SEQUENCE)) {
        return false;
    }
    
    offset++;
    size_t length;
    return parse_ber_length(data, size, offset, length);
}

bool SNMPParser::parse_ber_length(const uint8_t* data, size_t size, size_t& offset, size_t& length) noexcept {
    if (offset >= size) {
        return false;
    }
    
    uint8_t first_byte = data[offset++];
    
    if ((first_byte & 0x80) == 0) {
        // 短格式
        length = first_byte;
        return true;
    }
    
    // 长格式
    uint8_t num_octets = first_byte & 0x7F;
    if (num_octets == 0 || num_octets > 4 || offset + num_octets > size) {
        return false;
    }
    
    length = 0;
    for (uint8_t i = 0; i < num_octets; ++i) {
        length = (length << 8) | data[offset++];
    }
    
    return offset + length <= size;
}

bool SNMPParser::parse_ber_integer(const uint8_t* data, size_t size, size_t& offset, int64_t& value) noexcept {
    if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::INTEGER)) {
        return false;
    }
    
    offset++;
    size_t length;
    if (!parse_ber_length(data, size, offset, length)) {
        return false;
    }
    
    if (length == 0 || length > 8 || offset + length > size) {
        return false;
    }
    
    value = 0;
    bool negative = (data[offset] & 0x80) != 0;
    
    for (size_t i = 0; i < length; ++i) {
        value = (value << 8) | data[offset++];
    }
    
    if (negative && length < 8) {
        // 符号扩展
        value |= (~0ULL << (length * 8));
    }
    
    return true;
}

bool SNMPParser::parse_ber_oid(const uint8_t* data, size_t size, size_t& offset, OID& oid) noexcept {
    if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::OBJECT_IDENTIFIER)) {
        return false;
    }

    ++offset;
    size_t length = 0;
    if (!parse_ber_length(data, size, offset, length) || length == 0 || offset + length > size) {
        return false;
    }

    const size_t end = offset + length;
    std::vector<uint32_t> components;
    const uint8_t first = data[offset++];
    if (first < 40) {
        components.push_back(0);
        components.push_back(first);
    } else if (first < 80) {
        components.push_back(1);
        components.push_back(first - 40);
    } else {
        components.push_back(2);
        components.push_back(first - 80);
    }

    while (offset < end) {
        uint32_t component = 0;
        bool completed = false;

        while (offset < end) {
            const uint8_t byte = data[offset++];
            component = (component << 7) | (byte & 0x7F);
            if ((byte & 0x80) == 0) {
                completed = true;
                break;
            }
        }

        if (!completed) {
            return false;
        }
        components.push_back(component);
    }

    oid = OID(components);
    return validate_oid(oid);
}

bool SNMPParser::parse_snmp_value(const uint8_t* data, size_t size, size_t& offset, BERType type, SNMPValue& value) noexcept {
    auto parse_unsigned = [&](size_t max_length, uint64_t& parsed) noexcept -> bool {
        if (offset >= size || data[offset] != static_cast<uint8_t>(type)) {
            return false;
        }

        ++offset;
        size_t length = 0;
        if (!parse_ber_length(data, size, offset, length) || length == 0 || length > max_length || offset + length > size) {
            return false;
        }

        parsed = 0;
        for (size_t i = 0; i < length; ++i) {
            parsed = (parsed << 8) | data[offset++];
        }
        return true;
    };

    switch (type) {
        case BERType::INTEGER: {
            int64_t parsed = 0;
            if (!parse_ber_integer(data, size, offset, parsed)) {
                return false;
            }
            value = parsed;
            return true;
        }
        case BERType::OCTET_STRING: {
            std::string parsed;
            if (!parse_ber_octet_string(data, size, offset, parsed)) {
                return false;
            }
            value = parsed;
            return true;
        }
        case BERType::NULL_TYPE: {
            if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::NULL_TYPE)) {
                return false;
            }
            ++offset;
            size_t length = 0;
            if (!parse_ber_length(data, size, offset, length) || offset + length > size) {
                return false;
            }
            offset += length;
            value = std::monostate{};
            return length == 0;
        }
        case BERType::OBJECT_IDENTIFIER: {
            OID parsed;
            if (!parse_ber_oid(data, size, offset, parsed)) {
                return false;
            }
            value = parsed;
            return true;
        }
        case BERType::IPADDRESS: {
            uint64_t parsed = 0;
            if (!parse_unsigned(4, parsed)) {
                return false;
            }
            value.emplace<4>(static_cast<uint32_t>(parsed));
            return true;
        }
        case BERType::COUNTER32: {
            uint64_t parsed = 0;
            if (!parse_unsigned(4, parsed)) {
                return false;
            }
            value.emplace<5>(static_cast<uint32_t>(parsed));
            return true;
        }
        case BERType::GAUGE32: {
            uint64_t parsed = 0;
            if (!parse_unsigned(4, parsed)) {
                return false;
            }
            value.emplace<6>(static_cast<uint32_t>(parsed));
            return true;
        }
        case BERType::TIMETICKS: {
            uint64_t parsed = 0;
            if (!parse_unsigned(4, parsed)) {
                return false;
            }
            value.emplace<7>(static_cast<uint32_t>(parsed));
            return true;
        }
        case BERType::OPAQUE: {
            if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::OPAQUE)) {
                return false;
            }
            ++offset;
            size_t length = 0;
            if (!parse_ber_length(data, size, offset, length) || offset + length > size) {
                return false;
            }
            value = std::vector<uint8_t>(data + offset, data + offset + length);
            offset += length;
            return true;
        }
        case BERType::COUNTER64: {
            uint64_t parsed = 0;
            if (!parse_unsigned(8, parsed)) {
                return false;
            }
            value = parsed;
            return true;
        }
        default:
            return false;
    }
}

bool SNMPParser::parse_v1_v2c_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    // 解析community字符串
    if (!parse_ber_octet_string(data, size, offset, snmp_message_.community)) {
        return false;
    }
    
    // 解析PDU
    return parse_pdu(data, size, offset, snmp_message_.pdu);
}

bool SNMPParser::parse_v3_message(const uint8_t* data, size_t size, size_t& offset) noexcept {
    (void)data;
    (void)size;
    (void)offset;
    return true;
}

bool SNMPParser::validate_ber_encoding(const uint8_t* data, size_t size) const noexcept {
    // 基本BER编码验证
    return size > 0 && data[0] == static_cast<uint8_t>(BERType::SEQUENCE);
}

void SNMPParser::update_statistics(const SNMPMessage& message) noexcept {
    statistics_.total_messages++;
    
    switch (message.version) {
        case SNMPVersion::VERSION_1: statistics_.v1_messages++; break;
        case SNMPVersion::VERSION_2C: statistics_.v2c_messages++; break;
        case SNMPVersion::VERSION_3: statistics_.v3_messages++; break;
    }
    
    const auto& pdu = message.get_pdu();
    switch (pdu.type) {
        case SNMPPDUType::GET_REQUEST: statistics_.get_requests++; break;
        case SNMPPDUType::GET_RESPONSE: statistics_.get_responses++; break;
        case SNMPPDUType::SET_REQUEST: statistics_.set_requests++; break;
        case SNMPPDUType::TRAP:
        case SNMPPDUType::TRAP_V2: statistics_.traps++; break;
        case SNMPPDUType::GET_BULK_REQUEST: statistics_.bulk_requests++; break;
        default: break;
    }
    
    if (!message.community.empty()) {
        statistics_.community_usage[message.community]++;
    }
    
    statistics_.error_distribution[pdu.error_status]++;
    
    if (is_malformed_) {
        statistics_.malformed_messages++;
    }
}

std::string SNMPParser::classify_oid_by_prefix(const OID& oid) const noexcept {
    const auto& components = oid.components();
    if (components.size() < 3) {
        return "";
    }
    
    // 标准MIB-II (1.3.6.1.2.1)
    if (components.size() >= 6 && 
        components[0] == 1 && components[1] == 3 && components[2] == 6 &&
        components[3] == 1 && components[4] == 2 && components[5] == 1) {
        return "MIB-II";
    }
    
    // 企业MIB (1.3.6.1.4.1)
    if (components.size() >= 6 &&
        components[0] == 1 && components[1] == 3 && components[2] == 6 &&
        components[3] == 1 && components[4] == 4 && components[5] == 1) {
        return "Enterprise";
    }
    
    return "Unknown";
}

// 简化的其他方法实现...
bool SNMPParser::parse_ber_octet_string(const uint8_t* data, size_t size, size_t& offset, std::string& value) noexcept {
    if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::OCTET_STRING)) {
        return false;
    }

    ++offset;
    size_t length = 0;
    if (!parse_ber_length(data, size, offset, length) || offset + length > size) {
        return false;
    }

    value.assign(reinterpret_cast<const char*>(data + offset), length);
    offset += length;
    return true;
}

bool SNMPParser::parse_pdu(const uint8_t* data, size_t size, size_t& offset, SNMPPDU& pdu) noexcept {
    if (offset >= size) {
        return false;
    }

    const uint8_t pdu_tag = data[offset++];
    if (pdu_tag < 0xA0 || pdu_tag > 0xA8) {
        return false;
    }

    size_t length = 0;
    if (!parse_ber_length(data, size, offset, length) || offset + length > size) {
        return false;
    }

    const size_t end = offset + length;
    pdu.type = static_cast<SNMPPDUType>(pdu_tag - 0xA0);

    int64_t request_id = 0;
    int64_t error_status = 0;
    int64_t error_index = 0;
    if (!parse_ber_integer(data, end, offset, request_id) ||
        !parse_ber_integer(data, end, offset, error_status) ||
        !parse_ber_integer(data, end, offset, error_index)) {
        return false;
    }

    pdu.request_id = static_cast<uint32_t>(request_id);
    pdu.error_status = static_cast<SNMPErrorStatus>(error_status);
    pdu.error_index = static_cast<uint32_t>(error_index);

    if (!parse_variable_bindings(data, end, offset, pdu.variable_bindings)) {
        return false;
    }

    offset = end;
    return validate_pdu(pdu);
}

bool SNMPParser::parse_variable_bindings(const uint8_t* data, size_t size, size_t& offset, std::vector<VarBind>& bindings) noexcept {
    if (offset >= size || data[offset] != static_cast<uint8_t>(BERType::SEQUENCE)) {
        return false;
    }

    ++offset;
    size_t length = 0;
    if (!parse_ber_length(data, size, offset, length) || offset + length > size) {
        return false;
    }

    const size_t end = offset + length;
    while (offset < end) {
        if (data[offset] != static_cast<uint8_t>(BERType::SEQUENCE)) {
            return false;
        }

        ++offset;
        size_t binding_length = 0;
        if (!parse_ber_length(data, end, offset, binding_length) || offset + binding_length > end) {
            return false;
        }

        const size_t binding_end = offset + binding_length;
        VarBind binding;
        if (!parse_ber_oid(data, binding_end, offset, binding.oid) || offset >= binding_end) {
            return false;
        }

        binding.type = static_cast<BERType>(data[offset]);
        if (!parse_snmp_value(data, binding_end, offset, binding.type, binding.value) || offset != binding_end) {
            return false;
        }

        bindings.push_back(binding);
    }

    return offset == end;
}

bool SNMPParser::validate_oid(const OID& oid) const noexcept {
    return oid.is_valid() && oid.components().size() <= MAX_OID_LENGTH;
}

bool SNMPParser::validate_pdu(const SNMPPDU& pdu) const noexcept {
    return pdu.variable_bindings.size() <= MAX_VARBIND_COUNT;
}

bool SNMPParser::detect_dos_patterns() const noexcept {
    return snmp_message_.get_pdu().variable_bindings.size() > MAX_VARBIND_COUNT;
}

bool SNMPParser::validate_message_size() const noexcept {
    return parsed_successfully_ || !is_malformed_;
}

void SNMPParser::perform_security_analysis() noexcept {
    if (detect_dos_patterns()) {
        is_malformed_ = true;
    }
}

void SNMPParser::initialize_standard_mibs() noexcept {
    // 初始化标准MIB
}

} // namespace protocol_parser::parsers