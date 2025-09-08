#include "../../../include/parsers/application/https_parser.hpp"
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace protocol_parser::parsers {

HTTPSParser::HTTPSParser() 
    : handshake_messages_parsed_(0),
      application_data_records_(0),
      alert_messages_(0) {
    reset_session();
    initialize_cipher_suites();
}

const ProtocolInfo& HTTPSParser::get_protocol_info() const noexcept {
    static const ProtocolInfo info{
        "HTTPS/TLS",
        443,
        5,  // TLS record header size
        5,  // minimum packet size
        16384 + 5  // max TLS record size + header
    };
    return info;
}

bool HTTPSParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 5) return false;
    
    // Check for TLS content types
    uint8_t content_type = buffer.data()[0];
    return (content_type >= 20 && content_type <= 24);
}

ParseResult HTTPSParser::parse(ParseContext& context) noexcept {
    const uint8_t* data = context.buffer.data();
    size_t length = context.buffer.size();
    if (!data || length == 0) {
        return ParseResult::InvalidFormat;
    }
    
    // Add data to buffer
    buffer_.insert(buffer_.end(), data, data + length);
    
    size_t offset = 0;
    
    // Process complete TLS records
    while (offset + 5 <= buffer_.size()) {  // Minimum TLS record header size
        HTTPSMessage message;
        
        // Parse record header
        if (!parse_record_header(buffer_.data() + offset, message.record_header)) {
            // Invalid record header, skip this byte and try again
            offset++;
            continue;
        }
        
        // Check if we have the complete record
        size_t total_record_size = 5 + message.record_header.length;
        if (offset + total_record_size > buffer_.size()) {
            // Incomplete record, wait for more data
            return ParseResult::NeedMoreData;
        }
        
        // Parse the complete TLS record
        if (parse_tls_record(buffer_.data() + offset, total_record_size, message)) {
            message.session_info = current_session_;
            update_session_state(message);
            
            // Store parsed message in context metadata
            context.metadata["https_message"] = std::make_shared<HTTPSMessage>(message);
        }
        
        offset += total_record_size;
    }
    
    // Remove processed data from buffer
    if (offset > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + offset);
    }
    
    return ParseResult::Success;
}

void HTTPSParser::reset() noexcept {
    buffer_.clear();
    reset_session();
    handshake_messages_parsed_ = 0;
    application_data_records_ = 0;
    alert_messages_ = 0;
}

bool HTTPSParser::parse_tls_record(const uint8_t* data, size_t length, HTTPSMessage& message) {
    if (length < 5) {
        return false;
    }
    
    // Record header already parsed
    const uint8_t* payload = data + 5;
    size_t payload_length = message.record_header.length;
    
    switch (message.record_header.content_type) {
        case TLSContentType::HANDSHAKE:
            return parse_handshake_message(payload, payload_length, message);
            
        case TLSContentType::ALERT:
            return parse_alert(payload, payload_length, message.alert);
            
        case TLSContentType::APPLICATION_DATA:
            message.application_data.assign(payload, payload + payload_length);
            application_data_records_++;
            return true;
            
        case TLSContentType::CHANGE_CIPHER_SPEC:
            // Change cipher spec is a single byte (0x01)
            return payload_length == 1 && payload[0] == 0x01;
            
        default:
            return false;
    }
}

bool HTTPSParser::parse_record_header(const uint8_t* data, TLSRecordHeader& header) {
    if (!data) {
        return false;
    }
    
    header.content_type = static_cast<TLSContentType>(data[0]);
    header.version = parse_version(read_uint16(data + 1));
    header.length = read_uint16(data + 3);
    
    return is_valid_tls_record(header);
}

bool HTTPSParser::parse_handshake_message(const uint8_t* data, size_t length, HTTPSMessage& message) {
    if (length < 4) {
        return false;
    }
    
    // Parse handshake header
    message.handshake_header.msg_type = static_cast<TLSHandshakeType>(data[0]);
    message.handshake_header.length = read_uint24(data + 1);
    
    if (!is_valid_handshake_message(message.handshake_header)) {
        return false;
    }
    
    // Store raw handshake data
    message.raw_handshake_data.assign(data, data + length);
    
    const uint8_t* handshake_payload = data + 4;
    size_t handshake_payload_length = message.handshake_header.length;
    
    bool success = false;
    
    switch (message.handshake_header.msg_type) {
        case TLSHandshakeType::CLIENT_HELLO:
            success = parse_client_hello(handshake_payload, handshake_payload_length, message.client_hello);
            break;
            
        case TLSHandshakeType::SERVER_HELLO:
            success = parse_server_hello(handshake_payload, handshake_payload_length, message.server_hello);
            break;
            
        case TLSHandshakeType::CERTIFICATE:
            success = parse_certificate(handshake_payload, handshake_payload_length, message.certificates);
            break;
            
        default:
            // For other handshake messages, just mark as successfully parsed
            success = true;
            break;
    }
    
    if (success) {
        handshake_messages_parsed_++;
    }
    
    return success;
}

bool HTTPSParser::parse_client_hello(const uint8_t* data, size_t length, ClientHello& client_hello) {
    if (length < 38) {  // Minimum ClientHello size
        return false;
    }
    
    size_t offset = 0;
    
    // Parse version
    client_hello.version = parse_version(read_uint16(data + offset));
    offset += 2;
    
    // Parse random (32 bytes)
    client_hello.random.assign(data + offset, data + offset + 32);
    offset += 32;
    
    // Parse session ID
    uint8_t session_id_length = data[offset++];
    if (offset + session_id_length > length) {
        return false;
    }
    client_hello.session_id.assign(data + offset, data + offset + session_id_length);
    offset += session_id_length;
    
    // Parse cipher suites
    if (offset + 2 > length) {
        return false;
    }
    uint16_t cipher_suites_length = read_uint16(data + offset);
    offset += 2;
    
    if (offset + cipher_suites_length > length || cipher_suites_length % 2 != 0) {
        return false;
    }
    
    for (size_t i = 0; i < cipher_suites_length; i += 2) {
        client_hello.cipher_suites.push_back(read_uint16(data + offset + i));
    }
    offset += cipher_suites_length;
    
    // Parse compression methods
    if (offset >= length) {
        return false;
    }
    uint8_t compression_methods_length = data[offset++];
    if (offset + compression_methods_length > length) {
        return false;
    }
    client_hello.compression_methods.assign(data + offset, data + offset + compression_methods_length);
    offset += compression_methods_length;
    
    // Parse extensions (if present)
    if (offset < length) {
        if (offset + 2 > length) {
            return false;
        }
        uint16_t extensions_length = read_uint16(data + offset);
        offset += 2;
        
        if (offset + extensions_length <= length) {
            parse_extensions(data + offset, extensions_length, client_hello.extensions);
        }
    }
    
    return true;
}

bool HTTPSParser::parse_server_hello(const uint8_t* data, size_t length, ServerHello& server_hello) {
    if (length < 38) {  // Minimum ServerHello size
        return false;
    }
    
    size_t offset = 0;
    
    // Parse version
    server_hello.version = parse_version(read_uint16(data + offset));
    offset += 2;
    
    // Parse random (32 bytes)
    server_hello.random.assign(data + offset, data + offset + 32);
    offset += 32;
    
    // Parse session ID
    uint8_t session_id_length = data[offset++];
    if (offset + session_id_length > length) {
        return false;
    }
    server_hello.session_id.assign(data + offset, data + offset + session_id_length);
    offset += session_id_length;
    
    // Parse cipher suite
    if (offset + 2 > length) {
        return false;
    }
    server_hello.cipher_suite = read_uint16(data + offset);
    offset += 2;
    
    // Parse compression method
    if (offset >= length) {
        return false;
    }
    server_hello.compression_method = data[offset++];
    
    // Parse extensions (if present)
    if (offset < length) {
        if (offset + 2 > length) {
            return false;
        }
        uint16_t extensions_length = read_uint16(data + offset);
        offset += 2;
        
        if (offset + extensions_length <= length) {
            parse_extensions(data + offset, extensions_length, server_hello.extensions);
        }
    }
    
    return true;
}

bool HTTPSParser::parse_certificate(const uint8_t* data, size_t length, std::vector<Certificate>& certificates) {
    if (length < 3) {
        return false;
    }
    
    // Parse certificates length (24-bit)
    uint32_t certificates_length = read_uint24(data);
    if (certificates_length + 3 != length) {
        return false;
    }
    
    size_t offset = 3;
    
    while (offset < length) {
        if (offset + 3 > length) {
            break;
        }
        
        uint32_t cert_length = read_uint24(data + offset);
        offset += 3;
        
        if (offset + cert_length > length) {
            break;
        }
        
        Certificate cert = parse_x509_certificate(data + offset, cert_length);
        certificates.push_back(cert);
        
        offset += cert_length;
    }
    
    return !certificates.empty();
}

bool HTTPSParser::parse_extensions(const uint8_t* data, size_t length, std::vector<TLSExtension>& extensions) {
    size_t offset = 0;
    
    while (offset + 4 <= length) {
        TLSExtension extension;
        
        extension.type = read_uint16(data + offset);
        extension.length = read_uint16(data + offset + 2);
        offset += 4;
        
        if (offset + extension.length > length) {
            break;
        }
        
        extension.data.assign(data + offset, data + offset + extension.length);
        extension.name = extension_type_to_string(extension.type);
        
        // Parse specific extensions
        if (extension.type == 0) {  // Server Name Indication
            current_session_.server_name = parse_server_name_extension(extension.data);
        }
        
        extensions.push_back(extension);
        offset += extension.length;
    }
    
    return true;
}

bool HTTPSParser::parse_alert(const uint8_t* data, size_t length, TLSAlert& alert) {
    if (length != 2) {
        return false;
    }
    
    alert.level = static_cast<TLSAlertLevel>(data[0]);
    alert.description = static_cast<TLSAlertDescription>(data[1]);
    alert.description_text = alert_description_to_string(alert.description);
    
    alert_messages_++;
    return true;
}

TLSVersion HTTPSParser::parse_version(uint16_t version_bytes) {
    switch (version_bytes) {
        case 0x0300: return TLSVersion::SSL_3_0;
        case 0x0301: return TLSVersion::TLS_1_0;
        case 0x0302: return TLSVersion::TLS_1_1;
        case 0x0303: return TLSVersion::TLS_1_2;
        case 0x0304: return TLSVersion::TLS_1_3;
        default: return TLSVersion::UNKNOWN;
    }
}

std::string HTTPSParser::version_to_string(TLSVersion version) {
    switch (version) {
        case TLSVersion::SSL_3_0: return "SSL 3.0";
        case TLSVersion::TLS_1_0: return "TLS 1.0";
        case TLSVersion::TLS_1_1: return "TLS 1.1";
        case TLSVersion::TLS_1_2: return "TLS 1.2";
        case TLSVersion::TLS_1_3: return "TLS 1.3";
        default: return "Unknown";
    }
}

std::string HTTPSParser::content_type_to_string(TLSContentType type) {
    switch (type) {
        case TLSContentType::CHANGE_CIPHER_SPEC: return "Change Cipher Spec";
        case TLSContentType::ALERT: return "Alert";
        case TLSContentType::HANDSHAKE: return "Handshake";
        case TLSContentType::APPLICATION_DATA: return "Application Data";
        case TLSContentType::HEARTBEAT: return "Heartbeat";
        default: return "Unknown";
    }
}

std::string HTTPSParser::handshake_type_to_string(TLSHandshakeType type) {
    switch (type) {
        case TLSHandshakeType::HELLO_REQUEST: return "Hello Request";
        case TLSHandshakeType::CLIENT_HELLO: return "Client Hello";
        case TLSHandshakeType::SERVER_HELLO: return "Server Hello";
        case TLSHandshakeType::CERTIFICATE: return "Certificate";
        case TLSHandshakeType::SERVER_KEY_EXCHANGE: return "Server Key Exchange";
        case TLSHandshakeType::CERTIFICATE_REQUEST: return "Certificate Request";
        case TLSHandshakeType::SERVER_HELLO_DONE: return "Server Hello Done";
        case TLSHandshakeType::CERTIFICATE_VERIFY: return "Certificate Verify";
        case TLSHandshakeType::CLIENT_KEY_EXCHANGE: return "Client Key Exchange";
        case TLSHandshakeType::FINISHED: return "Finished";
        default: return "Unknown";
    }
}

std::string HTTPSParser::extension_type_to_string(uint16_t extension_type) {
    switch (extension_type) {
        case 0: return "Server Name";
        case 1: return "Max Fragment Length";
        case 5: return "Status Request";
        case 10: return "Supported Groups";
        case 11: return "EC Point Formats";
        case 13: return "Signature Algorithms";
        case 16: return "Application Layer Protocol Negotiation";
        case 23: return "Extended Master Secret";
        case 43: return "Supported Versions";
        case 51: return "Key Share";
        default: return "Unknown (" + std::to_string(extension_type) + ")";
    }
}

std::string HTTPSParser::parse_server_name_extension(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        return "";
    }
    
    // Skip server name list length (2 bytes)
    // Skip name type (1 byte, should be 0 for hostname)
    // Read name length (2 bytes)
    uint16_t name_length = (data[3] << 8) | data[4];
    
    if (data.size() < 5 + static_cast<size_t>(name_length)) {
        return "";
    }
    
    return std::string(data.begin() + 5, data.begin() + 5 + name_length);
}

void HTTPSParser::update_session_state(const HTTPSMessage& message) {
    switch (message.record_header.content_type) {
        case TLSContentType::HANDSHAKE:
            switch (message.handshake_header.msg_type) {
                case TLSHandshakeType::CLIENT_HELLO:
                    current_session_.state = TLSConnectionState::CLIENT_HELLO_SENT;
                    break;
                    
                case TLSHandshakeType::SERVER_HELLO:
                    current_session_.state = TLSConnectionState::SERVER_HELLO_RECEIVED;
                    current_session_.negotiated_version = message.server_hello.version;
                    current_session_.negotiated_cipher_suite = message.server_hello.cipher_suite;
                    current_session_.session_id = message.server_hello.session_id;
                    break;
                    
                case TLSHandshakeType::CERTIFICATE:
                    current_session_.state = TLSConnectionState::CERTIFICATE_RECEIVED;
                    current_session_.certificates = message.certificates;
                    break;
                    
                case TLSHandshakeType::FINISHED:
                    current_session_.state = TLSConnectionState::HANDSHAKE_COMPLETED;
                    break;
                    
                default:
                    break;
            }
            break;
            
        case TLSContentType::APPLICATION_DATA:
            if (current_session_.state == TLSConnectionState::HANDSHAKE_COMPLETED) {
                current_session_.state = TLSConnectionState::APPLICATION_DATA;
            }
            break;
            
        case TLSContentType::ALERT:
            current_session_.state = TLSConnectionState::ALERT_RECEIVED;
            break;
            
        default:
            break;
    }
}

bool HTTPSParser::is_valid_tls_record(const TLSRecordHeader& header) {
    // Check content type
    if (header.content_type == TLSContentType::UNKNOWN) {
        return false;
    }
    
    // Check version
    if (header.version == TLSVersion::UNKNOWN) {
        return false;
    }
    
    // Check length (TLS records can be up to 2^14 bytes)
    if (header.length > 16384) {
        return false;
    }
    
    return true;
}

bool HTTPSParser::is_valid_handshake_message(const TLSHandshakeHeader& header) {
    return header.msg_type != TLSHandshakeType::UNKNOWN && header.length > 0;
}

void HTTPSParser::reset_session() {
    current_session_ = TLSSession();
}

uint16_t HTTPSParser::read_uint16(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}

uint32_t HTTPSParser::read_uint24(const uint8_t* data) {
    return (data[0] << 16) | (data[1] << 8) | data[2];
}

uint32_t HTTPSParser::read_uint32(const uint8_t* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

Certificate HTTPSParser::parse_x509_certificate(const uint8_t* data, size_t length) {
    Certificate cert;
    cert.raw_data.assign(data, data + length);
    
    // Basic X.509 parsing would go here
    // For now, just store the raw data
    cert.subject = "[Certificate parsing not implemented]";
    cert.issuer = "[Certificate parsing not implemented]";
    
    return cert;
}

void HTTPSParser::initialize_cipher_suites() {
    // Initialize common cipher suites
    CipherSuite suite1; suite1.id = 0x002F; suite1.name = "TLS_RSA_WITH_AES_128_CBC_SHA"; suite1.key_exchange = "RSA"; suite1.authentication = "RSA"; suite1.encryption = "AES_128_CBC"; suite1.mac = "SHA"; cipher_suite_db_[0x002F] = suite1;
    CipherSuite suite2; suite2.id = 0x0035; suite2.name = "TLS_RSA_WITH_AES_256_CBC_SHA"; suite2.key_exchange = "RSA"; suite2.authentication = "RSA"; suite2.encryption = "AES_256_CBC"; suite2.mac = "SHA"; cipher_suite_db_[0x0035] = suite2;
    CipherSuite suite3; suite3.id = 0x003C; suite3.name = "TLS_RSA_WITH_AES_128_CBC_SHA256"; suite3.key_exchange = "RSA"; suite3.authentication = "RSA"; suite3.encryption = "AES_128_CBC"; suite3.mac = "SHA256"; cipher_suite_db_[0x003C] = suite3;
    CipherSuite suite4; suite4.id = 0x009C; suite4.name = "TLS_RSA_WITH_AES_128_GCM_SHA256"; suite4.key_exchange = "RSA"; suite4.authentication = "RSA"; suite4.encryption = "AES_128_GCM"; suite4.mac = "SHA256"; cipher_suite_db_[0x009C] = suite4;
    CipherSuite suite5; suite5.id = 0x009D; suite5.name = "TLS_RSA_WITH_AES_256_GCM_SHA384"; suite5.key_exchange = "RSA"; suite5.authentication = "RSA"; suite5.encryption = "AES_256_GCM"; suite5.mac = "SHA384"; cipher_suite_db_[0x009D] = suite5;
    CipherSuite suite6; suite6.id = 0xC02F; suite6.name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; suite6.key_exchange = "ECDHE"; suite6.authentication = "RSA"; suite6.encryption = "AES_128_GCM"; suite6.mac = "SHA256"; cipher_suite_db_[0xC02F] = suite6;
    CipherSuite suite7; suite7.id = 0xC030; suite7.name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"; suite7.key_exchange = "ECDHE"; suite7.authentication = "RSA"; suite7.encryption = "AES_256_GCM"; suite7.mac = "SHA384"; cipher_suite_db_[0xC030] = suite7;
}

CipherSuite HTTPSParser::get_cipher_suite_info(uint16_t cipher_suite_id) {
    auto it = cipher_suite_db_.find(cipher_suite_id);
    if (it != cipher_suite_db_.end()) {
        return it->second;
    }
    
    CipherSuite unknown;
    unknown.id = cipher_suite_id;
    unknown.name = "Unknown (0x" + std::to_string(cipher_suite_id) + ")";
    return unknown;
}

std::string HTTPSParser::cipher_suite_to_string(uint16_t cipher_suite_id) {
    return get_cipher_suite_info(cipher_suite_id).name;
}

std::string HTTPSParser::alert_level_to_string(TLSAlertLevel level) {
    switch (level) {
        case TLSAlertLevel::WARNING: return "Warning";
        case TLSAlertLevel::FATAL: return "Fatal";
        default: return "Unknown";
    }
}

std::string HTTPSParser::alert_description_to_string(TLSAlertDescription desc) {
    switch (desc) {
        case TLSAlertDescription::CLOSE_NOTIFY: return "Close Notify";
        case TLSAlertDescription::UNEXPECTED_MESSAGE: return "Unexpected Message";
        case TLSAlertDescription::BAD_RECORD_MAC: return "Bad Record MAC";
        case TLSAlertDescription::HANDSHAKE_FAILURE: return "Handshake Failure";
        case TLSAlertDescription::BAD_CERTIFICATE: return "Bad Certificate";
        case TLSAlertDescription::CERTIFICATE_EXPIRED: return "Certificate Expired";
        case TLSAlertDescription::PROTOCOL_VERSION: return "Protocol Version";
        default: return "Unknown";
    }
}

double HTTPSParser::get_progress() const noexcept {
    // 基于握手消息数量计算进度
    if (handshake_messages_parsed_ >= 4) {
        return 1.0; // 握手完成
    }
    return static_cast<double>(handshake_messages_parsed_) / 4.0;
}

} // namespace protocol_parser::parsers