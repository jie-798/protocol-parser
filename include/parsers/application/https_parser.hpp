#ifndef HTTPS_PARSER_HPP
#define HTTPS_PARSER_HPP

#include "../base_parser.hpp"
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <chrono>

namespace protocol_parser::parsers {

// TLS Content Types
enum class TLSContentType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    HEARTBEAT = 24,
    UNKNOWN = 255
};

// TLS Handshake Message Types
enum class TLSHandshakeType : uint8_t {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    CERTIFICATE_URL = 21,
    CERTIFICATE_STATUS = 22,
    KEY_UPDATE = 24,
    MESSAGE_HASH = 254,
    UNKNOWN = 255
};

// TLS Versions
enum class TLSVersion : uint16_t {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
    UNKNOWN = 0x0000
};

// TLS Alert Levels
enum class TLSAlertLevel : uint8_t {
    WARNING = 1,
    FATAL = 2,
    UNKNOWN = 255
};

// TLS Alert Descriptions
enum class TLSAlertDescription : uint8_t {
    CLOSE_NOTIFY = 0,
    UNEXPECTED_MESSAGE = 10,
    BAD_RECORD_MAC = 20,
    DECRYPTION_FAILED = 21,
    RECORD_OVERFLOW = 22,
    DECOMPRESSION_FAILURE = 30,
    HANDSHAKE_FAILURE = 40,
    NO_CERTIFICATE = 41,
    BAD_CERTIFICATE = 42,
    UNSUPPORTED_CERTIFICATE = 43,
    CERTIFICATE_REVOKED = 44,
    CERTIFICATE_EXPIRED = 45,
    CERTIFICATE_UNKNOWN = 46,
    ILLEGAL_PARAMETER = 47,
    UNKNOWN_CA = 48,
    ACCESS_DENIED = 49,
    DECODE_ERROR = 50,
    DECRYPT_ERROR = 51,
    EXPORT_RESTRICTION = 60,
    PROTOCOL_VERSION = 70,
    INSUFFICIENT_SECURITY = 71,
    INTERNAL_ERROR = 80,
    USER_CANCELED = 90,
    NO_RENEGOTIATION = 100,
    UNSUPPORTED_EXTENSION = 110,
    UNKNOWN = 255
};

// TLS Connection State
enum class TLSConnectionState {
    INITIAL,
    CLIENT_HELLO_SENT,
    SERVER_HELLO_RECEIVED,
    CERTIFICATE_RECEIVED,
    KEY_EXCHANGE_COMPLETED,
    HANDSHAKE_COMPLETED,
    APPLICATION_DATA,
    ALERT_RECEIVED,
    CONNECTION_CLOSED,
    ERROR_STATE
};

// TLS Record Header
struct TLSRecordHeader {
    TLSContentType content_type;
    TLSVersion version;
    uint16_t length;
    
    TLSRecordHeader() : content_type(TLSContentType::UNKNOWN), 
                       version(TLSVersion::UNKNOWN), length(0) {}
};

// TLS Handshake Header
struct TLSHandshakeHeader {
    TLSHandshakeType msg_type;
    uint32_t length;  // 24-bit length
    
    TLSHandshakeHeader() : msg_type(TLSHandshakeType::UNKNOWN), length(0) {}
};

// Cipher Suite Information
struct CipherSuite {
    uint16_t id;
    std::string name;
    std::string key_exchange;
    std::string authentication;
    std::string encryption;
    std::string mac;
    
    CipherSuite() : id(0) {}
};

// TLS Extension
struct TLSExtension {
    uint16_t type;
    uint16_t length;
    std::vector<uint8_t> data;
    std::string name;
    
    TLSExtension() : type(0), length(0) {}
};

// Client Hello Message
struct ClientHello {
    TLSVersion version;
    std::vector<uint8_t> random;  // 32 bytes
    std::vector<uint8_t> session_id;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint8_t> compression_methods;
    std::vector<TLSExtension> extensions;
    
    ClientHello() : version(TLSVersion::UNKNOWN) {}
};

// Server Hello Message
struct ServerHello {
    TLSVersion version;
    std::vector<uint8_t> random;  // 32 bytes
    std::vector<uint8_t> session_id;
    uint16_t cipher_suite;
    uint8_t compression_method;
    std::vector<TLSExtension> extensions;
    
    ServerHello() : version(TLSVersion::UNKNOWN), cipher_suite(0), compression_method(0) {}
};

// Certificate Information
struct Certificate {
    std::vector<uint8_t> raw_data;
    std::string subject;
    std::string issuer;
    std::string serial_number;
    std::string not_before;
    std::string not_after;
    std::vector<std::string> san_dns_names;  // Subject Alternative Names
    
    Certificate() {}
};

// TLS Alert Message
struct TLSAlert {
    TLSAlertLevel level;
    TLSAlertDescription description;
    std::string description_text;
    
    TLSAlert() : level(TLSAlertLevel::UNKNOWN), description(TLSAlertDescription::UNKNOWN) {}
};

// TLS Session Information
struct TLSSession {
    TLSConnectionState state;
    TLSVersion negotiated_version;
    uint16_t negotiated_cipher_suite;
    std::vector<uint8_t> session_id;
    std::string server_name;  // SNI
    std::vector<Certificate> certificates;
    bool is_resumed_session;
    
    TLSSession() : state(TLSConnectionState::INITIAL), 
                  negotiated_version(TLSVersion::UNKNOWN),
                  negotiated_cipher_suite(0),
                  is_resumed_session(false) {}
};

// Main HTTPS/TLS Message Structure
struct HTTPSMessage {
    TLSRecordHeader record_header;
    TLSHandshakeHeader handshake_header;  // Only for handshake messages
    
    // Message content (union-like structure)
    ClientHello client_hello;
    ServerHello server_hello;
    std::vector<Certificate> certificates;
    TLSAlert alert;
    std::vector<uint8_t> application_data;
    std::vector<uint8_t> raw_handshake_data;
    
    TLSSession session_info;
    
    // Timing information
    std::chrono::system_clock::time_point timestamp;
    
    HTTPSMessage() {
        timestamp = std::chrono::system_clock::now();
    }
};

class HTTPSParser : public BaseParser {
public:
    HTTPSParser();
    virtual ~HTTPSParser() = default;
    
    // BaseParser interface implementation
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    
    // TLS record parsing
    bool parse_tls_record(const uint8_t* data, size_t length, HTTPSMessage& message);
    bool parse_record_header(const uint8_t* data, TLSRecordHeader& header);
    
    // Handshake message parsing
    bool parse_handshake_message(const uint8_t* data, size_t length, HTTPSMessage& message);
    bool parse_client_hello(const uint8_t* data, size_t length, ClientHello& client_hello);
    bool parse_server_hello(const uint8_t* data, size_t length, ServerHello& server_hello);
    bool parse_certificate(const uint8_t* data, size_t length, std::vector<Certificate>& certificates);
    
    // Extension parsing
    bool parse_extensions(const uint8_t* data, size_t length, std::vector<TLSExtension>& extensions);
    bool parse_extension(const uint8_t* data, size_t length, TLSExtension& extension);
    
    // Alert parsing
    bool parse_alert(const uint8_t* data, size_t length, TLSAlert& alert);
    
    // Utility functions
    TLSVersion parse_version(uint16_t version_bytes);
    std::string version_to_string(TLSVersion version);
    std::string content_type_to_string(TLSContentType type);
    std::string handshake_type_to_string(TLSHandshakeType type);
    std::string alert_level_to_string(TLSAlertLevel level);
    std::string alert_description_to_string(TLSAlertDescription desc);
    
    // Cipher suite utilities
    CipherSuite get_cipher_suite_info(uint16_t cipher_suite_id);
    std::string cipher_suite_to_string(uint16_t cipher_suite_id);
    
    // Extension utilities
    std::string extension_type_to_string(uint16_t extension_type);
    std::string parse_server_name_extension(const std::vector<uint8_t>& data);
    
    // Session state management
    void update_session_state(const HTTPSMessage& message);
    
    // Validation functions
    bool is_valid_tls_record(const TLSRecordHeader& header);
    bool is_valid_handshake_message(const TLSHandshakeHeader& header);
    
    // State queries
    TLSConnectionState get_connection_state() const { return current_session_.state; }
    TLSVersion get_negotiated_version() const { return current_session_.negotiated_version; }
    std::string get_server_name() const { return current_session_.server_name; }
    
    // Statistics
    size_t get_handshake_messages_parsed() const { return handshake_messages_parsed_; }
    size_t get_application_data_records() const { return application_data_records_; }
    size_t get_alert_messages() const { return alert_messages_; }
    
private:
    TLSSession current_session_;
    std::vector<uint8_t> buffer_;  // For handling fragmented records
    
    // Statistics
    size_t handshake_messages_parsed_;
    size_t application_data_records_;
    size_t alert_messages_;
    
    // Helper methods
    void reset_session();
    uint16_t read_uint16(const uint8_t* data);
    uint32_t read_uint24(const uint8_t* data);
    uint32_t read_uint32(const uint8_t* data);
    
    // Certificate parsing helpers
    Certificate parse_x509_certificate(const uint8_t* data, size_t length);
    std::string extract_certificate_field(const uint8_t* data, size_t length, const std::string& field);
    
    // Cipher suite database
    void initialize_cipher_suites();
    std::map<uint16_t, CipherSuite> cipher_suite_db_;
};

} // namespace protocol_parser::parsers

#endif // HTTPS_PARSER_HPP