#pragma once

#include "../base_parser.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <optional>

namespace protocol_parser::parsers {

// SSH Protocol versions
enum class SSHVersion {
    SSH_1_0,
    SSH_1_3,
    SSH_1_5,
    SSH_1_99,
    SSH_2_0,
    UNKNOWN
};

// SSH Message types (RFC 4253)
enum class SSHMessageType : uint8_t {
    // Transport layer protocol
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    
    // Key exchange
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    
    // Key exchange method specific (30-49)
    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,
    
    // User authentication protocol
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    
    // Connection protocol
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
    
    UNKNOWN_MESSAGE = 255
};

// SSH Connection state
enum class SSHConnectionState {
    VERSION_EXCHANGE,
    KEY_EXCHANGE,
    AUTHENTICATION,
    CONNECTION,
    DISCONNECTED,
    UNKNOWN
};

// SSH Disconnect reason codes
enum class SSHDisconnectReason : uint32_t {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
};

// SSH Version exchange structure
struct SSHVersionExchange {
    SSHVersion version;
    std::string version_string;
    std::string software_version;
    std::string comments;
};

// SSH Binary packet structure
struct SSHBinaryPacket {
    uint32_t packet_length;
    uint8_t padding_length;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> padding;
    std::array<uint8_t, 20> mac; // Maximum MAC size
    bool has_mac;
};

// SSH Key exchange init structure
struct SSHKeyExchangeInit {
    std::array<uint8_t, 16> cookie;
    std::vector<std::string> kex_algorithms;
    std::vector<std::string> server_host_key_algorithms;
    std::vector<std::string> encryption_algorithms_client_to_server;
    std::vector<std::string> encryption_algorithms_server_to_client;
    std::vector<std::string> mac_algorithms_client_to_server;
    std::vector<std::string> mac_algorithms_server_to_client;
    std::vector<std::string> compression_algorithms_client_to_server;
    std::vector<std::string> compression_algorithms_server_to_client;
    std::vector<std::string> languages_client_to_server;
    std::vector<std::string> languages_server_to_client;
    bool first_kex_packet_follows;
    uint32_t reserved;
};

// SSH Message structures
struct SSHDisconnectMessage {
    uint32_t reason_code;
    std::string description;
    std::string language_tag;
};

struct SSHServiceMessage {
    std::string service_name;
};

// SSH Message structure
struct SSHMessage {
    SSHMessageType type;
    std::vector<uint8_t> data;
    
    // Parsed message data based on type (using optional for type safety)
    std::optional<SSHKeyExchangeInit> kex_init;
    std::optional<SSHDisconnectMessage> disconnect;
    std::optional<SSHServiceMessage> service_request;
    std::optional<SSHServiceMessage> service_accept;
    
    SSHMessage() : type(SSHMessageType::UNKNOWN_MESSAGE) {}
};

// SSH Connection information
struct SSHConnection {
    SSHConnectionState state;
    SSHVersionExchange client_version;
    SSHVersionExchange server_version;
    bool version_exchange_complete;
    bool key_exchange_complete;
    bool authentication_complete;
    std::vector<SSHMessage> messages;
};

class SSHParser : public BaseParser {
public:
    SSHParser() = default;
    ~SSHParser() override = default;

    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    [[nodiscard]] std::string get_protocol_name() const { return "SSH"; }
    [[nodiscard]] uint16_t get_protocol_id() const { return 22; } // SSH port

    // SSH-specific methods
    [[nodiscard]] const SSHConnection& get_ssh_connection() const { return ssh_connection_; }
    [[nodiscard]] SSHConnectionState get_connection_state() const { return ssh_connection_.state; }
    [[nodiscard]] const SSHVersionExchange& get_client_version() const { return ssh_connection_.client_version; }
    [[nodiscard]] const SSHVersionExchange& get_server_version() const { return ssh_connection_.server_version; }
    [[nodiscard]] const std::vector<SSHMessage>& get_messages() const { return ssh_connection_.messages; }
    
    // State check methods
    [[nodiscard]] bool is_version_exchange_complete() const { return ssh_connection_.version_exchange_complete; }
    [[nodiscard]] bool is_key_exchange_complete() const { return ssh_connection_.key_exchange_complete; }
    [[nodiscard]] bool is_authentication_complete() const { return ssh_connection_.authentication_complete; }
    [[nodiscard]] bool is_connection_established() const;
    
    // Version methods
    [[nodiscard]] SSHVersion get_negotiated_version() const;
    [[nodiscard]] bool is_ssh2() const;
    [[nodiscard]] bool is_ssh1() const;
    
    // Message methods
    [[nodiscard]] SSHMessage get_last_message() const;
    [[nodiscard]] size_t get_message_count() const { return ssh_connection_.messages.size(); }
    
    // Utility methods
    [[nodiscard]] std::string version_to_string(SSHVersion version) const;
    [[nodiscard]] SSHVersion string_to_version(const std::string& version_str) const;
    [[nodiscard]] std::string message_type_to_string(SSHMessageType type) const;
    [[nodiscard]] std::string disconnect_reason_to_string(SSHDisconnectReason reason) const;

private:
    SSHConnection ssh_connection_;
    
    // Helper methods
    [[nodiscard]] ParseResult parse_version_exchange(const BufferView& buffer);
    [[nodiscard]] ParseResult parse_binary_packet(const BufferView& buffer);
    [[nodiscard]] ParseResult parse_ssh_message(const SSHBinaryPacket& packet);
    [[nodiscard]] ParseResult parse_kex_init(const std::vector<uint8_t>& payload, SSHKeyExchangeInit& kex_init);
    
    [[nodiscard]] bool is_version_line_complete(const BufferView& buffer) const;
    [[nodiscard]] bool validate_version_string(const std::string& version_str) const;
    [[nodiscard]] bool validate_ssh_packet(const BufferView& buffer) const;
    
    [[nodiscard]] std::vector<std::string> parse_name_list(const std::vector<uint8_t>& data, size_t& offset) const;
    [[nodiscard]] std::string read_string(const std::vector<uint8_t>& data, size_t& offset) const;
    [[nodiscard]] uint32_t read_uint32(const std::vector<uint8_t>& data, size_t& offset) const;
    [[nodiscard]] uint8_t read_uint8(const std::vector<uint8_t>& data, size_t& offset) const;
    
    void reset() noexcept;
    void update_connection_state();
};

} // namespace protocol_parser::parsers