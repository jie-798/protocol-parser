#pragma once

#include "../base_parser.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace protocol_parser::parsers {

// FTP Command types
enum class FTPCommand {
    USER,       // Username
    PASS,       // Password
    ACCT,       // Account
    CWD,        // Change working directory
    CDUP,       // Change to parent directory
    SMNT,       // Structure mount
    QUIT,       // Logout
    REIN,       // Reinitialize
    PORT,       // Data port
    PASV,       // Passive mode
    TYPE,       // Representation type
    STRU,       // File structure
    MODE,       // Transfer mode
    RETR,       // Retrieve file
    STOR,       // Store file
    STOU,       // Store unique
    APPE,       // Append
    ALLO,       // Allocate
    REST,       // Restart
    RNFR,       // Rename from
    RNTO,       // Rename to
    ABOR,       // Abort
    DELE,       // Delete
    RMD,        // Remove directory
    MKD,        // Make directory
    PWD,        // Print working directory
    LIST,       // List files
    NLST,       // Name list
    SITE,       // Site parameters
    SYST,       // System
    STAT,       // Status
    HELP,       // Help
    NOOP,       // No operation
    FEAT,       // Feature list
    OPTS,       // Options
    AUTH,       // Authentication
    PBSZ,       // Protection buffer size
    PROT,       // Data channel protection
    UNKNOWN
};

// FTP Response codes
enum class FTPResponseCode {
    // 1xx - Positive preliminary reply
    RESTART_MARKER = 110,
    SERVICE_READY_SOON = 120,
    DATA_CONNECTION_OPEN = 125,
    FILE_STATUS_OK = 150,
    
    // 2xx - Positive completion reply
    COMMAND_OK = 200,
    COMMAND_SUPERFLUOUS = 202,
    SYSTEM_STATUS = 211,
    DIRECTORY_STATUS = 212,
    FILE_STATUS = 213,
    HELP_MESSAGE = 214,
    SYSTEM_TYPE = 215,
    SERVICE_READY = 220,
    SERVICE_CLOSING = 221,
    DATA_CONNECTION_OPEN_NO_TRANSFER = 225,
    DATA_CONNECTION_CLOSED = 226,
    PASSIVE_MODE = 227,
    USER_LOGGED_IN = 230,
    FILE_ACTION_OK = 250,
    PATHNAME_CREATED = 257,
    
    // 3xx - Positive intermediate reply
    USER_NAME_OK = 331,
    NEED_ACCOUNT = 332,
    FILE_ACTION_PENDING = 350,
    
    // 4xx - Transient negative completion reply
    SERVICE_NOT_AVAILABLE = 421,
    CANNOT_OPEN_DATA_CONNECTION = 425,
    CONNECTION_CLOSED = 426,
    FILE_ACTION_NOT_TAKEN = 450,
    ACTION_ABORTED = 451,
    ACTION_NOT_TAKEN_INSUFFICIENT_STORAGE = 452,
    
    // 5xx - Permanent negative completion reply
    SYNTAX_ERROR = 500,
    SYNTAX_ERROR_PARAMETERS = 501,
    COMMAND_NOT_IMPLEMENTED = 502,
    BAD_SEQUENCE = 503,
    PARAMETER_NOT_IMPLEMENTED = 504,
    NOT_LOGGED_IN = 530,
    NEED_ACCOUNT_FOR_STORING = 532,
    FILE_ACTION_NOT_TAKEN_FILE_UNAVAILABLE = 550,
    ACTION_ABORTED_PAGE_TYPE = 551,
    ACTION_ABORTED_EXCEEDED_STORAGE = 552,
    ACTION_NOT_TAKEN_FILE_NAME = 553,
    
    UNKNOWN_CODE = 0
};

// FTP Message types
enum class FTPMessageType {
    COMMAND,
    RESPONSE,
    UNKNOWN
};

// FTP Command structure
struct FTPCommandMessage {
    FTPCommand command;
    std::string command_str;
    std::string parameters;
};

// FTP Response structure
struct FTPResponseMessage {
    FTPResponseCode code;
    uint16_t code_number;
    std::string message;
    bool is_multiline;
    std::vector<std::string> lines;
};

// FTP Message structure
struct FTPMessage {
    FTPMessageType type;
    union {
        FTPCommandMessage command;
        FTPResponseMessage response;
    };
    
    FTPMessage() : type(FTPMessageType::UNKNOWN) {}
    ~FTPMessage() {
        if (type == FTPMessageType::COMMAND) {
            command.~FTPCommandMessage();
        } else if (type == FTPMessageType::RESPONSE) {
            response.~FTPResponseMessage();
        }
    }
    
    FTPMessage(const FTPMessage& other) : type(other.type) {
        if (type == FTPMessageType::COMMAND) {
            new(&command) FTPCommandMessage(other.command);
        } else if (type == FTPMessageType::RESPONSE) {
            new(&response) FTPResponseMessage(other.response);
        }
    }
    
    FTPMessage& operator=(const FTPMessage& other) {
        if (this != &other) {
            this->~FTPMessage();
            type = other.type;
            if (type == FTPMessageType::COMMAND) {
                new(&command) FTPCommandMessage(other.command);
            } else if (type == FTPMessageType::RESPONSE) {
                new(&response) FTPResponseMessage(other.response);
            }
        }
        return *this;
    }
};

class FTPParser : public BaseParser {
public:
    FTPParser() = default;
    ~FTPParser() override = default;

    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept override;
    
    // Protocol identification methods
    [[nodiscard]] std::string get_protocol_name() const { return "FTP"; }
    [[nodiscard]] uint16_t get_protocol_id() const { return 21; } // FTP control port

    // FTP-specific methods
    [[nodiscard]] const FTPMessage& get_ftp_message() const { return ftp_message_; }
    [[nodiscard]] FTPMessageType get_message_type() const { return ftp_message_.type; }
    [[nodiscard]] bool is_command() const { return ftp_message_.type == FTPMessageType::COMMAND; }
    [[nodiscard]] bool is_response() const { return ftp_message_.type == FTPMessageType::RESPONSE; }
    
    // Command-specific methods
    [[nodiscard]] FTPCommand get_command() const;
    [[nodiscard]] std::string get_command_string() const;
    [[nodiscard]] std::string get_command_parameters() const;
    
    // Response-specific methods
    [[nodiscard]] FTPResponseCode get_response_code() const;
    [[nodiscard]] uint16_t get_response_code_number() const;
    [[nodiscard]] std::string get_response_message() const;
    [[nodiscard]] bool is_multiline_response() const;
    [[nodiscard]] const std::vector<std::string>& get_response_lines() const;
    
    // Status check methods
    [[nodiscard]] bool is_positive_preliminary() const;
    [[nodiscard]] bool is_positive_completion() const;
    [[nodiscard]] bool is_positive_intermediate() const;
    [[nodiscard]] bool is_transient_negative() const;
    [[nodiscard]] bool is_permanent_negative() const;
    
    // Utility methods
    [[nodiscard]] std::string command_to_string(FTPCommand cmd) const;
    [[nodiscard]] FTPCommand string_to_command(const std::string& cmd_str) const;
    [[nodiscard]] std::string response_code_to_string(FTPResponseCode code) const;
    [[nodiscard]] FTPResponseCode number_to_response_code(uint16_t code_num) const;

private:
    FTPMessage ftp_message_;
    
    // Helper methods
    [[nodiscard]] ParseResult parse_command(const std::string& line);
    [[nodiscard]] ParseResult parse_response(const std::string& line);
    [[nodiscard]] ParseResult parse_multiline_response(const BufferView& buffer, size_t start_pos);
    [[nodiscard]] std::string trim(const std::string& str) const;
    [[nodiscard]] std::string to_upper(const std::string& str) const;
    [[nodiscard]] bool validate_ftp_message(const BufferView& buffer) const;
    [[nodiscard]] bool is_complete_line(const BufferView& buffer) const;
};

} // namespace protocol_parser::parsers