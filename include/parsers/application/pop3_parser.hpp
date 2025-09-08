#ifndef POP3_PARSER_HPP
#define POP3_PARSER_HPP

#include "../base_parser.hpp"
#include "core/buffer_view.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>

namespace protocol_parser {

// 引入parsers命名空间的类型
using namespace parsers;
using BufferView = core::BufferView;

// POP3 Commands
enum class POP3Command {
    USER,
    PASS,
    STAT,
    LIST,
    RETR,
    DELE,
    NOOP,
    RSET,
    QUIT,
    TOP,
    UIDL,
    APOP,
    CAPA,
    UNKNOWN
};

// POP3 Response Status
enum class POP3ResponseStatus {
    OK,         // +OK
    ERR,        // -ERR
    UNKNOWN
};

// POP3 Connection State
enum class POP3State {
    AUTHORIZATION,  // Before successful login
    TRANSACTION,    // After successful login
    UPDATE,         // After QUIT command
    CLOSED
};

// POP3 Command Structure
struct POP3CommandMessage {
    POP3Command command;
    std::string command_str;
    std::vector<std::string> arguments;
    std::string raw_line;
    
    POP3CommandMessage() : command(POP3Command::UNKNOWN) {}
};

// POP3 Response Structure
struct POP3ResponseMessage {
    POP3ResponseStatus status;
    std::string status_indicator;  // "+OK" or "-ERR"
    std::string message;
    std::vector<std::string> data_lines;  // For multi-line responses
    bool is_multiline;
    std::string raw_response;
    
    POP3ResponseMessage() : status(POP3ResponseStatus::UNKNOWN), is_multiline(false) {}
};

// POP3 Session Information
struct POP3Session {
    POP3State state;
    std::string username;
    bool authenticated;
    int message_count;
    size_t mailbox_size;
    std::map<int, bool> deleted_messages;  // Message number -> deleted flag
    
    POP3Session() : state(POP3State::AUTHORIZATION), authenticated(false), 
                   message_count(0), mailbox_size(0) {}
};

// Main POP3 Message Structure
struct POP3Message {
    enum Type {
        COMMAND,
        RESPONSE
    } type;
    
    POP3CommandMessage command;
    POP3ResponseMessage response;
    POP3Session session_info;
    
    // Timing information
    std::chrono::system_clock::time_point timestamp;
    
    POP3Message() : type(COMMAND) {
        timestamp = std::chrono::system_clock::now();
    }
};

class POP3Parser : public parsers::BaseParser {
public:
    POP3Parser();
    virtual ~POP3Parser() = default;
    
    // BaseParser interface implementation
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const core::BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept override;
    
    // POP3-specific parsing methods
    bool parse_command(const std::string& line, POP3CommandMessage& cmd);
    bool parse_response(const std::string& line, POP3ResponseMessage& resp);
    bool parse_multiline_response(const std::vector<std::string>& lines, POP3ResponseMessage& resp);
    
    // Command parsing helpers
    POP3Command string_to_command(const std::string& cmd_str);
    std::string command_to_string(POP3Command cmd);
    
    // Response parsing helpers
    POP3ResponseStatus parse_status_indicator(const std::string& indicator);
    std::string status_to_string(POP3ResponseStatus status);
    
    // Session state management
    void update_session_state(const POP3CommandMessage& cmd, const POP3ResponseMessage& resp);
    bool is_multiline_command(POP3Command cmd);
    
    // Validation functions
    bool is_valid_command_syntax(const POP3CommandMessage& cmd);
    bool is_valid_response_format(const POP3ResponseMessage& resp);
    
    // Utility functions
    std::vector<std::string> split_lines(const std::string& data);
    std::string trim_whitespace(const std::string& str);
    bool is_end_of_multiline(const std::string& line);
    
    // State queries
    POP3State get_current_state() const { return current_session_.state; }
    bool is_authenticated() const { return current_session_.authenticated; }
    int get_message_count() const { return current_session_.message_count; }
    
    // Statistics
    size_t get_commands_parsed() const { return commands_parsed_; }
    size_t get_responses_parsed() const { return responses_parsed_; }
    
private:
    POP3Session current_session_;
    std::string buffer_;  // For handling partial data
    bool expecting_multiline_;
    POP3Command pending_multiline_command_;
    
    // Statistics
    size_t commands_parsed_;
    size_t responses_parsed_;
    
    // Helper methods
    void reset_session();
    void handle_authentication_success(const std::string& username);
    void handle_stat_response(const std::string& response);
    void handle_list_response(const std::vector<std::string>& lines);
};

} // namespace protocol_parser

#endif // POP3_PARSER_HPP