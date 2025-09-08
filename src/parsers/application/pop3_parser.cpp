#include "../../../include/parsers/application/pop3_parser.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <chrono>

namespace protocol_parser {

POP3Parser::POP3Parser() 
    : expecting_multiline_(false), 
      pending_multiline_command_(POP3Command::UNKNOWN),
      commands_parsed_(0), 
      responses_parsed_(0) {
    reset_session();
}

const ProtocolInfo& POP3Parser::get_protocol_info() const noexcept {
    static const ProtocolInfo info{
        "POP3",     // name
        110,        // type (POP3 port)
        0,          // header_size (variable)
        4,          // min_packet_size
        65535       // max_packet_size
    };
    return info;
}

bool POP3Parser::can_parse(const core::BufferView& buffer) const noexcept {
    if (buffer.size() < 4) {
        return false;
    }
    
    std::string data(reinterpret_cast<const char*>(buffer.data()), std::min(buffer.size(), size_t(10)));
    
    // Check for POP3 response indicators
    if (data.substr(0, 3) == "+OK" || data.substr(0, 4) == "-ERR") {
        return true;
    }
    
    // Check for common POP3 commands
    std::transform(data.begin(), data.end(), data.begin(), ::toupper);
    return data.find("USER") == 0 || data.find("PASS") == 0 || 
           data.find("STAT") == 0 || data.find("LIST") == 0 ||
           data.find("RETR") == 0 || data.find("QUIT") == 0;
}

ParseResult POP3Parser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;
    if (buffer.size() == 0) {
        return ParseResult::NeedMoreData;
    }
    
    try {
        // Convert to string and add to buffer
        std::string input(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        buffer_ += input;
        
        // Split into lines
        std::vector<std::string> lines = split_lines(buffer_);
        
        // If no complete lines, wait for more data
        if (lines.empty()) {
            return ParseResult::NeedMoreData;
        }
        
        // Keep incomplete line in buffer
        if (!buffer_.empty() && buffer_.back() != '\n') {
            buffer_ = lines.back();
            lines.pop_back();
        } else {
            buffer_.clear();
        }
        
        // Process each complete line
        for (const auto& line : lines) {
            std::string trimmed_line = trim_whitespace(line);
            
            if (trimmed_line.empty()) {
                continue;
            }
            
            if (trimmed_line.substr(0, 3) == "+OK" || trimmed_line.substr(0, 4) == "-ERR") {
                // This is a response
                POP3ResponseMessage response;
                if (parse_response(trimmed_line, response)) {
                    responses_parsed_++;
                    
                    // Update session state based on pending command
                    POP3CommandMessage dummy_cmd;
                    dummy_cmd.command = pending_multiline_command_;
                    update_session_state(dummy_cmd, response);
                }
            } else {
                // This is a command
                POP3CommandMessage command;
                if (parse_command(trimmed_line, command)) {
                    commands_parsed_++;
                    
                    // Set pending multiline command if applicable
                    if (is_multiline_command(command.command)) {
                        pending_multiline_command_ = command.command;
                    }
                }
            }
        }
        
        context.state = ParserState::Complete;
        return ParseResult::Success;
        
    } catch (const std::exception& e) {
        error_message_ = e.what();
        context.state = ParserState::Error;
        return ParseResult::InternalError;
    }
}

void POP3Parser::reset() noexcept {
    buffer_.clear();
    expecting_multiline_ = false;
    pending_multiline_command_ = POP3Command::UNKNOWN;
    commands_parsed_ = 0;
    responses_parsed_ = 0;
    error_message_.clear();
    reset_session();
}

std::string POP3Parser::get_error_message() const noexcept {
    return error_message_;
}

bool POP3Parser::parse_command(const std::string& line, POP3CommandMessage& cmd) {
    cmd.raw_line = line;
    
    std::istringstream iss(line);
    std::string command_str;
    iss >> command_str;
    
    // Convert to uppercase for comparison
    std::transform(command_str.begin(), command_str.end(), command_str.begin(), ::toupper);
    cmd.command_str = command_str;
    cmd.command = string_to_command(command_str);
    
    // Parse arguments
    std::string arg;
    while (iss >> arg) {
        cmd.arguments.push_back(arg);
    }
    
    return is_valid_command_syntax(cmd);
}

bool POP3Parser::parse_response(const std::string& line, POP3ResponseMessage& resp) {
    resp.raw_response = line;
    
    if (line.length() < 3) {
        return false;
    }
    
    // Parse status indicator
    if (line.substr(0, 3) == "+OK") {
        resp.status = POP3ResponseStatus::OK;
        resp.status_indicator = "+OK";
        if (line.length() > 3) {
            resp.message = trim_whitespace(line.substr(3));
        }
    } else if (line.substr(0, 4) == "-ERR") {
        resp.status = POP3ResponseStatus::ERR;
        resp.status_indicator = "-ERR";
        if (line.length() > 4) {
            resp.message = trim_whitespace(line.substr(4));
        }
    } else {
        resp.status = POP3ResponseStatus::UNKNOWN;
        resp.message = line;
        return false;
    }
    
    return is_valid_response_format(resp);
}

bool POP3Parser::parse_multiline_response(const std::vector<std::string>& lines, POP3ResponseMessage& resp) {
    if (lines.empty()) {
        return false;
    }
    
    // First line is the status line
    if (!parse_response(lines[0], resp)) {
        return false;
    }
    
    resp.is_multiline = true;
    
    // Remaining lines are data (excluding the terminating ".")
    for (size_t i = 1; i < lines.size(); ++i) {
        if (lines[i] == ".") {
            break;  // End of multiline response
        }
        
        // Handle byte-stuffing (lines starting with "." are escaped as "..")
        std::string data_line = lines[i];
        if (data_line.length() > 0 && data_line[0] == '.' && data_line.length() > 1 && data_line[1] == '.') {
            data_line = data_line.substr(1);  // Remove the extra dot
        }
        
        resp.data_lines.push_back(data_line);
    }
    
    return true;
}

POP3Command POP3Parser::string_to_command(const std::string& cmd_str) {
    std::string upper_cmd = cmd_str;
    std::transform(upper_cmd.begin(), upper_cmd.end(), upper_cmd.begin(), ::toupper);
    
    if (upper_cmd == "USER") return POP3Command::USER;
    if (upper_cmd == "PASS") return POP3Command::PASS;
    if (upper_cmd == "STAT") return POP3Command::STAT;
    if (upper_cmd == "LIST") return POP3Command::LIST;
    if (upper_cmd == "RETR") return POP3Command::RETR;
    if (upper_cmd == "DELE") return POP3Command::DELE;
    if (upper_cmd == "NOOP") return POP3Command::NOOP;
    if (upper_cmd == "RSET") return POP3Command::RSET;
    if (upper_cmd == "QUIT") return POP3Command::QUIT;
    if (upper_cmd == "TOP") return POP3Command::TOP;
    if (upper_cmd == "UIDL") return POP3Command::UIDL;
    if (upper_cmd == "APOP") return POP3Command::APOP;
    if (upper_cmd == "CAPA") return POP3Command::CAPA;
    
    return POP3Command::UNKNOWN;
}

std::string POP3Parser::command_to_string(POP3Command cmd) {
    switch (cmd) {
        case POP3Command::USER: return "USER";
        case POP3Command::PASS: return "PASS";
        case POP3Command::STAT: return "STAT";
        case POP3Command::LIST: return "LIST";
        case POP3Command::RETR: return "RETR";
        case POP3Command::DELE: return "DELE";
        case POP3Command::NOOP: return "NOOP";
        case POP3Command::RSET: return "RSET";
        case POP3Command::QUIT: return "QUIT";
        case POP3Command::TOP: return "TOP";
        case POP3Command::UIDL: return "UIDL";
        case POP3Command::APOP: return "APOP";
        case POP3Command::CAPA: return "CAPA";
        default: return "UNKNOWN";
    }
}

POP3ResponseStatus POP3Parser::parse_status_indicator(const std::string& indicator) {
    if (indicator == "+OK") return POP3ResponseStatus::OK;
    if (indicator == "-ERR") return POP3ResponseStatus::ERR;
    return POP3ResponseStatus::UNKNOWN;
}

std::string POP3Parser::status_to_string(POP3ResponseStatus status) {
    switch (status) {
        case POP3ResponseStatus::OK: return "+OK";
        case POP3ResponseStatus::ERR: return "-ERR";
        default: return "UNKNOWN";
    }
}

void POP3Parser::update_session_state(const POP3CommandMessage& cmd, const POP3ResponseMessage& resp) {
    if (resp.status != POP3ResponseStatus::OK) {
        return;  // Only update state on successful responses
    }
    
    switch (cmd.command) {
        case POP3Command::USER:
            if (!cmd.arguments.empty()) {
                current_session_.username = cmd.arguments[0];
            }
            break;
            
        case POP3Command::PASS:
            if (resp.status == POP3ResponseStatus::OK) {
                handle_authentication_success(current_session_.username);
            }
            break;
            
        case POP3Command::STAT:
            handle_stat_response(resp.message);
            break;
            
        case POP3Command::DELE:
            if (!cmd.arguments.empty()) {
                try {
                    int msg_num = std::stoi(cmd.arguments[0]);
                    current_session_.deleted_messages[msg_num] = true;
                } catch (const std::exception&) {
                    // Invalid message number
                }
            }
            break;
            
        case POP3Command::RSET:
            current_session_.deleted_messages.clear();
            break;
            
        case POP3Command::QUIT:
            current_session_.state = POP3State::UPDATE;
            break;
            
        default:
            break;
    }
}

bool POP3Parser::is_multiline_command(POP3Command cmd) {
    return cmd == POP3Command::LIST ||
           cmd == POP3Command::RETR ||
           cmd == POP3Command::TOP ||
           cmd == POP3Command::UIDL ||
           cmd == POP3Command::CAPA;
}

bool POP3Parser::is_valid_command_syntax(const POP3CommandMessage& cmd) {
    switch (cmd.command) {
        case POP3Command::USER:
        case POP3Command::PASS:
            return cmd.arguments.size() == 1;
            
        case POP3Command::LIST:
        case POP3Command::RETR:
        case POP3Command::DELE:
        case POP3Command::UIDL:
            return cmd.arguments.size() <= 1;  // Optional message number
            
        case POP3Command::TOP:
            return cmd.arguments.size() == 2;  // message number and line count
            
        case POP3Command::APOP:
            return cmd.arguments.size() == 2;  // username and digest
            
        case POP3Command::STAT:
        case POP3Command::NOOP:
        case POP3Command::RSET:
        case POP3Command::QUIT:
        case POP3Command::CAPA:
            return cmd.arguments.empty();
            
        default:
            return false;
    }
}

bool POP3Parser::is_valid_response_format(const POP3ResponseMessage& resp) {
    return resp.status != POP3ResponseStatus::UNKNOWN &&
           !resp.status_indicator.empty();
}

std::vector<std::string> POP3Parser::split_lines(const std::string& data) {
    std::vector<std::string> lines;
    std::istringstream stream(data);
    std::string line;
    
    while (std::getline(stream, line)) {
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    
    return lines;
}

std::string POP3Parser::trim_whitespace(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

bool POP3Parser::is_end_of_multiline(const std::string& line) {
    return trim_whitespace(line) == ".";
}

void POP3Parser::reset_session() {
    current_session_ = POP3Session();
}

void POP3Parser::handle_authentication_success(const std::string& username) {
    current_session_.authenticated = true;
    current_session_.state = POP3State::TRANSACTION;
    current_session_.username = username;
}

void POP3Parser::handle_stat_response(const std::string& response) {
    // Parse "count size" format
    std::istringstream iss(response);
    int count;
    size_t size;
    
    if (iss >> count >> size) {
        current_session_.message_count = count;
        current_session_.mailbox_size = size;
    }
}

void POP3Parser::handle_list_response(const std::vector<std::string>& lines) {
    // Process LIST command multiline response
    // Each line contains "message_number size"
    for (const auto& line : lines) {
        std::istringstream iss(line);
        int msg_num;
        size_t msg_size;
        
        if (iss >> msg_num >> msg_size) {
            // Store message information if needed
            // This could be extended to maintain a message list
        }
    }
}

} // namespace protocol_parser