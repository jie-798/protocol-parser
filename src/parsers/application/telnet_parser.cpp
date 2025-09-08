#include "../../../include/parsers/application/telnet_parser.hpp"
#include <algorithm>
#include <sstream>

namespace protocol_parser::parsers {

ParseResult TelnetParser::parse(ParseContext& context) noexcept {
const BufferView& buffer = context.buffer;
if (buffer.size() < 1) {
    return ParseResult::NeedMoreData;
}

if (!validate_telnet_data(buffer)) {
    return ParseResult::InvalidFormat;
    }
    
    return parse_telnet_stream(buffer);
}

ParseResult TelnetParser::parse_telnet_stream(const BufferView& buffer) {
    size_t pos = 0;
    std::vector<uint8_t> data_buffer;
    
    while (pos < buffer.size()) {
        uint8_t byte = buffer.data()[pos];
        
        if (connection_state_.in_subnegotiation) {
            // We're in a subnegotiation sequence
            if (byte == static_cast<uint8_t>(TelnetCommand::IAC)) {
                // Check if this is IAC SE (end of subnegotiation)
                if (pos + 1 < buffer.size() && 
                    buffer.data()[pos + 1] == static_cast<uint8_t>(TelnetCommand::SE)) {
                    // End of subnegotiation
                    ParseResult status = handle_subnegotiation_end();
                if (status != ParseResult::Success) {
                        return status;
                    }
                    pos += 2; // Skip IAC SE
                    continue;
                } else if (pos + 1 < buffer.size() && 
                          buffer.data()[pos + 1] == static_cast<uint8_t>(TelnetCommand::IAC)) {
                    // Escaped IAC in subnegotiation data
                    connection_state_.subneg_buffer.push_back(byte);
                    pos += 2; // Skip both IAC bytes
                    continue;
                } else {
                    // IAC followed by something else - this shouldn't happen in subnegotiation
                    return ParseResult::InvalidFormat;
                }
            } else {
                // Regular data in subnegotiation
                connection_state_.subneg_buffer.push_back(byte);
                pos++;
                continue;
            }
        }
        
        if (byte == static_cast<uint8_t>(TelnetCommand::IAC)) {
            // Save any accumulated data before processing IAC sequence
            if (!data_buffer.empty()) {
                add_data_message(data_buffer);
                data_buffer.clear();
            }
            
            ParseResult status = process_iac_sequence(buffer, pos);
        if (status != ParseResult::Success) {
                return status;
            }
        } else {
            // Regular data byte
            data_buffer.push_back(byte);
            pos++;
        }
    }
    
    // Add any remaining data
    if (!data_buffer.empty()) {
        add_data_message(data_buffer);
    }
    
    return ParseResult::Success;
}

ParseResult TelnetParser::process_iac_sequence(const BufferView& buffer, size_t& pos) {
    if (pos + 1 >= buffer.size()) {
        return ParseResult::NeedMoreData;
    }
    
    uint8_t command_byte = buffer.data()[pos + 1];
    TelnetCommand command = byte_to_command(command_byte);
    
    switch (command) {
        case TelnetCommand::IAC:
            // Escaped IAC - treat as data byte 0xFF
            {
                std::vector<uint8_t> iac_data = {0xFF};
                add_data_message(iac_data);
                pos += 2;
            }
            break;
            
        case TelnetCommand::WILL:
        case TelnetCommand::WONT:
        case TelnetCommand::DO:
        case TelnetCommand::DONT:
            // Option negotiation - need one more byte
            if (pos + 2 >= buffer.size()) {
                return ParseResult::NeedMoreData;
            }
            {
                TelnetOption option = byte_to_option(buffer.data()[pos + 2]);
                add_negotiation_message(command, option);
                update_option_state(command, option);
                pos += 3;
            }
            break;
            
        case TelnetCommand::SB:
            // Start of subnegotiation - need option byte
            if (pos + 2 >= buffer.size()) {
                return ParseResult::NeedMoreData;
            }
            {
                TelnetOption option = byte_to_option(buffer.data()[pos + 2]);
                ParseResult status = handle_subnegotiation_start(option);
                if (status != ParseResult::Success) {
                    return status;
                }
                pos += 3;
            }
            break;
            
        case TelnetCommand::SE:
            // End of subnegotiation - this should only occur within subnegotiation
            if (!connection_state_.in_subnegotiation) {
                return ParseResult::InvalidFormat;
            }
            {
                ParseResult status = handle_subnegotiation_end();
                if (status != ParseResult::Success) {
                    return status;
                }
                pos += 2;
            }
            break;
            
        default:
            // Single-byte commands
            add_command_message(command);
            pos += 2;
            break;
    }
    
    return ParseResult::Success;
}

ParseResult TelnetParser::handle_negotiation(TelnetCommand cmd, TelnetOption opt) {
    // This is called after the negotiation message is added
    // Here we could implement negotiation logic if needed
    (void)cmd; // Suppress unused parameter warning
    (void)opt; // Suppress unused parameter warning
    return ParseResult::Success;
}

ParseResult TelnetParser::handle_subnegotiation_start(TelnetOption opt) {
    connection_state_.in_subnegotiation = true;
    connection_state_.current_subneg_option = opt;
    connection_state_.subneg_buffer.clear();
    return ParseResult::Success;
}

ParseResult TelnetParser::handle_subnegotiation_end() {
    if (!connection_state_.in_subnegotiation) {
        return ParseResult::InvalidFormat;
    }
    
    add_subnegotiation_message(connection_state_.current_subneg_option, 
                              connection_state_.subneg_buffer);
    
    connection_state_.in_subnegotiation = false;
    connection_state_.subneg_buffer.clear();
    
    return ParseResult::Success;
}

void TelnetParser::add_data_message(const std::vector<uint8_t>& data) {
    TelnetMessage message;
    message.type = TelnetMessageType::DATA;
    new(&message.data_msg) decltype(message.data_msg)();
    message.data_msg.data = data;
    messages_.push_back(message);
}

void TelnetParser::add_command_message(TelnetCommand cmd) {
    TelnetMessage message;
    message.type = TelnetMessageType::COMMAND;
    message.command_msg.command = cmd;
    messages_.push_back(message);
}

void TelnetParser::add_negotiation_message(TelnetCommand cmd, TelnetOption opt) {
    TelnetMessage message;
    message.type = TelnetMessageType::NEGOTIATION;
    message.negotiation.command = cmd;
    message.negotiation.option = opt;
    messages_.push_back(message);
}

void TelnetParser::add_subnegotiation_message(TelnetOption opt, const std::vector<uint8_t>& data) {
    TelnetMessage message;
    message.type = TelnetMessageType::SUBNEGOTIATION;
    new(&message.subnegotiation) TelnetSubnegotiation();
    message.subnegotiation.option = opt;
    message.subnegotiation.data = data;
    messages_.push_back(message);
}

void TelnetParser::update_option_state(TelnetCommand cmd, TelnetOption opt) {
    switch (cmd) {
        case TelnetCommand::WILL:
            connection_state_.remote_options[opt] = true;
            break;
        case TelnetCommand::WONT:
            connection_state_.remote_options[opt] = false;
            break;
        case TelnetCommand::DO:
            connection_state_.local_options[opt] = true;
            break;
        case TelnetCommand::DONT:
            connection_state_.local_options[opt] = false;
            break;
        default:
            break;
    }
}

TelnetMessage TelnetParser::get_last_message() const {
    if (!messages_.empty()) {
        return messages_.back();
    }
    return TelnetMessage();
}

bool TelnetParser::is_local_option_enabled(TelnetOption option) const {
    auto it = connection_state_.local_options.find(option);
    return it != connection_state_.local_options.end() && it->second;
}

bool TelnetParser::is_remote_option_enabled(TelnetOption option) const {
    auto it = connection_state_.remote_options.find(option);
    return it != connection_state_.remote_options.end() && it->second;
}

std::vector<TelnetOption> TelnetParser::get_enabled_local_options() const {
    std::vector<TelnetOption> enabled;
    for (const auto& pair : connection_state_.local_options) {
        if (pair.second) {
            enabled.push_back(pair.first);
        }
    }
    return enabled;
}

std::vector<TelnetOption> TelnetParser::get_enabled_remote_options() const {
    std::vector<TelnetOption> enabled;
    for (const auto& pair : connection_state_.remote_options) {
        if (pair.second) {
            enabled.push_back(pair.first);
        }
    }
    return enabled;
}

bool TelnetParser::has_data_messages() const {
    return std::any_of(messages_.begin(), messages_.end(), 
                      [](const TelnetMessage& msg) {
                          return msg.type == TelnetMessageType::DATA;
                      });
}

bool TelnetParser::has_negotiation_messages() const {
    return std::any_of(messages_.begin(), messages_.end(), 
                      [](const TelnetMessage& msg) {
                          return msg.type == TelnetMessageType::NEGOTIATION;
                      });
}

bool TelnetParser::has_subnegotiation_messages() const {
    return std::any_of(messages_.begin(), messages_.end(), 
                      [](const TelnetMessage& msg) {
                          return msg.type == TelnetMessageType::SUBNEGOTIATION;
                      });
}

std::string TelnetParser::get_data_as_string() const {
    std::ostringstream oss;
    for (const auto& message : messages_) {
        if (message.type == TelnetMessageType::DATA) {
            for (uint8_t byte : message.data_msg.data) {
                oss << static_cast<char>(byte);
            }
        }
    }
    return oss.str();
}

std::vector<uint8_t> TelnetParser::get_raw_data() const {
    std::vector<uint8_t> data;
    for (const auto& message : messages_) {
        if (message.type == TelnetMessageType::DATA) {
            data.insert(data.end(), message.data_msg.data.begin(), message.data_msg.data.end());
        }
    }
    return data;
}

std::string TelnetParser::command_to_string(TelnetCommand cmd) const {
    switch (cmd) {
        case TelnetCommand::SE: return "SE";
        case TelnetCommand::NOP: return "NOP";
        case TelnetCommand::DM: return "DM";
        case TelnetCommand::BRK: return "BRK";
        case TelnetCommand::IP: return "IP";
        case TelnetCommand::AO: return "AO";
        case TelnetCommand::AYT: return "AYT";
        case TelnetCommand::EC: return "EC";
        case TelnetCommand::EL: return "EL";
        case TelnetCommand::GA: return "GA";
        case TelnetCommand::SB: return "SB";
        case TelnetCommand::WILL: return "WILL";
        case TelnetCommand::WONT: return "WONT";
        case TelnetCommand::DO: return "DO";
        case TelnetCommand::DONT: return "DONT";
        case TelnetCommand::IAC: return "IAC";
        default: return "UNKNOWN";
    }
}

std::string TelnetParser::option_to_string(TelnetOption opt) const {
    switch (opt) {
        case TelnetOption::BINARY: return "BINARY";
        case TelnetOption::ECHO: return "ECHO";
        case TelnetOption::RECONNECTION: return "RECONNECTION";
        case TelnetOption::SUPPRESS_GO_AHEAD: return "SUPPRESS_GO_AHEAD";
        case TelnetOption::APPROX_MESSAGE_SIZE: return "APPROX_MESSAGE_SIZE";
        case TelnetOption::STATUS: return "STATUS";
        case TelnetOption::TIMING_MARK: return "TIMING_MARK";
        case TelnetOption::RCTE: return "RCTE";
        case TelnetOption::OUTPUT_LINE_WIDTH: return "OUTPUT_LINE_WIDTH";
        case TelnetOption::OUTPUT_PAGE_SIZE: return "OUTPUT_PAGE_SIZE";
        case TelnetOption::OUTPUT_CR_DISPOSITION: return "OUTPUT_CR_DISPOSITION";
        case TelnetOption::OUTPUT_HT_STOPS: return "OUTPUT_HT_STOPS";
        case TelnetOption::OUTPUT_HT_DISPOSITION: return "OUTPUT_HT_DISPOSITION";
        case TelnetOption::OUTPUT_FF_DISPOSITION: return "OUTPUT_FF_DISPOSITION";
        case TelnetOption::OUTPUT_VT_STOPS: return "OUTPUT_VT_STOPS";
        case TelnetOption::OUTPUT_VT_DISPOSITION: return "OUTPUT_VT_DISPOSITION";
        case TelnetOption::OUTPUT_LF_DISPOSITION: return "OUTPUT_LF_DISPOSITION";
        case TelnetOption::EXTENDED_ASCII: return "EXTENDED_ASCII";
        case TelnetOption::LOGOUT: return "LOGOUT";
        case TelnetOption::BYTE_MACRO: return "BYTE_MACRO";
        case TelnetOption::DATA_ENTRY_TERMINAL: return "DATA_ENTRY_TERMINAL";
        case TelnetOption::SUPDUP: return "SUPDUP";
        case TelnetOption::SUPDUP_OUTPUT: return "SUPDUP_OUTPUT";
        case TelnetOption::SEND_LOCATION: return "SEND_LOCATION";
        case TelnetOption::TERMINAL_TYPE: return "TERMINAL_TYPE";
        case TelnetOption::END_OF_RECORD: return "END_OF_RECORD";
        case TelnetOption::TACACS_USER_ID: return "TACACS_USER_ID";
        case TelnetOption::OUTPUT_MARKING: return "OUTPUT_MARKING";
        case TelnetOption::TERMINAL_LOCATION_NUMBER: return "TERMINAL_LOCATION_NUMBER";
        case TelnetOption::TELNET_3270_REGIME: return "TELNET_3270_REGIME";
        case TelnetOption::X_3_PAD: return "X_3_PAD";
        case TelnetOption::NEGOTIATE_ABOUT_WINDOW_SIZE: return "NEGOTIATE_ABOUT_WINDOW_SIZE";
        case TelnetOption::TERMINAL_SPEED: return "TERMINAL_SPEED";
        case TelnetOption::REMOTE_FLOW_CONTROL: return "REMOTE_FLOW_CONTROL";
        case TelnetOption::LINEMODE: return "LINEMODE";
        case TelnetOption::X_DISPLAY_LOCATION: return "X_DISPLAY_LOCATION";
        case TelnetOption::ENVIRONMENT: return "ENVIRONMENT";
        case TelnetOption::AUTHENTICATION: return "AUTHENTICATION";
        case TelnetOption::ENCRYPTION: return "ENCRYPTION";
        case TelnetOption::NEW_ENVIRONMENT: return "NEW_ENVIRONMENT";
        case TelnetOption::TN3270E: return "TN3270E";
        case TelnetOption::XAUTH: return "XAUTH";
        case TelnetOption::CHARSET: return "CHARSET";
        case TelnetOption::TELNET_REMOTE_SERIAL_PORT: return "TELNET_REMOTE_SERIAL_PORT";
        case TelnetOption::COM_PORT_CONTROL: return "COM_PORT_CONTROL";
        case TelnetOption::TELNET_SUPPRESS_LOCAL_ECHO: return "TELNET_SUPPRESS_LOCAL_ECHO";
        case TelnetOption::TELNET_START_TLS: return "TELNET_START_TLS";
        case TelnetOption::KERMIT: return "KERMIT";
        case TelnetOption::SEND_URL: return "SEND_URL";
        case TelnetOption::FORWARD_X: return "FORWARD_X";
        default: return "UNKNOWN_OPTION";
    }
}

std::string TelnetParser::message_type_to_string(TelnetMessageType type) const {
    switch (type) {
        case TelnetMessageType::DATA: return "DATA";
        case TelnetMessageType::COMMAND: return "COMMAND";
        case TelnetMessageType::NEGOTIATION: return "NEGOTIATION";
        case TelnetMessageType::SUBNEGOTIATION: return "SUBNEGOTIATION";
        default: return "UNKNOWN";
    }
}

TelnetCommand TelnetParser::byte_to_command(uint8_t byte) const {
    if (byte >= 240) {
        return static_cast<TelnetCommand>(byte);
    }
    return TelnetCommand::DATA;
}

TelnetOption TelnetParser::byte_to_option(uint8_t byte) const {
    if (byte <= 49) {
        return static_cast<TelnetOption>(byte);
    }
    return TelnetOption::UNKNOWN_OPTION;
}

bool TelnetParser::validate_telnet_data(const BufferView& buffer) const {
    // Basic validation - Telnet can contain any byte values
    // More sophisticated validation could check for proper IAC sequences
    return buffer.size() > 0;
}

void TelnetParser::reset() noexcept {
    messages_.clear();
    connection_state_ = TelnetConnectionState();
}

} // namespace protocol_parser::parsers