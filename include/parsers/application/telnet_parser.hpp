#pragma once

#include "../base_parser.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace protocol_parser::parsers {

// Telnet commands (RFC 854)
enum class TelnetCommand : uint8_t {
    // Data byte
    DATA = 0,
    
    // End of subnegotiation parameters
    SE = 240,   // 0xF0
    
    // No operation
    NOP = 241,  // 0xF1
    
    // Data mark - indicates the position of a Synch event within the data stream
    DM = 242,   // 0xF2
    
    // Break - indicates that the "break" or "attention" key was hit
    BRK = 243,  // 0xF3
    
    // Interrupt process - suspend, interrupt, abort or terminate the process
    IP = 244,   // 0xF4
    
    // Abort output - allow the running process to complete but do not send output to user
    AO = 245,   // 0xF5
    
    // Are you there - send back to the NVT some visible evidence that the AYT was received
    AYT = 246,  // 0xF6
    
    // Erase character - delete the last preceding undeleted character from the data stream
    EC = 247,   // 0xF7
    
    // Erase line - delete characters from the data stream back to but not including the previous CRLF
    EL = 248,   // 0xF8
    
    // Go ahead - used under certain circumstances when the GA signal is helpful
    GA = 249,   // 0xF9
    
    // Subnegotiation - indicates that what follows is subnegotiation of the indicated option
    SB = 250,   // 0xFA
    
    // Will - indicates the desire to begin performing, or confirmation that you are now performing, the indicated option
    WILL = 251, // 0xFB
    
    // Won't - indicates the refusal to perform, or continue performing, the indicated option
    WONT = 252, // 0xFC
    
    // Do - indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option
    DO = 253,   // 0xFD
    
    // Don't - indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option
    DONT = 254, // 0xFE
    
    // Interpret as command - all data bytes after this byte in the data stream are to be interpreted as commands
    IAC = 255   // 0xFF
};

// Telnet options (RFC 855 and others)
enum class TelnetOption : uint8_t {
    BINARY = 0,                    // RFC 856 - Binary Transmission
    ECHO = 1,                      // RFC 857 - Echo
    RECONNECTION = 2,              // RFC 671 - Reconnection
    SUPPRESS_GO_AHEAD = 3,         // RFC 858 - Suppress Go Ahead
    APPROX_MESSAGE_SIZE = 4,       // Approximate Message Size Negotiation
    STATUS = 5,                    // RFC 859 - Status
    TIMING_MARK = 6,               // RFC 860 - Timing Mark
    RCTE = 7,                      // RFC 563 - Remote Controlled Trans and Echo
    OUTPUT_LINE_WIDTH = 8,         // RFC 1073 - Output Line Width
    OUTPUT_PAGE_SIZE = 9,          // RFC 1073 - Output Page Size
    OUTPUT_CR_DISPOSITION = 10,    // RFC 652 - Output Carriage-Return Disposition
    OUTPUT_HT_STOPS = 11,          // RFC 653 - Output Horizontal Tab Stops
    OUTPUT_HT_DISPOSITION = 12,    // RFC 654 - Output Horizontal Tab Disposition
    OUTPUT_FF_DISPOSITION = 13,    // RFC 655 - Output Formfeed Disposition
    OUTPUT_VT_STOPS = 14,          // RFC 656 - Output Vertical Tabstops
    OUTPUT_VT_DISPOSITION = 15,    // RFC 657 - Output Vertical Tab Disposition
    OUTPUT_LF_DISPOSITION = 16,    // RFC 658 - Output Linefeed Disposition
    EXTENDED_ASCII = 17,           // RFC 698 - Extended ASCII
    LOGOUT = 18,                   // RFC 727 - Logout
    BYTE_MACRO = 19,               // RFC 735 - Byte Macro
    DATA_ENTRY_TERMINAL = 20,      // RFC 1043 - Data Entry Terminal
    SUPDUP = 21,                   // RFC 736 - SUPDUP
    SUPDUP_OUTPUT = 22,            // RFC 749 - SUPDUP Output
    SEND_LOCATION = 23,            // RFC 779 - Send Location
    TERMINAL_TYPE = 24,            // RFC 1091 - Terminal Type
    END_OF_RECORD = 25,            // RFC 885 - End of Record
    TACACS_USER_ID = 26,           // RFC 927 - TACACS User Identification
    OUTPUT_MARKING = 27,           // RFC 933 - Output Marking
    TERMINAL_LOCATION_NUMBER = 28, // RFC 946 - Terminal Location Number
    TELNET_3270_REGIME = 29,       // RFC 1041 - Telnet 3270 Regime
    X_3_PAD = 30,                  // RFC 1053 - X.3 PAD
    NEGOTIATE_ABOUT_WINDOW_SIZE = 31, // RFC 1073 - Negotiate About Window Size (NAWS)
    TERMINAL_SPEED = 32,           // RFC 1079 - Terminal Speed
    REMOTE_FLOW_CONTROL = 33,      // RFC 1372 - Remote Flow Control
    LINEMODE = 34,                 // RFC 1184 - Linemode
    X_DISPLAY_LOCATION = 35,       // RFC 1096 - X Display Location
    ENVIRONMENT = 36,              // RFC 1408 - Environment Option
    AUTHENTICATION = 37,           // RFC 2941 - Authentication
    ENCRYPTION = 38,               // RFC 2946 - Encryption
    NEW_ENVIRONMENT = 39,          // RFC 1572 - New Environment Option
    TN3270E = 40,                  // RFC 2355 - TN3270E
    XAUTH = 41,                    // XAUTH
    CHARSET = 42,                  // RFC 2066 - Charset
    TELNET_REMOTE_SERIAL_PORT = 43, // Telnet Remote Serial Port
    COM_PORT_CONTROL = 44,         // RFC 2217 - Com Port Control
    TELNET_SUPPRESS_LOCAL_ECHO = 45, // Telnet Suppress Local Echo
    TELNET_START_TLS = 46,         // Telnet Start TLS
    KERMIT = 47,                   // KERMIT
    SEND_URL = 48,                 // SEND-URL
    FORWARD_X = 49,                // FORWARD_X
    
    UNKNOWN_OPTION = 255
};

// Telnet message types
enum class TelnetMessageType {
    DATA,           // Regular data
    COMMAND,        // Telnet command (IAC + command)
    NEGOTIATION,    // Option negotiation (IAC + WILL/WONT/DO/DONT + option)
    SUBNEGOTIATION, // Subnegotiation (IAC + SB + option + data + IAC + SE)
    UNKNOWN
};

// Telnet negotiation structure
struct TelnetNegotiation {
    TelnetCommand command; // WILL, WONT, DO, DONT
    TelnetOption option;
};

// Telnet subnegotiation structure
struct TelnetSubnegotiation {
    TelnetOption option;
    std::vector<uint8_t> data;
};

// Telnet message structure
struct TelnetMessage {
    TelnetMessageType type;
    
    union {
        struct {
            std::vector<uint8_t> data;
        } data_msg;
        
        struct {
            TelnetCommand command;
        } command_msg;
        
        TelnetNegotiation negotiation;
        TelnetSubnegotiation subnegotiation;
    };
    
    TelnetMessage() : type(TelnetMessageType::UNKNOWN) {}
    
    ~TelnetMessage() {
        if (type == TelnetMessageType::DATA) {
            data_msg.data.~vector();
        } else if (type == TelnetMessageType::SUBNEGOTIATION) {
            subnegotiation.~TelnetSubnegotiation();
        }
    }
    
    TelnetMessage(const TelnetMessage& other) : type(other.type) {
        switch (type) {
            case TelnetMessageType::DATA:
                new(&data_msg) decltype(data_msg)(other.data_msg);
                break;
            case TelnetMessageType::COMMAND:
                command_msg = other.command_msg;
                break;
            case TelnetMessageType::NEGOTIATION:
                negotiation = other.negotiation;
                break;
            case TelnetMessageType::SUBNEGOTIATION:
                new(&subnegotiation) TelnetSubnegotiation(other.subnegotiation);
                break;
            default:
                break;
        }
    }
    
    TelnetMessage& operator=(const TelnetMessage& other) {
        if (this != &other) {
            this->~TelnetMessage();
            type = other.type;
            switch (type) {
                case TelnetMessageType::DATA:
                    new(&data_msg) decltype(data_msg)(other.data_msg);
                    break;
                case TelnetMessageType::COMMAND:
                    command_msg = other.command_msg;
                    break;
                case TelnetMessageType::NEGOTIATION:
                    negotiation = other.negotiation;
                    break;
                case TelnetMessageType::SUBNEGOTIATION:
                    new(&subnegotiation) TelnetSubnegotiation(other.subnegotiation);
                    break;
                default:
                    break;
            }
        }
        return *this;
    }
};

// Telnet connection state
struct TelnetConnectionState {
    std::map<TelnetOption, bool> local_options;  // Options we have enabled
    std::map<TelnetOption, bool> remote_options; // Options the remote has enabled
    bool in_subnegotiation;
    TelnetOption current_subneg_option;
    std::vector<uint8_t> subneg_buffer;
};

class TelnetParser : public BaseParser {
public:
    TelnetParser() = default;
    ~TelnetParser() override = default;

    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept { return error_message_; }
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override { return validate_telnet_data(buffer); }
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override {
        static const ProtocolInfo info{"Telnet", 23, 1, 1, 65535};
        return info;
    }

    // Telnet-specific methods
    [[nodiscard]] const std::vector<TelnetMessage>& get_messages() const { return messages_; }
    [[nodiscard]] const TelnetConnectionState& get_connection_state() const { return connection_state_; }
    [[nodiscard]] TelnetMessage get_last_message() const;
    [[nodiscard]] size_t get_message_count() const { return messages_.size(); }
    
    // Option state methods
    [[nodiscard]] bool is_local_option_enabled(TelnetOption option) const;
    [[nodiscard]] bool is_remote_option_enabled(TelnetOption option) const;
    [[nodiscard]] std::vector<TelnetOption> get_enabled_local_options() const;
    [[nodiscard]] std::vector<TelnetOption> get_enabled_remote_options() const;
    
    // Message type checks
    [[nodiscard]] bool has_data_messages() const;
    [[nodiscard]] bool has_negotiation_messages() const;
    [[nodiscard]] bool has_subnegotiation_messages() const;
    
    // Data extraction methods
    [[nodiscard]] std::string get_data_as_string() const;
    [[nodiscard]] std::vector<uint8_t> get_raw_data() const;
    
    // Utility methods
    [[nodiscard]] std::string command_to_string(TelnetCommand cmd) const;
    [[nodiscard]] std::string option_to_string(TelnetOption opt) const;
    [[nodiscard]] std::string message_type_to_string(TelnetMessageType type) const;
    [[nodiscard]] TelnetCommand byte_to_command(uint8_t byte) const;
    [[nodiscard]] TelnetOption byte_to_option(uint8_t byte) const;

private:
    std::vector<TelnetMessage> messages_;
    TelnetConnectionState connection_state_;
    std::string error_message_;
    
    // Helper methods
    [[nodiscard]] ParseResult parse_telnet_stream(const BufferView& buffer);
    [[nodiscard]] ParseResult process_iac_sequence(const BufferView& buffer, size_t& pos);
    [[nodiscard]] ParseResult handle_negotiation(TelnetCommand cmd, TelnetOption opt);
    [[nodiscard]] ParseResult handle_subnegotiation_start(TelnetOption opt);
    [[nodiscard]] ParseResult handle_subnegotiation_end();
    
    void add_data_message(const std::vector<uint8_t>& data);
    void add_command_message(TelnetCommand cmd);
    void add_negotiation_message(TelnetCommand cmd, TelnetOption opt);
    void add_subnegotiation_message(TelnetOption opt, const std::vector<uint8_t>& data);
    
    void update_option_state(TelnetCommand cmd, TelnetOption opt);
    [[nodiscard]] bool validate_telnet_data(const BufferView& buffer) const;
};

} // namespace protocol_parser::parsers