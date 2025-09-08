#include "../../../include/parsers/application/ftp_parser.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace protocol_parser::parsers {

ParseResult FTPParser::parse(ParseContext& context) noexcept {
    if (context.buffer.size() < 3) {
        return ParseResult::NeedMoreData;
    }
    
    if (!validate_ftp_message(context.buffer)) {
        return ParseResult::InvalidFormat;
    }
    
    if (!is_complete_line(context.buffer)) {
        return ParseResult::NeedMoreData;
    }
    
    reset();
    
    // Convert buffer to string for easier processing
    std::string data(reinterpret_cast<const char*>(context.buffer.data()), context.buffer.size());
    
    // Find the first complete line
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) {
        line_end = data.find('\n');
        if (line_end == std::string::npos) {
            return ParseResult::NeedMoreData;
        }
    }
    
    std::string first_line = data.substr(0, line_end);
    first_line = trim(first_line);
    
    if (first_line.empty()) {
        return ParseResult::InvalidFormat;
    }
    
    // Determine if this is a command or response
    if (std::isdigit(first_line[0]) && first_line.length() >= 3) {
        // Response (starts with 3-digit code)
        if (first_line.length() > 3 && first_line[3] == '-') {
            // Multiline response
            return parse_multiline_response(context.buffer, 0);
        } else {
            return parse_response(first_line);
        }
    } else {
        // Command
        return parse_command(first_line);
    }
}

ParseResult FTPParser::parse_command(const std::string& line) {
    std::istringstream iss(line);
    std::string command_str;
    
    if (!(iss >> command_str)) {
        return ParseResult::InvalidFormat;
    }
    
    command_str = to_upper(command_str);
    
    ftp_message_.type = FTPMessageType::COMMAND;
    new(&ftp_message_.command) FTPCommandMessage();
    
    ftp_message_.command.command_str = command_str;
    ftp_message_.command.command = string_to_command(command_str);
    
    // Get parameters (rest of the line)
    std::string parameters;
    if (std::getline(iss, parameters)) {
        parameters = trim(parameters);
        ftp_message_.command.parameters = parameters;
    }
    
    return ParseResult::Success;
}

ParseResult FTPParser::parse_response(const std::string& line) {
    if (line.length() < 3) {
        return ParseResult::InvalidFormat;
    }
    
    // Extract response code
    std::string code_str = line.substr(0, 3);
    if (!std::all_of(code_str.begin(), code_str.end(), ::isdigit)) {
        return ParseResult::InvalidFormat;
    }
    
    uint16_t code_number = static_cast<uint16_t>(std::stoi(code_str));
    
    ftp_message_.type = FTPMessageType::RESPONSE;
    new(&ftp_message_.response) FTPResponseMessage();
    
    ftp_message_.response.code_number = code_number;
    ftp_message_.response.code = number_to_response_code(code_number);
    ftp_message_.response.is_multiline = false;
    
    // Extract message (skip space after code)
    if (line.length() > 4 && line[3] == ' ') {
        ftp_message_.response.message = line.substr(4);
    } else if (line.length() > 3) {
        ftp_message_.response.message = line.substr(3);
    }
    
    ftp_message_.response.lines.push_back(ftp_message_.response.message);
    
    return ParseResult::Success;
}

ParseResult FTPParser::parse_multiline_response(const BufferView& buffer, size_t start_pos) {
    std::string data(reinterpret_cast<const char*>(buffer.data() + start_pos), 
                    buffer.size() - start_pos);
    
    std::istringstream iss(data);
    std::string line;
    std::vector<std::string> lines;
    
    if (!std::getline(iss, line)) {
        return ParseResult::NeedMoreData;
    }
    
    // Remove \r if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    
    if (line.length() < 4 || line[3] != '-') {
        return ParseResult::InvalidFormat;
    }
    
    std::string code_str = line.substr(0, 3);
    uint16_t code_number = static_cast<uint16_t>(std::stoi(code_str));
    
    ftp_message_.type = FTPMessageType::RESPONSE;
    new(&ftp_message_.response) FTPResponseMessage();
    
    ftp_message_.response.code_number = code_number;
    ftp_message_.response.code = number_to_response_code(code_number);
    ftp_message_.response.is_multiline = true;
    
    // First line message (after "xxx-")
    std::string first_message = line.substr(4);
    lines.push_back(first_message);
    
    // Read subsequent lines until we find the end marker
    std::string end_marker = code_str + " ";
    
    while (std::getline(iss, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.substr(0, 4) == end_marker) {
            // End of multiline response
            lines.push_back(line.substr(4));
            break;
        } else {
            lines.push_back(line);
        }
    }
    
    if (lines.empty() || !iss.eof()) {
        // Check if we have the complete multiline response
        size_t pos = data.find(end_marker);
        if (pos == std::string::npos) {
            return ParseResult::NeedMoreData;
        }
    }
    
    ftp_message_.response.lines = lines;
    ftp_message_.response.message = lines.empty() ? "" : lines[0];
    
    return ParseResult::Success;
}

FTPCommand FTPParser::get_command() const {
    if (ftp_message_.type == FTPMessageType::COMMAND) {
        return ftp_message_.command.command;
    }
    return FTPCommand::UNKNOWN;
}

std::string FTPParser::get_command_string() const {
    if (ftp_message_.type == FTPMessageType::COMMAND) {
        return ftp_message_.command.command_str;
    }
    return "";
}

std::string FTPParser::get_command_parameters() const {
    if (ftp_message_.type == FTPMessageType::COMMAND) {
        return ftp_message_.command.parameters;
    }
    return "";
}

FTPResponseCode FTPParser::get_response_code() const {
    if (ftp_message_.type == FTPMessageType::RESPONSE) {
        return ftp_message_.response.code;
    }
    return FTPResponseCode::UNKNOWN_CODE;
}

uint16_t FTPParser::get_response_code_number() const {
    if (ftp_message_.type == FTPMessageType::RESPONSE) {
        return ftp_message_.response.code_number;
    }
    return 0;
}

std::string FTPParser::get_response_message() const {
    if (ftp_message_.type == FTPMessageType::RESPONSE) {
        return ftp_message_.response.message;
    }
    return "";
}

bool FTPParser::is_multiline_response() const {
    if (ftp_message_.type == FTPMessageType::RESPONSE) {
        return ftp_message_.response.is_multiline;
    }
    return false;
}

const std::vector<std::string>& FTPParser::get_response_lines() const {
    static const std::vector<std::string> empty_lines;
    if (ftp_message_.type == FTPMessageType::RESPONSE) {
        return ftp_message_.response.lines;
    }
    return empty_lines;
}

bool FTPParser::is_positive_preliminary() const {
    uint16_t code = get_response_code_number();
    return code >= 100 && code < 200;
}

bool FTPParser::is_positive_completion() const {
    uint16_t code = get_response_code_number();
    return code >= 200 && code < 300;
}

bool FTPParser::is_positive_intermediate() const {
    uint16_t code = get_response_code_number();
    return code >= 300 && code < 400;
}

bool FTPParser::is_transient_negative() const {
    uint16_t code = get_response_code_number();
    return code >= 400 && code < 500;
}

bool FTPParser::is_permanent_negative() const {
    uint16_t code = get_response_code_number();
    return code >= 500 && code < 600;
}

std::string FTPParser::command_to_string(FTPCommand cmd) const {
    switch (cmd) {
        case FTPCommand::USER: return "USER";
        case FTPCommand::PASS: return "PASS";
        case FTPCommand::ACCT: return "ACCT";
        case FTPCommand::CWD: return "CWD";
        case FTPCommand::CDUP: return "CDUP";
        case FTPCommand::SMNT: return "SMNT";
        case FTPCommand::QUIT: return "QUIT";
        case FTPCommand::REIN: return "REIN";
        case FTPCommand::PORT: return "PORT";
        case FTPCommand::PASV: return "PASV";
        case FTPCommand::TYPE: return "TYPE";
        case FTPCommand::STRU: return "STRU";
        case FTPCommand::MODE: return "MODE";
        case FTPCommand::RETR: return "RETR";
        case FTPCommand::STOR: return "STOR";
        case FTPCommand::STOU: return "STOU";
        case FTPCommand::APPE: return "APPE";
        case FTPCommand::ALLO: return "ALLO";
        case FTPCommand::REST: return "REST";
        case FTPCommand::RNFR: return "RNFR";
        case FTPCommand::RNTO: return "RNTO";
        case FTPCommand::ABOR: return "ABOR";
        case FTPCommand::DELE: return "DELE";
        case FTPCommand::RMD: return "RMD";
        case FTPCommand::MKD: return "MKD";
        case FTPCommand::PWD: return "PWD";
        case FTPCommand::LIST: return "LIST";
        case FTPCommand::NLST: return "NLST";
        case FTPCommand::SITE: return "SITE";
        case FTPCommand::SYST: return "SYST";
        case FTPCommand::STAT: return "STAT";
        case FTPCommand::HELP: return "HELP";
        case FTPCommand::NOOP: return "NOOP";
        case FTPCommand::FEAT: return "FEAT";
        case FTPCommand::OPTS: return "OPTS";
        case FTPCommand::AUTH: return "AUTH";
        case FTPCommand::PBSZ: return "PBSZ";
        case FTPCommand::PROT: return "PROT";
        default: return "UNKNOWN";
    }
}

FTPCommand FTPParser::string_to_command(const std::string& cmd_str) const {
    std::string upper_cmd = to_upper(cmd_str);
    
    if (upper_cmd == "USER") return FTPCommand::USER;
    if (upper_cmd == "PASS") return FTPCommand::PASS;
    if (upper_cmd == "ACCT") return FTPCommand::ACCT;
    if (upper_cmd == "CWD") return FTPCommand::CWD;
    if (upper_cmd == "CDUP") return FTPCommand::CDUP;
    if (upper_cmd == "SMNT") return FTPCommand::SMNT;
    if (upper_cmd == "QUIT") return FTPCommand::QUIT;
    if (upper_cmd == "REIN") return FTPCommand::REIN;
    if (upper_cmd == "PORT") return FTPCommand::PORT;
    if (upper_cmd == "PASV") return FTPCommand::PASV;
    if (upper_cmd == "TYPE") return FTPCommand::TYPE;
    if (upper_cmd == "STRU") return FTPCommand::STRU;
    if (upper_cmd == "MODE") return FTPCommand::MODE;
    if (upper_cmd == "RETR") return FTPCommand::RETR;
    if (upper_cmd == "STOR") return FTPCommand::STOR;
    if (upper_cmd == "STOU") return FTPCommand::STOU;
    if (upper_cmd == "APPE") return FTPCommand::APPE;
    if (upper_cmd == "ALLO") return FTPCommand::ALLO;
    if (upper_cmd == "REST") return FTPCommand::REST;
    if (upper_cmd == "RNFR") return FTPCommand::RNFR;
    if (upper_cmd == "RNTO") return FTPCommand::RNTO;
    if (upper_cmd == "ABOR") return FTPCommand::ABOR;
    if (upper_cmd == "DELE") return FTPCommand::DELE;
    if (upper_cmd == "RMD") return FTPCommand::RMD;
    if (upper_cmd == "MKD") return FTPCommand::MKD;
    if (upper_cmd == "PWD") return FTPCommand::PWD;
    if (upper_cmd == "LIST") return FTPCommand::LIST;
    if (upper_cmd == "NLST") return FTPCommand::NLST;
    if (upper_cmd == "SITE") return FTPCommand::SITE;
    if (upper_cmd == "SYST") return FTPCommand::SYST;
    if (upper_cmd == "STAT") return FTPCommand::STAT;
    if (upper_cmd == "HELP") return FTPCommand::HELP;
    if (upper_cmd == "NOOP") return FTPCommand::NOOP;
    if (upper_cmd == "FEAT") return FTPCommand::FEAT;
    if (upper_cmd == "OPTS") return FTPCommand::OPTS;
    if (upper_cmd == "AUTH") return FTPCommand::AUTH;
    if (upper_cmd == "PBSZ") return FTPCommand::PBSZ;
    if (upper_cmd == "PROT") return FTPCommand::PROT;
    
    return FTPCommand::UNKNOWN;
}

std::string FTPParser::response_code_to_string(FTPResponseCode code) const {
    switch (code) {
        case FTPResponseCode::RESTART_MARKER: return "110 Restart marker";
        case FTPResponseCode::SERVICE_READY_SOON: return "120 Service ready soon";
        case FTPResponseCode::DATA_CONNECTION_OPEN: return "125 Data connection open";
        case FTPResponseCode::FILE_STATUS_OK: return "150 File status okay";
        case FTPResponseCode::COMMAND_OK: return "200 Command okay";
        case FTPResponseCode::COMMAND_NOT_IMPLEMENTED: return "202 Command not implemented";
        case FTPResponseCode::SYSTEM_STATUS: return "211 System status";
        case FTPResponseCode::DIRECTORY_STATUS: return "212 Directory status";
        case FTPResponseCode::FILE_STATUS: return "213 File status";
        case FTPResponseCode::HELP_MESSAGE: return "214 Help message";
        case FTPResponseCode::SYSTEM_TYPE: return "215 System type";
        case FTPResponseCode::SERVICE_READY: return "220 Service ready";
        case FTPResponseCode::SERVICE_CLOSING: return "221 Service closing";
        case FTPResponseCode::DATA_CONNECTION_OPEN_NO_TRANSFER: return "225 Data connection open, no transfer";
        case FTPResponseCode::DATA_CONNECTION_CLOSED: return "226 Data connection closed";
        case FTPResponseCode::PASSIVE_MODE: return "227 Entering passive mode";
        case FTPResponseCode::USER_LOGGED_IN: return "230 User logged in";
        case FTPResponseCode::FILE_ACTION_OK: return "250 File action okay";
        case FTPResponseCode::PATHNAME_CREATED: return "257 Pathname created";
        case FTPResponseCode::USER_NAME_OK: return "331 User name okay";
        case FTPResponseCode::NEED_ACCOUNT: return "332 Need account";
        case FTPResponseCode::FILE_ACTION_PENDING: return "350 File action pending";
        case FTPResponseCode::SERVICE_NOT_AVAILABLE: return "421 Service not available";
        case FTPResponseCode::CANNOT_OPEN_DATA_CONNECTION: return "425 Cannot open data connection";
        case FTPResponseCode::CONNECTION_CLOSED: return "426 Connection closed";
        case FTPResponseCode::FILE_ACTION_NOT_TAKEN: return "450 File action not taken";
        case FTPResponseCode::ACTION_ABORTED: return "451 Action aborted";
        case FTPResponseCode::ACTION_NOT_TAKEN_INSUFFICIENT_STORAGE: return "452 Insufficient storage";
        case FTPResponseCode::SYNTAX_ERROR: return "500 Syntax error";
        case FTPResponseCode::SYNTAX_ERROR_PARAMETERS: return "501 Syntax error in parameters";

        case FTPResponseCode::BAD_SEQUENCE: return "503 Bad sequence of commands";
        case FTPResponseCode::PARAMETER_NOT_IMPLEMENTED: return "504 Parameter not implemented";
        case FTPResponseCode::NOT_LOGGED_IN: return "530 Not logged in";
        case FTPResponseCode::NEED_ACCOUNT_FOR_STORING: return "532 Need account for storing";
        case FTPResponseCode::FILE_ACTION_NOT_TAKEN_FILE_UNAVAILABLE: return "550 File unavailable";
        case FTPResponseCode::ACTION_ABORTED_PAGE_TYPE: return "551 Page type unknown";
        case FTPResponseCode::ACTION_ABORTED_EXCEEDED_STORAGE: return "552 Exceeded storage allocation";
        case FTPResponseCode::ACTION_NOT_TAKEN_FILE_NAME: return "553 File name not allowed";
        default: return "Unknown response code";
    }
}

FTPResponseCode FTPParser::number_to_response_code(uint16_t code_num) const {
    switch (code_num) {
        case 110: return FTPResponseCode::RESTART_MARKER;
        case 120: return FTPResponseCode::SERVICE_READY_SOON;
        case 125: return FTPResponseCode::DATA_CONNECTION_OPEN;
        case 150: return FTPResponseCode::FILE_STATUS_OK;
        case 200: return FTPResponseCode::COMMAND_OK;
        case 202: return FTPResponseCode::COMMAND_NOT_IMPLEMENTED;
        case 211: return FTPResponseCode::SYSTEM_STATUS;
        case 212: return FTPResponseCode::DIRECTORY_STATUS;
        case 213: return FTPResponseCode::FILE_STATUS;
        case 214: return FTPResponseCode::HELP_MESSAGE;
        case 215: return FTPResponseCode::SYSTEM_TYPE;
        case 220: return FTPResponseCode::SERVICE_READY;
        case 221: return FTPResponseCode::SERVICE_CLOSING;
        case 225: return FTPResponseCode::DATA_CONNECTION_OPEN_NO_TRANSFER;
        case 226: return FTPResponseCode::DATA_CONNECTION_CLOSED;
        case 227: return FTPResponseCode::PASSIVE_MODE;
        case 230: return FTPResponseCode::USER_LOGGED_IN;
        case 250: return FTPResponseCode::FILE_ACTION_OK;
        case 257: return FTPResponseCode::PATHNAME_CREATED;
        case 331: return FTPResponseCode::USER_NAME_OK;
        case 332: return FTPResponseCode::NEED_ACCOUNT;
        case 350: return FTPResponseCode::FILE_ACTION_PENDING;
        case 421: return FTPResponseCode::SERVICE_NOT_AVAILABLE;
        case 425: return FTPResponseCode::CANNOT_OPEN_DATA_CONNECTION;
        case 426: return FTPResponseCode::CONNECTION_CLOSED;
        case 450: return FTPResponseCode::FILE_ACTION_NOT_TAKEN;
        case 451: return FTPResponseCode::ACTION_ABORTED;
        case 452: return FTPResponseCode::ACTION_NOT_TAKEN_INSUFFICIENT_STORAGE;
        case 500: return FTPResponseCode::SYNTAX_ERROR;
        case 501: return FTPResponseCode::SYNTAX_ERROR_PARAMETERS;
        case 502: return FTPResponseCode::COMMAND_NOT_IMPLEMENTED;
        case 503: return FTPResponseCode::BAD_SEQUENCE;
        case 504: return FTPResponseCode::PARAMETER_NOT_IMPLEMENTED;
        case 530: return FTPResponseCode::NOT_LOGGED_IN;
        case 532: return FTPResponseCode::NEED_ACCOUNT_FOR_STORING;
        case 550: return FTPResponseCode::FILE_ACTION_NOT_TAKEN_FILE_UNAVAILABLE;
        case 551: return FTPResponseCode::ACTION_ABORTED_PAGE_TYPE;
        case 552: return FTPResponseCode::ACTION_ABORTED_EXCEEDED_STORAGE;
        case 553: return FTPResponseCode::ACTION_NOT_TAKEN_FILE_NAME;
        default: return FTPResponseCode::UNKNOWN_CODE;
    }
}

std::string FTPParser::trim(const std::string& str) const {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string FTPParser::to_upper(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

bool FTPParser::validate_ftp_message(const BufferView& buffer) const {
    if (buffer.size() == 0) {
        return false;
    }
    
    // Basic validation - FTP messages should be printable ASCII
    for (size_t i = 0; i < std::min(buffer.size(), size_t(1024)); ++i) {
        uint8_t byte = buffer.data()[i];
        if (byte < 32 && byte != '\r' && byte != '\n' && byte != '\t') {
            return false;
        }
        if (byte > 126) {
            return false;
        }
    }
    
    return true;
}

bool FTPParser::is_complete_line(const BufferView& buffer) const {
    std::string data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return data.find('\n') != std::string::npos;
}

void FTPParser::reset() noexcept {
    if (ftp_message_.type == FTPMessageType::COMMAND) {
        ftp_message_.command.~FTPCommandMessage();
    } else if (ftp_message_.type == FTPMessageType::RESPONSE) {
        ftp_message_.response.~FTPResponseMessage();
    }
    ftp_message_.type = FTPMessageType::UNKNOWN;
    error_message_.clear();
}

std::string FTPParser::get_error_message() const noexcept {
    return error_message_;
}

} // namespace protocol_parser::parsers