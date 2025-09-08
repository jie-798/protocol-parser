#pragma once

#include "parsers/base_parser.hpp"
#include "core/buffer_view.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace protocol_parser::parsers {

// 简化类型引用的using声明
using BufferView = core::BufferView;

// DNS Header structure
struct DNSHeader {
    uint16_t id;           // Transaction ID
    uint16_t flags;        // Flags
    uint16_t qdcount;      // Number of questions
    uint16_t ancount;      // Number of answers
    uint16_t nscount;      // Number of authority records
    uint16_t arcount;      // Number of additional records
};

// DNS Question structure
struct DNSQuestion {
    std::string qname;     // Domain name
    uint16_t qtype;        // Query type
    uint16_t qclass;       // Query class
};

// DNS Resource Record structure
struct DNSResourceRecord {
    std::string name;      // Domain name
    uint16_t type;         // Record type
    uint16_t rr_class;     // Record class
    uint32_t ttl;          // Time to live
    uint16_t rdlength;     // Resource data length
    std::vector<uint8_t> rdata; // Resource data
};

// DNS Message structure
struct DNSMessage {
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSResourceRecord> answers;
    std::vector<DNSResourceRecord> authority;
    std::vector<DNSResourceRecord> additional;
};

// DNS Record Types
enum class DNSRecordType : uint16_t {
    A = 1,          // IPv4 address
    NS = 2,         // Name server
    CNAME = 5,      // Canonical name
    SOA = 6,        // Start of authority
    PTR = 12,       // Pointer
    MX = 15,        // Mail exchange
    TXT = 16,       // Text
    AAAA = 28,      // IPv6 address
    SRV = 33,       // Service
    OPT = 41        // EDNS option
};

// DNS Classes
enum class DNSClass : uint16_t {
    INTERNET = 1,   // Internet
    CS = 2,         // CSNET
    CH = 3,         // CHAOS
    HS = 4          // Hesiod
};

// DNS Response Codes
enum class DNSResponseCode : uint8_t {
    kNoError = 0,    // No error
    FORMERR = 1,    // Format error
    SERVFAIL = 2,   // Server failure
    NXDOMAIN = 3,   // Non-existent domain
    NOTIMP = 4,     // Not implemented
    REFUSED = 5,    // Query refused
    YXDOMAIN = 6,   // Name exists when it should not
    YXRRSET = 7,    // RR set exists when it should not
    NXRRSET = 8,    // RR set that should exist does not
    NOTAUTH = 9,    // Server not authoritative
    NOTZONE = 10    // Name not contained in zone
};

class DNSParser : public BaseParser {
public:
    DNSParser() = default;
    ~DNSParser() = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;
    [[nodiscard]] double get_progress() const noexcept override;
    [[nodiscard]] std::string get_error_message() const noexcept;
    
    // Protocol identification methods
    [[nodiscard]] std::string get_protocol_name() const { return "DNS"; }
    [[nodiscard]] uint16_t get_protocol_id() const { return 53; } // DNS port

    // DNS-specific methods
    [[nodiscard]] const DNSMessage& get_dns_message() const { return dns_message_; }
    [[nodiscard]] bool is_query() const;
    [[nodiscard]] bool is_response() const;
    [[nodiscard]] DNSResponseCode get_response_code() const;
    [[nodiscard]] bool is_recursive_desired() const;
    [[nodiscard]] bool is_recursive_available() const;
    [[nodiscard]] bool is_authoritative() const;
    [[nodiscard]] bool is_truncated() const;

    // Utility methods
    [[nodiscard]] std::string format_domain_name(const std::vector<uint8_t>& data, size_t& offset) const;
    [[nodiscard]] std::string record_type_to_string(uint16_t type) const;
    [[nodiscard]] std::string class_to_string(uint16_t rr_class) const;

private:
    static const ProtocolInfo protocol_info_;
    DNSMessage dns_message_;
    
    // Helper methods
    [[nodiscard]] ParseResult parse_header(const BufferView& buffer, size_t& offset);
    [[nodiscard]] ParseResult parse_questions(const BufferView& buffer, size_t& offset);
    [[nodiscard]] ParseResult parse_resource_records(const BufferView& buffer, size_t& offset,
                                                      std::vector<DNSResourceRecord>& records, uint16_t count);
    [[nodiscard]] std::string parse_domain_name(const BufferView& buffer, size_t& offset) const;
    [[nodiscard]] bool validate_dns_packet(const BufferView& buffer) const;
};

/**
 * DNS解析器工厂
 */
class DNSParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<DNSParser>();
    }
    
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const {
        return {53};
    }
};

} // namespace protocol_parser::parsers