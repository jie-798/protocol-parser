#include "../../../include/parsers/application/dns_parser.hpp"
#include "utils/network_utils.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace protocol_parser::utils;

namespace protocol_parser::parsers {

ParseResult DNSParser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;
    if (buffer.size() < 12) {
        return ParseResult::InvalidFormat;
    }

    size_t offset = 0;
    
    // Parse DNS header
    auto status = parse_header(buffer, offset);
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse questions
    status = parse_questions(buffer, offset);
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse answer records
    status = parse_resource_records(buffer, offset, dns_message_.answers, dns_message_.header.ancount);
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse authority records
    status = parse_resource_records(buffer, offset, dns_message_.authority, dns_message_.header.nscount);
    if (status != ParseResult::Success) {
        return status;
    }

    // Parse additional records
    status = parse_resource_records(buffer, offset, dns_message_.additional, dns_message_.header.arcount);
    if (status != ParseResult::Success) {
        return status;
    }

    // Store parsed data in context
    context.metadata["dns_transaction_id"] = dns_message_.header.id;
    context.metadata["dns_is_query"] = is_query();
    context.metadata["dns_is_response"] = is_response();
    context.metadata["dns_question_count"] = dns_message_.header.qdcount;
    context.metadata["dns_answer_count"] = dns_message_.header.ancount;
    context.metadata["dns_response_code"] = static_cast<uint8_t>(get_response_code());
    
    if (!dns_message_.questions.empty()) {
        context.metadata["dns_query_name"] = dns_message_.questions[0].qname;
        context.metadata["dns_query_type"] = dns_message_.questions[0].qtype;
    }

    context.offset = offset;
    return ParseResult::Success;
}

ParseResult DNSParser::parse_header(const BufferView& buffer, size_t& offset) {
    if (buffer.size() < offset + 12) {
        return ParseResult::NeedMoreData;
    }

    const auto* header_ptr = reinterpret_cast<const DNSHeader*>(buffer.data() + offset);
    
    dns_message_.header.id = ntohs(header_ptr->id);
    dns_message_.header.flags = ntohs(header_ptr->flags);
    dns_message_.header.qdcount = ntohs(header_ptr->qdcount);
    dns_message_.header.ancount = ntohs(header_ptr->ancount);
    dns_message_.header.nscount = ntohs(header_ptr->nscount);
    dns_message_.header.arcount = ntohs(header_ptr->arcount);

    offset += sizeof(DNSHeader);
    return ParseResult::Success;
}

ParseResult DNSParser::parse_questions(const BufferView& buffer, size_t& offset) {
    dns_message_.questions.reserve(dns_message_.header.qdcount);
    
    for (uint16_t i = 0; i < dns_message_.header.qdcount; ++i) {
        DNSQuestion question;
        
        // Parse domain name
        question.qname = parse_domain_name(buffer, offset);
        if (question.qname.empty()) {
            return ParseResult::InvalidFormat;
        }

        // Parse question type and class
        if (buffer.size() < offset + 4) {
            return ParseResult::NeedMoreData;
        }

        question.qtype = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;
        question.qclass = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;

        dns_message_.questions.push_back(question);
    }
    
    return ParseResult::Success;
}

ParseResult DNSParser::parse_resource_records(const BufferView& buffer, size_t& offset, 
                                            std::vector<DNSResourceRecord>& records, uint16_t count) {
    records.reserve(count);
    
    for (uint16_t i = 0; i < count; ++i) {
        DNSResourceRecord record;
        
        // Parse name
        record.name = parse_domain_name(buffer, offset);
        if (record.name.empty()) {
            return ParseResult::InvalidFormat;
        }

        // Parse type, class, TTL, and data length
        if (buffer.size() < offset + 10) {
            return ParseResult::NeedMoreData;
        }

        record.type = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;
        record.rr_class = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;
        record.ttl = ntohl(*reinterpret_cast<const uint32_t*>(buffer.data() + offset));
        offset += 4;
        record.rdlength = ntohs(*reinterpret_cast<const uint16_t*>(buffer.data() + offset));
        offset += 2;

        // Parse resource data
        if (buffer.size() < offset + record.rdlength) {
            return ParseResult::NeedMoreData;
        }

        record.rdata.resize(record.rdlength);
        std::memcpy(record.rdata.data(), buffer.data() + offset, record.rdlength);
        offset += record.rdlength;

        records.push_back(std::move(record));
    }

    return ParseResult::Success;
}

std::string DNSParser::parse_domain_name(const BufferView& buffer, size_t& offset) const {
    std::string domain_name;
    bool jumped = false;
    size_t original_offset = offset;
    size_t max_jumps = 10; // Prevent infinite loops
    size_t jump_count = 0;

    while (offset < buffer.size()) {
        uint8_t length = buffer.data()[offset];
        
        // Check for compression (pointer)
        if ((length & 0xC0) == 0xC0) {
            if (offset + 1 >= buffer.size()) {
                return "";
            }
            
            if (++jump_count > max_jumps) {
                return ""; // Too many jumps, likely a loop
            }
            
            uint16_t pointer = ((length & 0x3F) << 8) | buffer.data()[offset + 1];
            if (!jumped) {
                original_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            continue;
        }
        
        // End of domain name
        if (length == 0) {
            offset++;
            break;
        }
        
        // Regular label
        if (offset + 1 + length >= buffer.size()) {
            return "";
        }
        
        if (!domain_name.empty()) {
            domain_name += ".";
        }
        
        domain_name.append(reinterpret_cast<const char*>(buffer.data() + offset + 1), length);
        offset += 1 + length;
    }

    if (jumped) {
        offset = original_offset;
    }

    return domain_name;
}

bool DNSParser::validate_dns_packet(const BufferView& buffer) const {
    // Minimum DNS packet size (header only)
    if (buffer.size() < sizeof(DNSHeader)) {
        return false;
    }

    // Additional validation can be added here
    return true;
}

bool DNSParser::is_query() const {
    return (dns_message_.header.flags & 0x8000) == 0;
}

bool DNSParser::is_response() const {
    return (dns_message_.header.flags & 0x8000) != 0;
}

DNSResponseCode DNSParser::get_response_code() const {
    return static_cast<DNSResponseCode>(dns_message_.header.flags & 0x000F);
}

bool DNSParser::is_recursive_desired() const {
    return (dns_message_.header.flags & 0x0100) != 0;
}

bool DNSParser::is_recursive_available() const {
    return (dns_message_.header.flags & 0x0080) != 0;
}

bool DNSParser::is_authoritative() const {
    return (dns_message_.header.flags & 0x0400) != 0;
}

bool DNSParser::is_truncated() const {
    return (dns_message_.header.flags & 0x0200) != 0;
}

std::string DNSParser::record_type_to_string(uint16_t type) const {
    switch (static_cast<DNSRecordType>(type)) {
        case DNSRecordType::A: return "A";
        case DNSRecordType::NS: return "NS";
        case DNSRecordType::CNAME: return "CNAME";
        case DNSRecordType::SOA: return "SOA";
        case DNSRecordType::PTR: return "PTR";
        case DNSRecordType::MX: return "MX";
        case DNSRecordType::TXT: return "TXT";
        case DNSRecordType::AAAA: return "AAAA";
        case DNSRecordType::SRV: return "SRV";
        case DNSRecordType::OPT: return "OPT";
        default: return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

std::string DNSParser::class_to_string(uint16_t rr_class) const {
    switch (static_cast<DNSClass>(rr_class)) {
        case DNSClass::INTERNET: return "IN";
        case DNSClass::CS: return "CS";
        case DNSClass::CH: return "CH";
        case DNSClass::HS: return "HS";
        default: return "UNKNOWN(" + std::to_string(rr_class) + ")";
    }}

// DNS协议信息
const ProtocolInfo DNSParser::protocol_info_ = {
    "DNS",
    53,     // DNS端口
    12,     // 最小头长度
    12,     // 最小包大小
    65535   // 最大包大小
};

const ProtocolInfo& DNSParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool DNSParser::can_parse(const BufferView& buffer) const noexcept {
    return buffer.size() >= 12; // DNS头部最小长度
}

double DNSParser::get_progress() const noexcept {
    return 1.0; // DNS解析是一次性完成的
}

void DNSParser::reset() noexcept {
    dns_message_ = DNSMessage{};
    error_message_.clear();
}

std::string DNSParser::get_error_message() const noexcept {
    return error_message_;
}

} // namespace protocol_parser::parsers