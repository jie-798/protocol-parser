#include "../../include/parsers/security/tls_deep_inspector.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

namespace protocol_parser::security {

TLSDeepInspector::TLSDeepInspector() {
    initialize_cipher_suite_database();
}

bool TLSDeepInspector::parse_tls_packet(const protocol_parser::core::BufferView& buffer, TLSInfo& tls_info) {
    if (!can_parse(buffer)) {
        tls_info.error_message = "Buffer does not contain valid TLS data";
        return false;
    }

    tls_info.parse_timestamp = std::chrono::steady_clock::now();
    bool success = parse_tls_record(buffer, tls_info);
    
    global_stats_.record_connection(success);
    
    if (success && vulnerability_scanning_enabled_) {
        tls_info.security_analysis = analyze_security(tls_info);
    }

    tls_info.is_valid = success;
    return success;
}

bool TLSDeepInspector::parse_tls_record(const protocol_parser::core::BufferView& buffer, TLSInfo& info) {
    if (buffer.size() < TLS_RECORD_HEADER_SIZE) return false;

    size_t offset = 0;
    info.record_type = static_cast<TLSRecordType>(buffer[offset++]);
    
    uint16_t version_raw = buffer.read_be16(offset);
    info.version = static_cast<TLSVersion>(version_raw);
    offset += 2;

    info.record_length = buffer.read_be16(offset);
    offset += 2;

    if (offset + info.record_length > buffer.size()) return false;

    auto record_data = buffer.substr(offset, info.record_length);
    
    switch (info.record_type) {
        case TLSRecordType::HANDSHAKE:
            return parse_handshake_message(record_data, info);
        case TLSRecordType::APPLICATION_DATA:
            info.application_data_length = info.record_length;
            info.is_encrypted = true;
            return true;
        case TLSRecordType::ALERT:
            if (record_data.size() >= 2) {
                info.alert_level = record_data[0];
                info.alert_description = record_data[1];
            }
            return true;
        case TLSRecordType::CHANGE_CIPHER_SPEC:
            info.handshake_state.change_cipher_spec_seen = true;
            return true;
        case TLSRecordType::HEARTBEAT:
            info.security_analysis.heartbeat_enabled = true;
            if (check_heartbleed_vulnerability(info)) {
                info.security_analysis.heartbleed_vulnerable = true;
                info.security_analysis.vulnerabilities.push_back("Heartbleed (CVE-2014-0160)");
            }
            return true;
        default:
            return false;
    }
}

bool TLSDeepInspector::parse_handshake_message(const protocol_parser::core::BufferView& buffer, TLSInfo& info) {
    if (buffer.size() < TLS_HANDSHAKE_HEADER_SIZE) return false;

    size_t offset = 0;
    info.handshake_type = static_cast<TLSHandshakeType>(buffer[offset++]);
    info.handshake_length = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
    offset += 3;

    if (offset + info.handshake_length > buffer.size()) return false;

    auto message_data = buffer.substr(offset, info.handshake_length);

    switch (info.handshake_type) {
        case TLSHandshakeType::CLIENT_HELLO:
            info.handshake_state.client_hello_seen = true;
            return parse_client_hello(message_data, info);
        case TLSHandshakeType::SERVER_HELLO:
            info.handshake_state.server_hello_seen = true;
            return parse_server_hello(message_data, info);
        case TLSHandshakeType::CERTIFICATE:
            info.handshake_state.certificate_seen = true;
            return parse_certificate_message(message_data, info);
        case TLSHandshakeType::FINISHED:
            if (!info.handshake_state.client_finished_seen) {
                info.handshake_state.client_finished_seen = true;
            } else {
                info.handshake_state.server_finished_seen = true;
            }
            return true;
        default:
            return true;
    }
}

bool TLSDeepInspector::parse_client_hello(const protocol_parser::core::BufferView& buffer, TLSInfo& info) {
    if (buffer.size() < 38) return false;

    size_t offset = 0;
    uint16_t client_version = buffer.read_be16(offset);
    info.version = static_cast<TLSVersion>(client_version);
    offset += 2;

    std::memcpy(info.client_random.data(), buffer.data() + offset, 32);
    offset += 32;

    uint8_t session_id_length = buffer[offset++];
    if (offset + session_id_length > buffer.size()) return false;
    
    if (session_id_length > 0) {
        info.session_id.resize(session_id_length);
        std::memcpy(info.session_id.data(), buffer.data() + offset, session_id_length);
        info.handshake_state.is_resumption = true;
    }
    offset += session_id_length;

    if (offset + 2 > buffer.size()) return false;
    uint16_t cipher_suites_length = buffer.read_be16(offset);
    offset += 2;

    if (offset + cipher_suites_length > buffer.size()) return false;
    
    for (size_t i = 0; i < cipher_suites_length; i += 2) {
        if (offset + i + 1 < buffer.size()) {
            uint16_t suite_id = buffer.read_be16(offset + i);
            auto it = cipher_suite_database_.find(suite_id);
            if (it != cipher_suite_database_.end()) {
                info.cipher_suites.push_back(it->second);
            }
        }
    }
    offset += cipher_suites_length;

    if (offset >= buffer.size()) return false;
    uint8_t compression_methods_length = buffer[offset++];
    
    if (offset + compression_methods_length > buffer.size()) return false;
    info.compression_methods.resize(compression_methods_length);
    std::memcpy(info.compression_methods.data(), buffer.data() + offset, compression_methods_length);
    offset += compression_methods_length;

    if (compression_methods_length > 1) {
        info.security_analysis.compression_enabled = true;
        info.security_analysis.crime_vulnerable = true;
        info.security_analysis.vulnerabilities.push_back("Compression enabled (CRIME)");
    }

    // 解析扩展
    if (offset + 2 <= buffer.size()) {
        uint16_t extensions_length = buffer.read_be16(offset);
        offset += 2;
        if (offset + extensions_length <= buffer.size()) {
            auto extensions_data = buffer.substr(offset, extensions_length);
            parse_extensions(extensions_data, info.extensions);
        }
    }

    return true;
}

bool TLSDeepInspector::parse_server_hello(const protocol_parser::core::BufferView& buffer, TLSInfo& info) {
    if (buffer.size() < 38) return false;

    size_t offset = 2; // 跳过版本
    std::memcpy(info.server_random.data(), buffer.data() + offset, 32);
    offset += 32;

    uint8_t session_id_length = buffer[offset++];
    offset += session_id_length;

    if (offset + 2 <= buffer.size()) {
        uint16_t cipher_suite_id = buffer.read_be16(offset);
        auto it = cipher_suite_database_.find(cipher_suite_id);
        if (it != cipher_suite_database_.end()) {
            info.session.cipher_suite = it->second;
            
            if (is_weak_cipher_suite(it->second)) {
                info.security_analysis.uses_deprecated_cipher = true;
                info.security_analysis.vulnerabilities.push_back("Weak cipher: " + it->second.name);
            }
            
            if (supports_perfect_forward_secrecy(it->second)) {
                info.security_analysis.perfect_forward_secrecy = true;
            }
        }
    }

    return true;
}

bool TLSDeepInspector::parse_certificate_message(const protocol_parser::core::BufferView& buffer, TLSInfo& info) {
    if (buffer.size() < 3) return false;

    size_t offset = 0;
    uint32_t certificates_length = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
    offset += 3;

    if (offset + certificates_length > buffer.size()) return false;

    // 解析第一个证书
    if (certificates_length > 3) {
        uint32_t cert_length = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
        offset += 3;

        if (offset + cert_length <= buffer.size()) {
            TLSCertificate cert;
            cert.raw_data.resize(cert_length);
            std::memcpy(cert.raw_data.data(), buffer.data() + offset, cert_length);
            
            // 简化的证书信息
            cert.subject = "CN=example.com";
            cert.issuer = "CN=CA";
            cert.not_before = std::chrono::system_clock::now() - std::chrono::hours(24*30);
            cert.not_after = std::chrono::system_clock::now() + std::chrono::hours(24*365);
            cert.is_expired = false;
            cert.is_self_signed = false;
            
            info.certificate_chain.push_back(cert);
            info.server_certificate = cert;
        }
    }

    return true;
}

TLSSecurityAnalysis TLSDeepInspector::analyze_security(const TLSInfo& info) const {
    TLSSecurityAnalysis analysis = info.security_analysis;
    
    if (is_deprecated_protocol(info.version)) {
        analysis.uses_weak_protocol = true;
        analysis.vulnerabilities.push_back("Deprecated TLS version");
    }

    if (check_poodle_vulnerability(info)) {
        analysis.poodle_vulnerable = true;
        analysis.vulnerabilities.push_back("POODLE vulnerability");
    }

    analysis.security_score = calculate_security_score(info);
    analysis.security_grade = determine_security_grade(analysis.security_score);

    return analysis;
}

uint32_t TLSDeepInspector::calculate_security_score(const TLSInfo& info) const {
    uint32_t score = 100;

    if (info.version < TLSVersion::TLS1_2) score -= 40;
    if (info.security_analysis.uses_deprecated_cipher) score -= 20;
    if (info.security_analysis.compression_enabled) score -= 15;
    if (!info.security_analysis.perfect_forward_secrecy) score -= 10;
    if (info.security_analysis.heartbleed_vulnerable) score -= 25;

    return std::max(0u, score);
}

std::string TLSDeepInspector::determine_security_grade(uint32_t score) const {
    if (score >= 95) return "A+";
    if (score >= 80) return "A";
    if (score >= 65) return "B";
    if (score >= 50) return "C";
    if (score >= 35) return "D";
    return "F";
}

bool TLSDeepInspector::can_parse(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < TLS_RECORD_HEADER_SIZE) return false;

    uint8_t content_type = buffer[0];
    if (content_type < 20 || content_type > 24) return false;

    uint16_t version = buffer.read_be16(1);
    if (version < 0x0300 || version > 0x0304) return false;

    uint16_t length = buffer.read_be16(3);
    return length <= MAX_TLS_RECORD_SIZE && length > 0;
}

void TLSDeepInspector::initialize_cipher_suite_database() {
    // 基础密码套件
    cipher_suite_database_[0x002F] = {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES-128-CBC", "SHA1", false, 128, 16, 20, false, 3};
    cipher_suite_database_[0x0035] = {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES-256-CBC", "SHA1", false, 256, 16, 20, false, 3};
    cipher_suite_database_[0x009C] = {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AES-128-GCM", "SHA256", true, 128, 12, 16, false, 4};
    
    // ECDHE密码套件（支持PFS）
    cipher_suite_database_[0xC02F] = {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES-128-GCM", "SHA256", true, 128, 12, 16, true, 5};
    cipher_suite_database_[0xC030] = {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES-256-GCM", "SHA384", true, 256, 12, 16, true, 5};
    
    // TLS 1.3密码套件
    cipher_suite_database_[0x1301] = {0x1301, "TLS_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES-128-GCM", "SHA256", true, 128, 12, 16, true, 5};
    cipher_suite_database_[0x1302] = {0x1302, "TLS_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AES-256-GCM", "SHA384", true, 256, 12, 16, true, 5};
}

bool TLSDeepInspector::is_weak_cipher_suite(const TLSCipherSuite& suite) const {
    return suite.encryption.find("RC4") != std::string::npos ||
           suite.encryption.find("DES") != std::string::npos ||
           suite.mac == "MD5" ||
           suite.security_level < 3;
}

bool TLSDeepInspector::is_deprecated_protocol(TLSVersion version) const {
    return version < TLSVersion::TLS1_2;
}

bool TLSDeepInspector::supports_perfect_forward_secrecy(const TLSCipherSuite& suite) const {
    return suite.supports_pfs;
}

// 漏洞检测方法
bool TLSDeepInspector::check_heartbleed_vulnerability(const TLSInfo& info) const {
    return info.security_analysis.heartbeat_enabled && 
           info.version >= TLSVersion::TLS1_0 && info.version <= TLSVersion::TLS1_2;
}

bool TLSDeepInspector::check_poodle_vulnerability(const TLSInfo& info) const {
    return info.version == TLSVersion::SSLv3;
}

bool TLSDeepInspector::check_beast_vulnerability(const TLSInfo& info) const {
    return info.version <= TLSVersion::TLS1_0;
}

bool TLSDeepInspector::check_crime_vulnerability(const TLSInfo& info) const {
    return info.security_analysis.compression_enabled;
}

bool TLSDeepInspector::check_freak_vulnerability(const TLSInfo& info) const {
    return false; // 简化实现
}

bool TLSDeepInspector::check_logjam_vulnerability(const TLSInfo& info) const {
    return false; // 简化实现
}

// 其他方法的简化实现
bool TLSDeepInspector::parse_extensions(const protocol_parser::core::BufferView& buffer, std::vector<TLSExtension>& extensions) {
    size_t offset = 0;
    while (offset + 4 <= buffer.size()) {
        TLSExtension ext;
        uint16_t type = buffer.read_be16(offset);
        ext.type = static_cast<TLSExtensionType>(type);
        offset += 2;
        
        ext.length = buffer.read_be16(offset);
        offset += 2;
        
        if (offset + ext.length > buffer.size()) break;
        
        ext.data.resize(ext.length);
        std::memcpy(ext.data.data(), buffer.data() + offset, ext.length);
        
        // 简化的SNI解析
        if (ext.type == TLSExtensionType::SERVER_NAME && ext.length > 5) {
            size_t name_offset = 5; // 跳过头部
            if (name_offset + 2 < ext.length) {
                uint16_t name_length = (ext.data[name_offset] << 8) | ext.data[name_offset + 1];
                name_offset += 2;
                if (name_offset + name_length <= ext.length) {
                    ext.server_name = std::string(reinterpret_cast<const char*>(ext.data.data() + name_offset), name_length);
                }
            }
        }
        
        extensions.push_back(std::move(ext));
        offset += ext.length;
    }
    return true;
}

std::string TLSDeepInspector::generate_security_report() const {
    return "TLS Security Analysis Report - Implementation Required";
}

std::vector<std::string> TLSDeepInspector::detect_vulnerabilities(const TLSInfo& info) const {
    return info.security_analysis.vulnerabilities;
}

bool TLSDeepInspector::analyze_certificate_chain(const std::vector<TLSCertificate>& chain, TLSSecurityAnalysis& analysis) const {
    return true; // 简化实现
}

bool TLSDeepInspector::validate_certificate(const TLSCertificate& cert) const {
    return !cert.is_expired && !cert.is_self_signed;
}

TLSVersion TLSDeepInspector::detect_tls_version(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() >= 3) {
        uint16_t version = buffer.read_be16(1);
        return static_cast<TLSVersion>(version);
    }
    return TLSVersion::TLS1_2;
}

std::string TLSDeepInspector::get_vulnerability_description(const std::string& vuln_name) const {
    return "Vulnerability: " + vuln_name;
}

} // namespace protocol_parser::security