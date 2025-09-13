#pragma once

#include "parsers/base_parser.hpp"
#include <unordered_map>
#include <vector>
#include <optional>
#include <array>
#include <string_view>

namespace ProtocolParser::Parsers::Application {

// DHCP消息类型 (RFC 2131)
enum class DHCPMessageType : uint8_t {
    BOOTREQUEST = 1,
    BOOTREPLY = 2
};

// DHCP操作码 (RFC 2131)
enum class DHCPOpcode : uint8_t {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
    FORCERENEW = 9,
    LEASEQUERY = 10,
    LEASEUNASSIGNED = 11,
    LEASEUNKNOWN = 12,
    LEASEACTIVE = 13
};

// DHCP硬件类型 (RFC 1700)
enum class DHCPHardwareType : uint8_t {
    ETHERNET = 1,
    IEEE802 = 6,
    ARCNET = 7,
    FRAME_RELAY = 15,
    ATM = 16,
    HDLC = 17,
    FIBRE_CHANNEL = 18,
    ATM2 = 19,
    SERIAL_LINE = 20
};

// DHCP选项类型 (RFC 2132)
enum class DHCPOptionType : uint8_t {
    SUBNET_MASK = 1,
    TIME_OFFSET = 2,
    ROUTER = 3,
    TIME_SERVER = 4,
    NAME_SERVER = 5,
    DNS_SERVER = 6,
    LOG_SERVER = 7,
    COOKIE_SERVER = 8,
    LPR_SERVER = 9,
    IMPRESS_SERVER = 10,
    RESOURCE_LOCATION_SERVER = 11,
    HOST_NAME = 12,
    BOOT_FILE_SIZE = 13,
    MERIT_DUMP_FILE = 14,
    DOMAIN_NAME = 15,
    SWAP_SERVER = 16,
    ROOT_PATH = 17,
    EXTENSIONS_PATH = 18,
    IP_FORWARDING = 19,
    NON_LOCAL_SOURCE_ROUTING = 20,
    POLICY_FILTER = 21,
    MAX_DATAGRAM_REASSEMBLY_SIZE = 22,
    DEFAULT_IP_TTL = 23,
    PATH_MTU_AGING_TIMEOUT = 24,
    PATH_MTU_PLATEAU_TABLE = 25,
    INTERFACE_MTU = 26,
    ALL_SUBNETS_LOCAL = 27,
    BROADCAST_ADDRESS = 28,
    PERFORM_MASK_DISCOVERY = 29,
    MASK_SUPPLIER = 30,
    PERFORM_ROUTER_DISCOVERY = 31,
    ROUTER_SOLICITATION_ADDRESS = 32,
    STATIC_ROUTE = 33,
    TRAILER_ENCAPSULATION = 34,
    ARP_CACHE_TIMEOUT = 35,
    ETHERNET_ENCAPSULATION = 36,
    TCP_DEFAULT_TTL = 37,
    TCP_KEEPALIVE_INTERVAL = 38,
    TCP_KEEPALIVE_GARBAGE = 39,
    NIS_DOMAIN = 40,
    NIS_SERVERS = 41,
    NTP_SERVERS = 42,
    VENDOR_SPECIFIC = 43,
    NETBIOS_NAME_SERVERS = 44,
    NETBIOS_DD_SERVER = 45,
    NETBIOS_NODE_TYPE = 46,
    NETBIOS_SCOPE = 47,
    X_FONT_SERVERS = 48,
    X_DISPLAY_MANAGERS = 49,
    DHCP_REQUESTED_ADDRESS = 50,
    DHCP_LEASE_TIME = 51,
    DHCP_OPTION_OVERLOAD = 52,
    DHCP_MESSAGE_TYPE = 53,
    DHCP_SERVER_IDENTIFIER = 54,
    DHCP_PARAMETER_REQUEST_LIST = 55,
    DHCP_MESSAGE = 56,
    DHCP_MAX_MESSAGE_SIZE = 57,
    DHCP_RENEWAL_TIME = 58,
    DHCP_REBINDING_TIME = 59,
    DHCP_VENDOR_CLASS_ID = 60,
    DHCP_CLIENT_IDENTIFIER = 61,
    DHCP_NETWARE_DOMAIN_NAME = 62,
    DHCP_NETWARE_SUB_OPTIONS = 63,
    DHCP_NIS_PLUS_DOMAIN = 64,
    DHCP_NIS_PLUS_SERVERS = 65,
    DHCP_TFTP_SERVER_NAME = 66,
    DHCP_BOOTFILE_NAME = 67,
    DHCP_MOBILE_IP_HOME_AGENT = 68,
    DHCP_SMTP_SERVERS = 69,
    DHCP_POP3_SERVERS = 70,
    DHCP_NNTP_SERVERS = 71,
    DHCP_WWW_SERVERS = 72,
    DHCP_FINGER_SERVERS = 73,
    DHCP_IRC_SERVERS = 74,
    DHCP_STREETTALK_SERVERS = 75,
    DHCP_STDA_SERVERS = 76,
    DHCP_USER_CLASS = 77,
    DHCP_FQDN = 81,
    DHCP_AGENT_OPTIONS = 82,
    DHCP_NDS_SERVERS = 85,
    DHCP_NDS_TREE_NAME = 86,
    DHCP_NDS_CONTEXT = 87,
    DHCP_CLIENT_LAST_TRANSACTION_TIME = 91,
    DHCP_ASSOCIATED_IP = 92,
    DHCP_AUTO_CONFIGURE = 116,
    DHCP_NAME_SERVICE_SEARCH = 117,
    DHCP_SUBNET_SELECTION = 118,
    DHCP_DNS_DOMAIN_SEARCH_LIST = 119,
    DHCP_CLASSLESS_ROUTE = 121,
    END = 255,
    PAD = 0
};

// DHCP选项数据结构
struct DHCPOption {
    DHCPOptionType type;
    uint8_t length;
    std::vector<uint8_t> data;
    
    // 便捷访问方法
    [[nodiscard]] uint32_t as_uint32() const noexcept;
    [[nodiscard]] uint16_t as_uint16() const noexcept;
    [[nodiscard]] uint8_t as_uint8() const noexcept;
    [[nodiscard]] std::string as_string() const;
    [[nodiscard]] std::vector<uint32_t> as_ip_list() const;
};

// DHCP报文头部结构 (RFC 2131)
struct DHCPHeader {
    DHCPMessageType op;              // 操作码
    DHCPHardwareType htype;          // 硬件地址类型
    uint8_t hlen;                    // 硬件地址长度
    uint8_t hops;                    // 跳数
    uint32_t xid;                    // 事务ID
    uint16_t secs;                   // 秒数
    uint16_t flags;                  // 标志
    uint32_t ciaddr;                 // 客户端IP地址
    uint32_t yiaddr;                 // 您的IP地址
    uint32_t siaddr;                 // 服务器IP地址
    uint32_t giaddr;                 // 网关IP地址
    std::array<uint8_t, 16> chaddr;  // 客户端硬件地址
    std::array<char, 64> sname;      // 服务器名称
    std::array<char, 128> file;      // 启动文件名
};

// 完整的DHCP消息
struct DHCPMessage {
    DHCPHeader header;
    std::vector<DHCPOption> options;
    
    // 便捷方法
    [[nodiscard]] std::optional<DHCPOpcode> get_message_type() const noexcept;
    [[nodiscard]] std::optional<uint32_t> get_server_identifier() const noexcept;
    [[nodiscard]] std::optional<uint32_t> get_requested_ip() const noexcept;
    [[nodiscard]] std::optional<uint32_t> get_lease_time() const noexcept;
    [[nodiscard]] std::optional<std::vector<uint32_t>> get_dns_servers() const noexcept;
    [[nodiscard]] std::optional<std::string> get_domain_name() const noexcept;
    [[nodiscard]] std::optional<std::string> get_hostname() const noexcept;
    [[nodiscard]] bool is_broadcast() const noexcept;
};

class DHCPParser : public BaseParser {
public:
    explicit DHCPParser() = default;
    ~DHCPParser() override = default;

    // 基类接口实现
    [[nodiscard]] ParseResult parse(const BufferView& buffer) noexcept override;
    [[nodiscard]] std::string get_protocol_name() const noexcept override;
    [[nodiscard]] uint16_t get_default_port() const noexcept override;
    [[nodiscard]] std::vector<uint16_t> get_supported_ports() const noexcept override;
    void reset() noexcept override;

    // DHCP特定接口
    [[nodiscard]] const DHCPMessage& get_dhcp_message() const noexcept;
    [[nodiscard]] bool is_dhcp_packet() const noexcept;
    
    // 验证和安全检查
    [[nodiscard]] bool validate_message() const noexcept;
    [[nodiscard]] bool is_malformed() const noexcept;
    
    // 高级分析功能
    struct DHCPAnalysis {
        bool is_client_request{false};
        bool is_server_response{false};
        bool has_relay_agent{false};
        bool is_renewal{false};
        bool is_rebinding{false};
        std::optional<std::string> vendor_class;
        std::optional<std::string> client_identifier;
        std::vector<DHCPOptionType> requested_options;
        size_t total_options{0};
        size_t unknown_options{0};
        bool has_security_issues{false};
        std::vector<std::string> security_warnings;
    };
    
    [[nodiscard]] DHCPAnalysis analyze_message() const noexcept;
    
    // 统计信息
    struct DHCPStatistics {
        uint64_t total_messages{0};
        uint64_t discover_count{0};
        uint64_t offer_count{0};
        uint64_t request_count{0};
        uint64_t ack_count{0};
        uint64_t nak_count{0};
        uint64_t release_count{0};
        uint64_t inform_count{0};
        uint64_t malformed_count{0};
        uint64_t unknown_options_count{0};
        std::unordered_map<DHCPOptionType, uint64_t> option_usage;
    };
    
    [[nodiscard]] const DHCPStatistics& get_statistics() const noexcept;
    void reset_statistics() noexcept;

    // 工具方法
    [[nodiscard]] static std::string ip_to_string(uint32_t ip) noexcept;
    [[nodiscard]] static std::string mac_to_string(const std::array<uint8_t, 16>& mac, uint8_t len) noexcept;
    [[nodiscard]] static std::string option_type_to_string(DHCPOptionType type) noexcept;
    [[nodiscard]] static std::string message_type_to_string(DHCPOpcode type) noexcept;
    [[nodiscard]] static bool is_valid_magic_cookie(const uint8_t* data) noexcept;

private:
    DHCPMessage dhcp_message_;
    bool parsed_successfully_{false};
    bool is_malformed_{false};
    DHCPStatistics statistics_;
    
    // 私有解析方法
    [[nodiscard]] bool parse_header(const uint8_t* data, size_t size) noexcept;
    [[nodiscard]] bool parse_options(const uint8_t* data, size_t size, size_t offset) noexcept;
    [[nodiscard]] bool parse_single_option(const uint8_t* data, size_t size, size_t& offset) noexcept;
    
    // 验证方法
    [[nodiscard]] bool validate_header(const DHCPHeader& header) const noexcept;
    [[nodiscard]] bool validate_option(const DHCPOption& option) const noexcept;
    
    // 安全检查
    void perform_security_analysis() noexcept;
    
    // 统计更新
    void update_statistics(const DHCPMessage& message) noexcept;
    
    // 常量定义
    static constexpr size_t DHCP_MIN_SIZE = 236;        // 最小DHCP报文大小
    static constexpr size_t DHCP_HEADER_SIZE = 236;     // DHCP头部大小
    static constexpr uint32_t DHCP_MAGIC_COOKIE = 0x63825363;  // DHCP魔数
    static constexpr uint16_t DHCP_CLIENT_PORT = 68;    // DHCP客户端端口
    static constexpr uint16_t DHCP_SERVER_PORT = 67;    // DHCP服务器端口
    static constexpr uint8_t DHCP_BROADCAST_FLAG = 0x80; // 广播标志
};

} // namespace ProtocolParser::Parsers::Application