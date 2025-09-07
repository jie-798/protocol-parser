#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <iomanip>
#include <chrono>
#include <map>
#include <algorithm>
#include <signal.h>
#include <fstream>
#include <ctime>
#include <sstream>

// npcap headers
#include "pcap.h"

// 我们的解析器头文件
#include "parsers/base_parser.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/ipv4_parser.hpp"
#include "parsers/ipv6_parser.hpp"
#include "parsers/tcp_parser.hpp"
#include "parsers/udp_parser.hpp"
#include "parsers/sctp_parser.hpp"
#include "parsers/icmp_parser.hpp"
#include "parsers/icmpv6_parser.hpp"
#include "core/buffer_view.hpp"

using namespace protocol_parser::parsers;
using namespace protocol_parser::core;

// 全局变量
static bool g_running = true;
static pcap_dumper_t* g_pcap_dumper = nullptr;
static pcap_t* g_pcap_handle = nullptr;

// 统计信息结构
struct PacketStats {
    size_t total_packets = 0;
    size_t ethernet_packets = 0;
    size_t ipv4_packets = 0;
    size_t ipv6_packets = 0;
    size_t tcp_packets = 0;
    size_t udp_packets = 0;
    size_t sctp_packets = 0;
    size_t icmp_packets = 0;
    size_t icmpv6_packets = 0;
    size_t other_packets = 0;
    size_t parse_errors = 0;
    
    std::map<uint16_t, size_t> tcp_ports;
    std::map<uint16_t, size_t> udp_ports;
    std::map<uint16_t, size_t> sctp_ports;
    std::map<std::string, size_t> ip_addresses;
    
    size_t total_bytes = 0;
    std::chrono::steady_clock::time_point start_time;
    std::string pcap_filename;
};

static PacketStats g_stats;

// 格式化时间戳
std::string format_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

// 打印数据包详细信息
void print_packet_details(size_t packet_num, size_t packet_len, const std::string& info) {
    std::cout << std::setw(6) << packet_num << " "
              << format_timestamp() << " "
              << std::setw(8) << packet_len << " "
              << info << std::endl;
}

// 信号处理函数
void signal_handler(int signal) {
    std::cout << "\n收到停止信号，正在停止捕获..." << std::endl;
    g_running = false;
    if (g_pcap_handle) {
        pcap_breakloop(g_pcap_handle);
    }
}

// 解析传输层协议
std::string parse_transport_layer(const BufferView& buffer, uint8_t protocol, 
                                 const std::string& src_ip, const std::string& dst_ip) {
    std::stringstream info;
    
    try {
        ParseContext context;
        context.buffer = buffer;
        
        switch (protocol) {
            case 6: { // TCP
                TCPParser tcp_parser;
                if (tcp_parser.can_parse(buffer)) {
                    auto result = tcp_parser.parse(context);
                    if (result == ParseResult::Success && context.metadata.contains("tcp_result")) {
                        auto tcp_data = std::any_cast<TCPParseResult>(context.metadata["tcp_result"]);
                        g_stats.tcp_packets++;
                        g_stats.tcp_ports[tcp_data.header.src_port]++;
                        g_stats.tcp_ports[tcp_data.header.dst_port]++;
                        
                        info << "TCP\n"
                             << "  Source Port: " << tcp_data.header.src_port << "\n"
                             << "  Destination Port: " << tcp_data.header.dst_port << "\n"
                             << "  Sequence Number: " << tcp_data.header.seq_num << "\n"
                             << "  Acknowledgment Number: " << tcp_data.header.ack_num << "\n"
                             << "  Header Length: " << ((tcp_data.header.data_offset_flags >> 12) & 0x0F) * 4 << " bytes\n"
                             << "  Flags: 0x" << std::hex << std::uppercase << (tcp_data.header.data_offset_flags & 0x3F) << std::dec;
                        
                        // TCP标志详细显示
                        std::vector<std::string> flags;
                        if (tcp_data.header.flags & 0x01) flags.push_back("FIN");
                        if (tcp_data.header.flags & 0x02) flags.push_back("SYN");
                        if (tcp_data.header.flags & 0x04) flags.push_back("RST");
                        if (tcp_data.header.flags & 0x08) flags.push_back("PSH");
                        if (tcp_data.header.flags & 0x10) flags.push_back("ACK");
                        if (tcp_data.header.flags & 0x20) flags.push_back("URG");
                        
                        if (!flags.empty()) {
                            info << " [";
                            for (size_t i = 0; i < flags.size(); ++i) {
                                if (i > 0) info << ",";
                                info << flags[i];
                            }
                            info << "]";
                        }
                        
                        info << "\n  Window Size: " << tcp_data.header.window_size << "\n"
                             << "  Checksum: 0x" << std::hex << std::uppercase << tcp_data.header.checksum << std::dec << "\n"
                             << "  Urgent Pointer: " << tcp_data.header.urgent_ptr << "\n"
                             << "  Connection: " << src_ip << ":" << tcp_data.header.src_port
                             << " -> " << dst_ip << ":" << tcp_data.header.dst_port;
                    }
                }
                break;
            }
            
            case 17: { // UDP
                UDPParser udp_parser;
                if (udp_parser.can_parse(buffer)) {
                    auto result = udp_parser.parse(context);
                    if (result == ParseResult::Success && context.metadata.contains("udp_result")) {
                        auto udp_data = std::any_cast<UDPParseResult>(context.metadata["udp_result"]);
                        g_stats.udp_packets++;
                        g_stats.udp_ports[udp_data.header.src_port]++;
                        g_stats.udp_ports[udp_data.header.dst_port]++;
                        
                        info << "UDP\n"
                             << "  Source Port: " << udp_data.header.src_port << "\n"
                             << "  Destination Port: " << udp_data.header.dst_port << "\n"
                             << "  Length: " << udp_data.header.length << " bytes\n"
                             << "  Checksum: 0x" << std::hex << std::uppercase << udp_data.header.checksum << std::dec << "\n"
                             << "  Connection: " << src_ip << ":" << udp_data.header.src_port
                             << " -> " << dst_ip << ":" << udp_data.header.dst_port;
                    }
                }
                break;
            }
            
            case 132: { // SCTP
                SCTPParser sctp_parser;
                if (sctp_parser.can_parse(buffer)) {
                    auto result = sctp_parser.parse(context);
                    if (result == ParseResult::Success && context.metadata.contains("sctp_result")) {
                        auto sctp_data = std::any_cast<SCTPParseResult>(context.metadata["sctp_result"]);
                        g_stats.sctp_packets++;
                        g_stats.sctp_ports[sctp_data.header.src_port]++;
                        g_stats.sctp_ports[sctp_data.header.dst_port]++;
                        
                        info << "SCTP\n"
                             << "  Source Port: " << sctp_data.header.src_port << "\n"
                             << "  Destination Port: " << sctp_data.header.dst_port << "\n"
                             << "  Verification Tag: 0x" << std::hex << std::uppercase << sctp_data.header.verification_tag << std::dec << "\n"
                             << "  Checksum: 0x" << std::hex << std::uppercase << sctp_data.header.checksum << std::dec << "\n"
                             << "  Connection: " << src_ip << ":" << sctp_data.header.src_port
                             << " -> " << dst_ip << ":" << sctp_data.header.dst_port;
                    }
                }
                break;
            }
            
            case 1: { // ICMP
                ICMPParser icmp_parser;
                if (icmp_parser.can_parse(buffer)) {
                    auto result = icmp_parser.parse(context);
                    if (result == ParseResult::Success && context.metadata.contains("icmp_result")) {
                        auto icmp_data = std::any_cast<ICMPParseResult>(context.metadata["icmp_result"]);
                        g_stats.icmp_packets++;
                        
                        info << "ICMP\n"
                             << "  Type: " << static_cast<int>(icmp_data.header.type) << "\n"
                             << "  Code: " << static_cast<int>(icmp_data.header.code) << "\n"
                             << "  Checksum: 0x" << std::hex << std::uppercase << icmp_data.header.checksum << std::dec << "\n"
                             << "  Identifier: " << icmp_data.header.get_identifier() << "\n"
                             << "  Sequence: " << icmp_data.header.get_sequence() << "\n"
                             << "  Connection: " << src_ip << " -> " << dst_ip;
                    }
                }
                break;
            }
            
            case 58: { // ICMPv6
                ICMPv6Parser icmpv6_parser;
                if (icmpv6_parser.can_parse(buffer)) {
                    auto result = icmpv6_parser.parse(context);
                    if (result == ParseResult::Success && context.metadata.contains("icmpv6_result")) {
                        auto icmpv6_data = std::any_cast<ICMPv6ParseResult>(context.metadata["icmpv6_result"]);
                        g_stats.icmpv6_packets++;
                        
                        info << "ICMPv6\n"
                             << "  Type: " << static_cast<int>(icmpv6_data.header.type) << "\n"
                             << "  Code: " << static_cast<int>(icmpv6_data.header.code) << "\n"
                             << "  Checksum: 0x" << std::hex << std::uppercase << icmpv6_data.header.checksum << std::dec << "\n"
                             << "  Data: 0x" << std::hex << std::uppercase << icmpv6_data.header.data << std::dec << "\n"
                             << "  Connection: " << src_ip << " -> " << dst_ip;
                    }
                }
                break;
            }
            
            default:
                info << "Protocol " << static_cast<int>(protocol) << " " << src_ip << " -> " << dst_ip;
                break;
        }
    } catch (const std::exception& e) {
        info << "Transport parse error: " << e.what();
    }
    
    return info.str();
}

// 解析网络层协议
std::string parse_network_layer(const BufferView& buffer, uint16_t ether_type) {
    std::stringstream info;
    
    try {
        ParseContext context;
        context.buffer = buffer;
        
        if (ether_type == 0x0800) { // IPv4
            IPv4Parser ipv4_parser;
            if (ipv4_parser.can_parse(buffer)) {
                auto result = ipv4_parser.parse(context);
                if (result == ParseResult::Success && context.metadata.contains("ipv4_result")) {
                    auto ipv4_data = std::any_cast<IPv4ParseResult>(context.metadata["ipv4_result"]);
                    g_stats.ipv4_packets++;
                    
                    std::string src_ip = ipv4_utils::format_ipv4_address(ipv4_data.header.src_ip);
                    std::string dst_ip = ipv4_utils::format_ipv4_address(ipv4_data.header.dst_ip);
                    g_stats.ip_addresses[src_ip]++;
                    g_stats.ip_addresses[dst_ip]++;
                    
                    // 显示IPv4详细信息
                    info << "IPv4\n"
                         << "  Version: " << ((ipv4_data.header.version_ihl >> 4) & 0x0F) << "\n"
                         << "  Header Length: " << ((ipv4_data.header.version_ihl & 0x0F) * 4) << " bytes\n"
                         << "  Type of Service: 0x" << std::hex << std::uppercase << static_cast<int>(ipv4_data.header.tos) << std::dec << "\n"
                         << "  Total Length: " << ipv4_data.header.total_length << " bytes\n"
                         << "  Identification: 0x" << std::hex << std::uppercase << ipv4_data.header.identification << std::dec << "\n"
                         << "  Flags: 0x" << std::hex << std::uppercase << ((ipv4_data.header.flags_fragment >> 13) & 0x07) << std::dec << "\n"
                         << "  Fragment Offset: " << ipv4_data.header.get_fragment_offset() << "\n"
                         << "  TTL: " << static_cast<int>(ipv4_data.header.ttl) << "\n"
                         << "  Protocol: " << static_cast<int>(ipv4_data.header.protocol) << "\n"
                         << "  Header Checksum: 0x" << std::hex << std::uppercase << ipv4_data.header.checksum << std::dec << "\n"
                         << "  Source IP: " << src_ip << "\n"
                         << "  Destination IP: " << dst_ip << "\n";
                    
                    // 解析传输层
                    size_t ip_header_len = (ipv4_data.header.version_ihl & 0x0F) * 4;
                    BufferView transport_buffer = buffer.substr(ip_header_len);
                    
                    std::string transport_info = parse_transport_layer(transport_buffer, ipv4_data.header.protocol, src_ip, dst_ip);
                    if (!transport_info.empty()) {
                        info << transport_info;
                    }
                }
            }
        } else if (ether_type == 0x86DD) { // IPv6
            IPv6Parser ipv6_parser;
            if (ipv6_parser.can_parse(buffer)) {
                auto result = ipv6_parser.parse(context);
                if (result == ParseResult::Success && context.metadata.contains("ipv6_result")) {
                    auto ipv6_data = std::any_cast<IPv6ParseResult>(context.metadata["ipv6_result"]);
                    g_stats.ipv6_packets++;
                    
                    std::string src_ip = ipv6_utils::format_address(ipv6_data.src_addr);
                     std::string dst_ip = ipv6_utils::format_address(ipv6_data.dst_addr);
                     g_stats.ip_addresses[src_ip]++;
                     g_stats.ip_addresses[dst_ip]++;
                     
                     // 显示IPv6详细信息
                     info << "IPv6\n"
                          << "  Version: " << static_cast<int>(ipv6_data.get_version()) << "\n"
                          << "  Traffic Class: 0x" << std::hex << std::uppercase << static_cast<int>(ipv6_data.get_traffic_class()) << std::dec << "\n"
                          << "  Flow Label: 0x" << std::hex << std::uppercase << ipv6_data.get_flow_label() << std::dec << "\n"
                          << "  Payload Length: " << ipv6_data.payload_length << " bytes\n"
                          << "  Next Header: " << static_cast<int>(ipv6_data.next_header) << "\n"
                          << "  Hop Limit: " << static_cast<int>(ipv6_data.hop_limit) << "\n"
                          << "  Source IP: " << src_ip << "\n"
                          << "  Destination IP: " << dst_ip << "\n";
                     
                     // 解析传输层
                     BufferView transport_buffer = buffer.substr(ipv6_data.header_length);
                     
                     std::string transport_info = parse_transport_layer(transport_buffer, ipv6_data.next_header, src_ip, dst_ip);
                     if (!transport_info.empty()) {
                         info << transport_info;
                     }
                }
            }
        } else {
            info << "EtherType 0x" << std::hex << std::uppercase << ether_type << std::dec;
        }
    } catch (const std::exception& e) {
        info << "Network parse error: " << e.what();
    }
    
    return info.str();
}

// 主要的数据包分析函数
void analyze_packet(const uint8_t* packet_data, size_t packet_len) {
    g_stats.total_packets++;
    g_stats.total_bytes += packet_len;
    
    std::string packet_info;
    
    try {
        BufferView buffer(packet_data, packet_len);
        ParseContext context;
        context.buffer = buffer;
        
        // 解析以太网层
        EthernetParser eth_parser;
        if (eth_parser.can_parse(buffer)) {
            g_stats.ethernet_packets++;
            
            auto eth_result = eth_parser.parse(context);
            if (eth_result == ParseResult::Success && context.metadata.contains("ethernet_result")) {
                auto eth_data = std::any_cast<EthernetParseResult>(context.metadata["ethernet_result"]);
                
                // 计算以太网头部大小
                size_t eth_header_size = EthernetHeader::SIZE + (eth_data.vlan_tag ? VlanTag::SIZE : 0);
                BufferView network_buffer = buffer.substr(eth_header_size);
                
                // 解析网络层
                packet_info = parse_network_layer(network_buffer, eth_data.header.ether_type);
                
                // 添加以太网头部信息到网络层信息前面
                std::stringstream full_info;
                full_info << "Ethernet\n"
                         << "  Source MAC: " << ethernet_utils::format_mac_address(eth_data.header.src_mac) << "\n"
                         << "  Destination MAC: " << ethernet_utils::format_mac_address(eth_data.header.dst_mac) << "\n"
                         << "  EtherType: 0x" << std::hex << std::uppercase << eth_data.header.ether_type << std::dec;
                
                if (eth_data.vlan_tag) {
                    full_info << "\n  VLAN ID: " << eth_data.vlan_tag->get_vlan_id()
                             << "\n  VLAN Priority: " << eth_data.vlan_tag->get_priority()
                             << "\n  VLAN CFI: " << (eth_data.vlan_tag->get_cfi() ? "1" : "0");
                }
                
                if (!packet_info.empty()) {
                    full_info << "\n" << packet_info;
                } else {
                    full_info << "\n  Unknown Protocol";
                }
                
                packet_info = full_info.str();
            } else {
                // 添加详细的错误信息
                std::stringstream ss;
                ss << "Ethernet parse failed (result=" << static_cast<int>(eth_result) << ")";
                if (!eth_parser.get_error_message().empty()) {
                    ss << " - " << eth_parser.get_error_message();
                }
                packet_info = ss.str();
            }
        } else {
            g_stats.other_packets++;
            packet_info = "Non-Ethernet frame";
        }
        
    } catch (const std::exception& e) {
        g_stats.parse_errors++;
        packet_info = "Parse error: " + std::string(e.what());
    }
    
    // 打印数据包信息
    print_packet_details(g_stats.total_packets, packet_len, packet_info);
    
    // 保存到pcap文件
    if (g_pcap_dumper) {
        struct pcap_pkthdr header;
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()) % 1000000;
        
        header.ts.tv_sec = time_t;
        header.ts.tv_usec = us.count();
        header.caplen = packet_len;
        header.len = packet_len;
        
        pcap_dump(reinterpret_cast<u_char*>(g_pcap_dumper), &header, packet_data);
    }
}

// 数据包回调函数
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet_data) {
    (void)user_data; // 标记参数未使用以避免编译警告
    if (!g_running) {
        return;
    }
    analyze_packet(packet_data, header->caplen);
}

// 打印统计信息
void print_statistics() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - g_stats.start_time);
    
    std::cout << "\n=== 捕获统计信息 ===" << std::endl;
    std::cout << "捕获时间: " << duration.count() << " 秒" << std::endl;
    std::cout << "总数据包: " << g_stats.total_packets << std::endl;
    std::cout << "总字节数: " << g_stats.total_bytes << " bytes" << std::endl;
    std::cout << "平均速率: " << (duration.count() > 0 ? g_stats.total_packets / duration.count() : 0) << " packets/sec" << std::endl;
    
    std::cout << "\n=== 协议分布 ===" << std::endl;
    std::cout << "以太网: " << g_stats.ethernet_packets << std::endl;
    std::cout << "IPv4: " << g_stats.ipv4_packets << std::endl;
    std::cout << "IPv6: " << g_stats.ipv6_packets << std::endl;
    std::cout << "TCP: " << g_stats.tcp_packets << std::endl;
    std::cout << "UDP: " << g_stats.udp_packets << std::endl;
    std::cout << "SCTP: " << g_stats.sctp_packets << std::endl;
    std::cout << "ICMP: " << g_stats.icmp_packets << std::endl;
    std::cout << "ICMPv6: " << g_stats.icmpv6_packets << std::endl;
    std::cout << "其他: " << g_stats.other_packets << std::endl;
    std::cout << "解析错误: " << g_stats.parse_errors << std::endl;
    
    // 显示热门端口
    if (!g_stats.tcp_ports.empty()) {
        std::cout << "\n=== 热门TCP端口 ===" << std::endl;
        std::vector<std::pair<uint16_t, size_t>> tcp_sorted(g_stats.tcp_ports.begin(), g_stats.tcp_ports.end());
        std::sort(tcp_sorted.begin(), tcp_sorted.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(size_t(10), tcp_sorted.size()); ++i) {
            std::cout << "端口 " << tcp_sorted[i].first << ": " << tcp_sorted[i].second << " 次" << std::endl;
        }
    }
    
    if (!g_stats.udp_ports.empty()) {
        std::cout << "\n=== 热门UDP端口 ===" << std::endl;
        std::vector<std::pair<uint16_t, size_t>> udp_sorted(g_stats.udp_ports.begin(), g_stats.udp_ports.end());
        std::sort(udp_sorted.begin(), udp_sorted.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(size_t(10), udp_sorted.size()); ++i) {
            std::cout << "端口 " << udp_sorted[i].first << ": " << udp_sorted[i].second << " 次" << std::endl;
        }
    }
    
    // 显示热门IP地址
    if (!g_stats.ip_addresses.empty()) {
        std::cout << "\n=== 热门IP地址 ===" << std::endl;
        std::vector<std::pair<std::string, size_t>> ip_sorted(g_stats.ip_addresses.begin(), g_stats.ip_addresses.end());
        std::sort(ip_sorted.begin(), ip_sorted.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(size_t(10), ip_sorted.size()); ++i) {
            std::cout << ip_sorted[i].first << ": " << ip_sorted[i].second << " 次" << std::endl;
        }
    }
    
    if (!g_stats.pcap_filename.empty()) {
        std::cout << "\n数据包已保存到: " << g_stats.pcap_filename << std::endl;
    }
}

// 列出可用的网络设备
void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "查找设备失败: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "可用的网络设备:" << std::endl;
    int i = 1;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        std::cout << i++ << ". " << (device->description ? device->description : device->name) << std::endl;
        std::cout << "   设备名: " << device->name << std::endl;
    }
    
    pcap_freealldevs(devices);
}

int main(int argc, char* argv[]) {
    std::cout << "=== 网络流量实时捕获分析器 ===" << std::endl;
    std::cout << "使用协议解析库进行实时流量分析" << std::endl;
    std::cout << "按 Ctrl+C 停止捕获" << std::endl << std::endl;
    
    // 注册信号处理函数
    signal(SIGINT, signal_handler);
    
    if (argc < 2) {
        std::cout << "用法: " << argv[0] << " <设备编号>" << std::endl;
        std::cout << "或者: " << argv[0] << " list" << std::endl << std::endl;
        list_devices();
        return 1;
    }
    
    if (std::string(argv[1]) == "list") {
        list_devices();
        return 0;
    }
    
    // 获取设备列表
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "查找设备失败: " << errbuf << std::endl;
        return 1;
    }
    
    // 选择设备
    int device_num = std::atoi(argv[1]);
    pcap_if_t* selected_device = nullptr;
    int i = 1;
    
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        if (i == device_num) {
            selected_device = device;
            break;
        }
        i++;
    }
    
    if (!selected_device) {
        std::cerr << "无效的设备编号: " << device_num << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }
    
    std::cout << "正在打开设备: " << selected_device->name << std::endl;
    
    // 打开设备
    pcap_t* handle = pcap_open_live(selected_device->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "无法打开设备: " << errbuf << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }
    g_pcap_handle = handle;
    
    // 创建pcap文件用于保存数据包
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream filename;
    filename << "capture_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".pcap";
    g_stats.pcap_filename = filename.str();
    
    g_pcap_dumper = pcap_dump_open(handle, g_stats.pcap_filename.c_str());
    if (!g_pcap_dumper) {
        std::cerr << "无法创建pcap文件: " << pcap_geterr(handle) << std::endl;
    } else {
        std::cout << "数据包将保存到: " << g_stats.pcap_filename << std::endl;
    }
    
    std::cout << "开始捕获数据包..." << std::endl << std::endl;
    
    // 打印表头
    std::cout << "   No.         Time   Length Info" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    
    // 记录开始时间
    g_stats.start_time = std::chrono::steady_clock::now();
    
    // 开始捕获
    pcap_loop(handle, -1, packet_handler, nullptr);
    
    // 清理资源
    if (g_pcap_dumper) {
        pcap_dump_close(g_pcap_dumper);
    }
    pcap_close(handle);
    pcap_freealldevs(devices);
    
    // 打印统计信息
    print_statistics();
    
    return 0;
}