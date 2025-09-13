# API参考文档

<cite>
**本文档中引用的文件**  
- [buffer_view.hpp](file://include/core/buffer_view.hpp)
- [base_parser.hpp](file://include/parsers/base_parser.hpp)
- [protocol_detection.hpp](file://include/detection/protocol_detection.hpp)
- [http_parser.hpp](file://include/parsers/application/http_parser.hpp)
- [tcp_parser.hpp](file://include/parsers/transport/tcp_parser.hpp)
- [ipv4_parser.hpp](file://include/parsers/network/ipv4_parser.hpp)
- [ethernet_parser.hpp](file://include/parsers/datalink/ethernet_parser.hpp)
- [traffic_statistics.hpp](file://include/statistics/traffic_statistics.hpp)
- [performance_monitor.hpp](file://include/monitoring/performance_monitor.hpp)
- [network_utils.hpp](file://include/utils/network_utils.hpp)
</cite>

## 目录
1. [简介](#简介)
2. [核心数据视图](#核心数据视图)
3. [协议解析基类](#协议解析基类)
4. [协议检测系统](#协议检测系统)
5. [应用层协议解析器](#应用层协议解析器)
6. [传输层协议解析器](#传输层协议解析器)
7. [网络层协议解析器](#网络层协议解析器)
8. [链路层协议解析器](#链路层协议解析器)
9. [流量统计与性能监控](#流量统计与性能监控)
10. [网络工具辅助函数](#网络工具辅助函数)

## 简介
本API参考文档全面覆盖协议解析器项目中的所有公开C++接口。文档按照Doxygen风格编写，详细描述每个头文件中类、方法、枚举和常量的功能语义、参数类型、返回值、异常行为及使用约束。目标是为开发者提供精确的调用上下文理解，确保在实际使用中能够正确集成和调用相关API。

## 核心数据视图

`BufferView` 类提供对原始网络数据包的安全、非拥有式访问接口。它封装了指针与长度信息，支持高效的子视图切片操作，避免不必要的内存拷贝。

### 构造函数
- `BufferView(const uint8_t* data, size_t length)`  
  构造一个指向指定内存区域的视图。**要求**：`data` 不为空且 `length > 0`。
- `BufferView(const std::vector<uint8_t>& buffer)`  
  从标准容器构造视图，自动获取数据指针与大小。

### 成员方法
- `span<const uint8_t> data() const`  
  返回一个只读span，用于安全访问底层数据。
- `size_t size() const`  
  获取视图长度（字节）。
- `BufferView subview(size_t offset, size_t length) const`  
  创建子视图。**异常**：若 `offset + length > size()` 则抛出 `std::out_of_range`。
- `bool empty() const`  
  判断视图是否为空。

**中文**
- [buffer_view.hpp](file://include/core/buffer_view.hpp#L15-L98)

## 协议解析基类

`BaseParser` 是所有协议解析器的抽象基类，定义统一的解析接口契约。

### 纯虚接口
- `virtual ParseResult parse(const BufferView& packet) = 0`  
  解析输入数据包并返回结果。**后置条件**：返回值指示解析成功与否及解析深度。
- `virtual ProtocolType getProtocol() const = 0`  
  返回该解析器对应的协议类型标识。

### 受保护方法
- `bool validateChecksum(const BufferView& data, uint16_t provided, uint16_t computed)`  
  验证校验和，支持补码比较逻辑。

**中文**
- [base_parser.hpp](file://include/parsers/base_parser.hpp#L12-L76)

## 协议检测系统

`ProtocolDetection` 类负责根据数据包特征动态识别其封装的协议栈。

### 主要方法
- `static DetectionResult detectProtocol(const BufferView& frame)`  
  启动协议检测流程。**调用规则**：输入必须至少包含链路层头部（通常14字节以太网头）。  
  **返回值**：包含检测到的协议链（如 Ethernet → IPv4 → TCP → HTTP）及置信度评分。
- `static bool isPortBasedProtocol(uint16_t port, ProtocolType type)`  
  判断特定端口是否通常用于某协议（如80端口对应HTTP）。

### 协议枚举
```cpp
enum class ProtocolType {
    UNKNOWN,
    ETHERNET,
    ARP,
    IPV4,
    IPV6,
    ICMP,
    TCP,
    UDP,
    HTTP,
    HTTPS,
    DNS,
    DHCP,
    FTP,
    SMTP,
    // ... 其他协议
};
```

**中文**
- [protocol_detection.hpp](file://include/detection/protocol_detection.hpp#L10-L135)

## 应用层协议解析器

应用层解析器继承自 `BaseParser`，实现具体协议语义解析。

### HTTP解析器
- `HttpParser::parse(const BufferView& packet)`  
  解析HTTP请求/响应行、头部字段与可选正文。**约束**：仅支持HTTP/1.1文本格式。  
  **返回**：`HttpMessage` 结构体，含方法、URL、状态码、头字段映射等。
- `bool HttpParser::isHttpRequest(const BufferView& data)`  
  快速判断是否为HTTP请求（基于起始行特征）。

### DNS解析器
- 支持A、AAAA、CNAME、MX等常见查询类型解析。
- `DnsParser::getQueries()` 与 `getAnswers()` 提供结构化访问。

**中文**
- [http_parser.hpp](file://include/parsers/application/http_parser.hpp#L14-L112)
- [dns_parser.hpp](file://include/parsers/application/dns_parser.hpp#L15-L98)

## 传输层协议解析器

### TCP解析器
- `TcpParser::parse(const BufferView& segment)`  
  解析TCP头部字段（端口、序列号、标志位等），支持选项字段解析。
- 提供 `isSyn()`, `isAck()`, `isFin()` 等便捷方法判断标志位状态。
- **异常行为**：头部长度不足或校验和错误时返回 `ParseResult::INVALID`。

### UDP解析器
- `UdpParser::getSourcePort()`, `getDestinationPort()`  
  提取端口号，用于后续应用层协议分发。
- 不强制验证校验和（允许为0）。

**中文**
- [tcp_parser.hpp](file://include/parsers/transport/tcp_parser.hpp#L16-L88)
- [udp_parser.hpp](file://include/parsers/transport/udp_parser.hpp#L15-L72)

## 网络层协议解析器

### IPv4解析器
- `Ipv4Parser::getSourceAddress()`, `getDestinationAddress()`  
  返回点分十进制格式的IP地址字符串。
- 支持TTL、协议字段、分片标志解析。
- 自动处理头部长度可变性（IHL字段）。

### ICMP解析器
- 区分Echo请求/响应、目的不可达等消息类型。
- `getEchoId()` 与 `getEchoSequence()` 用于匹配ping操作。

**中文**
- [ipv4_parser.hpp](file://include/parsers/network/ipv4_parser.hpp#L17-L105)
- [icmp_parser.hpp](file://include/parsers/network/icmp_parser.hpp#L16-L89)

## 链路层协议解析器

### 以太网解析器
- `EthernetParser::parse(const BufferView& frame)`  
  提取源/目的MAC地址与上层协议类型（EtherType）。
- 支持IEEE 802.3与标准以太网帧格式识别。

### ARP解析器
- 解析硬件类型、协议类型、操作码（请求/应答）。
- 提供 `getSenderIp()`, `getTargetMac()` 等访问方法。

**中文**
- [ethernet_parser.hpp](file://include/parsers/datalink/ethernet_parser.hpp#L18-L92)
- [arp_parser.hpp](file://include/parsers/datalink/arp_parser.hpp#L17-L84)

## 流量统计与性能监控

### 流量统计
`TrafficStatistics` 类提供线程安全的计数器集合：
- `void incrementPacketCount(ProtocolType type)`  
  按协议类型递增数据包计数。
- `uint64_t getTotalBytes()`  
  获取累计字节数。
- `std::map<ProtocolType, uint64_t> getProtocolDistribution()`  
  返回当前协议分布快照。

### 性能监控
`PerformanceMonitor` 支持：
- `ScopedTimer timer("parse_http");`  
  RAII风格的代码段计时。
- `void logThroughput(size_t bytes)`  
  记录吞吐量指标，用于速率计算。

**中文**
- [traffic_statistics.hpp](file://include/statistics/traffic_statistics.hpp#L14-L120)
- [performance_monitor.hpp](file://include/monitoring/performance_monitor.hpp#L13-L67)

## 网络工具辅助函数

`NetworkUtils` 命名空间提供通用工具：
- `std::string macToString(const uint8_t* mac)`  
  将6字节MAC地址格式化为 `xx:xx:xx:xx:xx:xx` 字符串。
- `uint16_t checksum(const uint8_t* data, size_t length)`  
  计算Internet校验和（RFC 1071），支持跨字段累加。
- `bool isValidIpv4(const std::string& ip)`  
  验证IP地址字符串格式合法性。

**中文**
- [network_utils.hpp](file://include/utils/network_utils.hpp#L12-L88)