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
- [mqtt_parser.hpp](file://include/parsers/application/mqtt_parser.hpp) - *新增于提交 5c71c0a*
- [websocket_parser.hpp](file://include/parsers/application/websocket_parser.hpp) - *新增于提交 5c71c0a*
- [grpc_parser.hpp](file://include/parsers/application/grpc_parser.hpp) - *新增于提交 5c71c0a*
- [tls_deep_inspector.hpp](file://include/parsers/security/tls_deep_inspector.hpp) - *新增于提交 03162cc*
</cite>

## 更新摘要
**已更改内容**  
- 在“应用层协议解析器”部分新增了MQTT、WebSocket和gRPC协议解析器的详细文档
- 新增“安全协议深度检测”章节，涵盖TLS深度检测器API
- 更新了文档引用文件列表，包含所有新增头文件
- 所有内容已完全转换为中文

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
11. [安全协议深度检测](#安全协议深度检测)

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

### MQTT解析器
MQTT解析器实现MQTT协议的完整解析功能，支持v3.1、v3.1.1和v5.0版本。

#### 主要特性
- 支持所有MQTT消息类型（CONNECT、PUBLISH、SUBSCRIBE等）
- 完整的属性解析（MQTT 5.0）
- QoS等级处理
- 遗嘱消息检测
- 安全性分析

#### 核心方法
- `ParseResult parse(ParseContext& context)`  
  解析MQTT数据包并填充解析结果。**返回**：解析状态码。
- `const MQTTPacket& get_mqtt_packet() const`  
  获取解析后的MQTT数据包结构。
- `MQTTAnalysis analyze_packet() const`  
  执行高级分析，返回连接特征、安全问题等信息。
- `bool is_mqtt_packet() const`  
  检查是否成功解析为有效MQTT包。

#### 常量
- `static constexpr uint16_t MQTT_DEFAULT_PORT = 1883`  
  标准MQTT端口
- `static constexpr uint16_t MQTT_TLS_PORT = 8883`  
  MQTT over TLS端口
- `static constexpr uint16_t MQTT_WS_PORT = 80`  
  MQTT over WebSocket端口
- `static constexpr uint16_t MQTT_WSS_PORT = 443`  
  MQTT over WSS端口

**中文**
- [http_parser.hpp](file://include/parsers/application/http_parser.hpp#L14-L112)
- [dns_parser.hpp](file://include/parsers/application/dns_parser.hpp#L15-L98)
- [mqtt_parser.hpp](file://include/parsers/application/mqtt_parser.hpp#L16-L678)

### WebSocket解析器
WebSocket解析器实现WebSocket协议的完整解析，包括握手和帧处理。

#### 核心功能
- WebSocket握手解析（HTTP升级）
- 帧格式解析（RFC 6455）
- 掩码处理
- 分片消息重组
- 控制帧处理（Ping/Pong/Close）

#### 主要方法
- `ParseResult parse_handshake(const BufferView& buffer, WebSocketHandshake& handshake)`  
  解析WebSocket握手请求，提取关键信息如子协议、扩展等。
- `ParseResult parse_frame(const BufferView& buffer, WebSocketFrame& frame)`  
  解析WebSocket帧，处理FIN、掩码、载荷长度等字段。
- `bool is_websocket_handshake(const BufferView& buffer) const`  
  检测数据是否为WebSocket握手。
- `std::string calculate_accept_key(const std::string& key) const`  
  根据WebSocket-Key计算WebSocket-Accept值。

#### 关键结构
- `WebSocketHandshake`：包含方法、URI、头部、子协议等握手信息
- `WebSocketFrame`：包含帧头、载荷、操作码等帧信息
- `WebSocketMessage`：整合握手和帧的完整消息

**中文**
- [websocket_parser.hpp](file://include/parsers/application/websocket_parser.hpp#L15-L664)

### gRPC解析器
gRPC解析器实现基于HTTP/2的gRPC协议解析。

#### 核心功能
- HTTP/2帧解析
- gRPC消息格式解析
- 头部压缩(HPACK)检测
- 流控制分析
- 压缩算法检测

#### 主要方法
- `ParseResult parse_http2_frame(const BufferView& buffer, GRPCMessage& message)`  
  解析HTTP/2帧，识别DATA、HEADERS等帧类型。
- `ParseResult parse_grpc_message(const BufferView& buffer, GRPCMessage& message)`  
  解析gRPC消息前缀，提取压缩标志和消息长度。
- `bool is_grpc_traffic(const BufferView& buffer) const`  
  检测流量是否为gRPC（基于内容类型和协议特征）。
- `bool extract_service_method(const std::string& path, std::string& service, std::string& method)`  
  从路径中提取服务名和方法名。

#### 关键结构
- `GRPCMessage`：包含帧头、消息头、调用信息和载荷
- `GRPCCall`：跟踪完整的RPC调用，包括请求/响应
- `GRPCMetrics`：收集调用统计、延迟、成功率等指标

**中文**
- [grpc_parser.hpp](file://include/parsers/application/grpc_parser.hpp#L15-L376)

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

## 安全协议深度检测

`TLSDeepInspector` 类提供TLS协议的深度分析和安全检测功能。

### 核心功能
- TLS握手过程完整解析
- 证书链验证与分析
- 密码套件安全性评估
- 已知漏洞检测（Heartbleed、POODLE等）
- 安全配置审计

### 主要方法
- `bool parse_tls_packet(const BufferView& buffer, TLSInfo& tls_info)`  
  解析TLS数据包并填充详细信息结构。**返回**：解析是否成功。
- `TLSSecurityAnalysis analyze_security(const TLSInfo& info) const`  
  执行全面安全分析，识别配置弱点和潜在风险。
- `uint32_t calculate_security_score(const TLSInfo& info) const`  
  计算0-100的安全评分。
- `std::string determine_security_grade(uint32_t score) const`  
  根据评分确定安全等级（A+, A, B, C, D, F）。

### 关键结构
- `TLSInfo`：包含版本、记录类型、握手信息、证书链等完整TLS信息
- `TLSSecurityAnalysis`：包含漏洞、警告、建议和安全评分
- `TLSCertificate`：表示X.509证书的详细信息和验证状态
- `TLSSession`：跟踪TLS会话参数和生命周期

### 漏洞检测
支持检测以下常见TLS漏洞：
- Heartbleed
- POODLE
- BEAST
- CRIME
- FREAK
- Logjam

### 配置检查
- 完美前向保密(PFS)检测
- 安全重协商检查
- SNI启用状态
- OCSP装订支持
- 弱协议版本检测

**中文**
- [tls_deep_inspector.hpp](file://include/parsers/security/tls_deep_inspector.hpp#L15-L431)