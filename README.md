# 高性能网络协议解析库

一个基于 C++23 的网络协议解析库。项目采用零拷贝 `BufferView`、分层解析器接口和可扩展的解析器注册表，目标是支持从链路层到应用层的协议识别与解析。

## 特性

- 零拷贝缓冲区视图：通过 `BufferView` 创建子视图，不复制原始数据。
- 类型安全读取：提供 `read_be16/32/64`、`read_le16/32/64` 等 endian-aware 读取接口。
- 分层解析器：解析器继承 `BaseParser`，通过 `ParseContext` 传递偏移和元数据。
- SIMD 查找：`BufferView::find_simd()` 在可用时使用 AVX2/SSE2，并回退到标量实现。
- CMake 构建：核心库、可选测试目标和安装规则由 CMake 管理。

## 当前协议覆盖

核心构建包含以下主要模块：

- 数据链路层：Ethernet、ARP
- 网络层：IPv4、IPv6、ICMP、ICMPv6
- 传输层：TCP、UDP、SCTP、RTP、QUIC
- 应用层：HTTP、HTTPS、FTP、SSH、DNS、POP3、Telnet、SNMP、DHCP、WebSocket、SIP、MQTT
- 工业协议：Modbus、DNP3
- 信令协议：GTPv2、Diameter、M3UA、S1AP、NGAP、X2AP、H.323、RADIUS
- 检测与统计：协议检测器、AI 协议检测器、流量统计模块

安全深度分析和部分实验性解析器仍在完善中，未全部纳入默认核心构建。

## 系统要求

- CMake 3.20+
- 支持 C++23 的编译器
  - GCC 13+ 推荐
  - Clang 16+ 推荐
  - MSVC 2022 推荐
- Windows 实时捕获功能需要额外安装 Npcap 并使用管理员权限；核心库本身不依赖 Npcap。

## 构建

```bash
cmake -S . -B build
cmake --build build --config Release
```

### 构建选项

- `BUILD_EXAMPLES`：构建示例程序，默认 `OFF`。当前 `examples` 目录只保留 CMake 占位配置。
- `BUILD_TESTS`：构建测试程序，默认 `OFF`。

运行测试：

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

## 快速开始

```cpp
#include "core/buffer_view.hpp"
#include "parsers/base_parser.hpp"
#include "parsers/datalink/ethernet_parser.hpp"
#include "parsers/network/ipv4_parser.hpp"
#include "parsers/transport/tcp_parser.hpp"

#include <any>
#include <vector>

using protocol_parser::core::BufferView;
using namespace protocol_parser::parsers;

std::vector<uint8_t> packet = {/* raw packet bytes */};
BufferView buffer(packet.data(), packet.size());
ParseContext context{buffer};

EthernetParser ethernet;
if (ethernet.parse(context) == ParseResult::Success) {
    auto eth = std::any_cast<EthernetParseResult>(context.metadata.at("ethernet_result"));

    if (eth.next_protocol == EtherType::IPv4) {
        ParseContext ipv4_context{eth.payload};
        IPv4Parser ipv4;

        if (ipv4.parse(ipv4_context) == ParseResult::Success) {
            auto ip = std::any_cast<IPv4ParseResult>(ipv4_context.metadata.at("ipv4_result"));

            if (ip.header.protocol == IPProtocol::TCP) {
                ParseContext tcp_context{ip.payload};
                TCPParser tcp;
                tcp.parse(tcp_context);
            }
        }
    }
}
```

## 核心 API

### `BufferView`

```cpp
BufferView view(data, size);
view.size();
view.data();
view.substr(offset, count);
view.prefix(count);
view.suffix(count);
view.can_read(count, offset);
view.read_be16(offset);
view.read_be32(offset);
view.read_le16(offset);
view.find_simd(byte);
```

### `BaseParser`

```cpp
class BaseParser {
public:
    virtual ~BaseParser() = default;
    virtual const ProtocolInfo& get_protocol_info() const noexcept = 0;
    virtual bool can_parse(const BufferView& buffer) const noexcept = 0;
    virtual ParseResult parse(ParseContext& context) noexcept = 0;
    virtual void reset() noexcept = 0;
};
```

### `ParseResult`

```cpp
enum class ParseResult {
    Success,
    NeedMoreData,
    InvalidFormat,
    UnsupportedVersion,
    BufferTooSmall,
    InternalError
};
```

### `ParseContext`

```cpp
struct ParseContext {
    BufferView buffer;
    size_t offset = 0;
    ParserState state = ParserState::Initial;
    std::unordered_map<std::string, std::any> metadata;
};
```

解析器会把结果写入 `metadata`，例如 `ethernet_result`、`ipv4_result`、`tcp_result`、`udp_result`、`arp_result`、`icmp_result`、`icmpv6_result`。

## 扩展新协议

新增解析器时建议遵循现有模式：

1. 继承 `BaseParser`。
2. 实现 `get_protocol_info()`、`can_parse()`、`parse()`、`reset()`。
3. 使用 `BufferView` 做边界检查和 endian-aware 读取。
4. 成功后把解析结果写入 `ParseContext::metadata`。
5. 如需注册到全局工厂，提供 `ParserFactory` 并使用 `REGISTER_PARSER(type, FactoryClass)`。

## 当前限制

- 部分协议解析器仍是简化实现，校验和、重组、压缩、证书和安全分析能力并不完整。
- `examples` 目录目前没有实际示例源文件。
- 需要在目标平台实际运行 CMake/编译器验证构建矩阵。

## 贡献

欢迎补充协议解析、测试样例和跨平台构建验证。提交前建议运行：

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```
