# 高性能网络协议解析库

一个基于C++20的高性能网络协议解析库，支持数据链路层、网络层和传输层协议的解析。该库采用零拷贝设计，支持SIMD加速，具有良好的扩展性和性能表现。

## 特性

- **高性能**: 零拷贝设计，SIMD加速，优化的内存访问模式
- **模块化**: 基于状态机的解析器架构，易于扩展新协议
- **类型安全**: 强类型接口，编译时错误检查
- **跨平台**: 支持Windows、Linux、macOS
- **现代C++**: 使用C++20特性，包括概念、模块等
- **完整协议栈**: 支持从数据链路层到传输层的完整协议解析
- **实时捕获**: 集成Npcap支持，可实时捕获和分析网络流量
- **链式解析**: 支持协议栈的自动链式解析，简化使用流程

## 支持的协议

### 数据链路层
- **以太网 (Ethernet)**: IEEE 802.3标准，支持VLAN标签
- **ARP**: 地址解析协议，支持IPv4地址映射

### 网络层
- **IPv4**: 完整的IPv4头解析，包括选项和分片处理
- **IPv6**: 完整的IPv6头解析，支持扩展头处理
- **ICMP**: Internet控制消息协议v4，支持各种ICMP消息类型
- **ICMPv6**: Internet控制消息协议v6，支持邻居发现等功能

### 传输层
- **TCP**: 完整的TCP头解析，包括选项和状态跟踪
- **UDP**: UDP头解析和载荷提取
- **SCTP**: 流控制传输协议，支持多流和多宿主

## 系统要求

- **编译器**: 
  - GCC 10+ (支持C++20)
  - Clang 12+ (支持C++20)
  - MSVC 2019+ (支持C++20)
- **CMake**: 3.15+
- **操作系统**: Windows 10+, Linux (内核4.0+), macOS 10.15+

## 构建说明

### 克隆项目

```bash
git clone <repository-url>
cd protocol_parser
```

### 使用CMake构建

```bash
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake ..

# 编译
cmake --build . --config Release

# 可选：安装
cmake --install .
```

### 构建选项

- `BUILD_EXAMPLES`: 构建示例程序 (默认: ON)
- `BUILD_TESTS`: 构建测试用例 (默认: OFF)
- `INSTALL_EXAMPLES`: 安装示例程序 (默认: OFF)
- `ENABLE_SIMD`: 启用SIMD优化 (默认: ON)

```bash
cmake .. -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON
```

## 快速开始

### 基本用法

```cpp
#include "core/buffer_view.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/ipv4_parser.hpp"
#include "parsers/ipv6_parser.hpp"
#include "parsers/tcp_parser.hpp"
#include "parsers/udp_parser.hpp"
#include "parsers/icmp_parser.hpp"

using namespace protocol_parser;

// 假设你有一个数据包
std::vector<uint8_t> packet_data = { /* 你的数据包数据 */ };

// 创建缓冲区视图
BufferView buffer(packet_data.data(), packet_data.size());
ParseContext context;

size_t offset = 0;

// 解析以太网层
EthernetParser eth_parser;
auto eth_result = eth_parser.parse(buffer.subview(offset), context);

if (eth_result.status == ParseStatus::Complete) {
    offset += eth_result.bytes_consumed;
    
    // 获取以太网解析结果
    if (context.metadata.contains("ethernet_result")) {
        auto eth_data = std::any_cast<EthernetParseResult>(context.metadata["ethernet_result"]);
        std::cout << "以太网: " << eth_parser.get_protocol_info().name << std::endl;
        
        // 根据EtherType选择网络层协议
        if (eth_data.header.ether_type == 0x0800) { // IPv4
            IPv4Parser ipv4_parser;
            auto ipv4_result = ipv4_parser.parse(buffer.subview(offset), context);
            
            if (ipv4_result.status == ParseStatus::Complete) {
                offset += ipv4_result.bytes_consumed;
                auto ipv4_data = std::any_cast<IPv4ParseResult>(context.metadata["ipv4_result"]);
                std::cout << "IPv4: " << ipv4_data.header.source_ip << " -> " << ipv4_data.header.destination_ip << std::endl;
                
                // 解析传输层
                if (ipv4_data.header.protocol == 6) { // TCP
                    TCPParser tcp_parser;
                    auto tcp_result = tcp_parser.parse(buffer.subview(offset), context);
                    if (tcp_result.status == ParseStatus::Complete) {
                        auto tcp_data = std::any_cast<TCPParseResult>(context.metadata["tcp_result"]);
                        std::cout << "TCP: " << tcp_data.header.source_port << " -> " << tcp_data.header.destination_port << std::endl;
                    }
                } else if (ipv4_data.header.protocol == 17) { // UDP
                    UDPParser udp_parser;
                    auto udp_result = udp_parser.parse(buffer.subview(offset), context);
                    if (udp_result.status == ParseStatus::Complete) {
                        auto udp_data = std::any_cast<UDPParseResult>(context.metadata["udp_result"]);
                        std::cout << "UDP: " << udp_data.header.source_port << " -> " << udp_data.header.destination_port << std::endl;
                    }
                } else if (ipv4_data.header.protocol == 1) { // ICMP
                    ICMPParser icmp_parser;
                    auto icmp_result = icmp_parser.parse(buffer.subview(offset), context);
                    if (icmp_result.status == ParseStatus::Complete) {
                        std::cout << "ICMP: 类型 " << static_cast<int>(icmp_result.type) << std::endl;
                    }
                }
            }
        } else if (eth_data.header.ether_type == 0x86DD) { // IPv6
            IPv6Parser ipv6_parser;
            auto ipv6_result = ipv6_parser.parse(buffer.subview(offset), context);
            
            if (ipv6_result.status == ParseStatus::Complete) {
                auto ipv6_data = std::any_cast<IPv6ParseResult>(context.metadata["ipv6_result"]);
                std::cout << "IPv6: " << ipv6_data.header.source_ip << " -> " << ipv6_data.header.destination_ip << std::endl;
                // 继续解析传输层...
            }
        }
    }
}
```

### 链式协议解析

```cpp
#include "parsers/ethernet_parser.hpp"
#include "parsers/ipv4_parser.hpp"
#include "parsers/ipv6_parser.hpp"
#include "parsers/tcp_parser.hpp"
#include "parsers/udp_parser.hpp"
#include "parsers/icmp_parser.hpp"

// 创建解析器链
EthernetParser eth_parser;
IPv4Parser ipv4_parser;
IPv6Parser ipv6_parser;
TCPParser tcp_parser;
UDPParser udp_parser;
ICMPParser icmp_parser;

// 解析以太网帧
auto eth_result = eth_parser.parse(buffer, context);
if (eth_result.status == ParseStatus::Complete) {
    // 根据EtherType选择网络层解析器
    if (context.metadata.contains("ethernet_result")) {
        auto eth_data = std::any_cast<EthernetParseResult>(context.metadata["ethernet_result"]);
        
        if (eth_data.header.ether_type == 0x0800) { // IPv4
            auto ipv4_result = ipv4_parser.parse(buffer.subview(eth_result.bytes_consumed), context);
            // 继续解析传输层...
        } else if (eth_data.header.ether_type == 0x86DD) { // IPv6
            auto ipv6_result = ipv6_parser.parse(buffer.subview(eth_result.bytes_consumed), context);
            // 继续解析传输层...
        }
    }
}
```

## 示例程序

项目包含三个示例程序，展示了库的不同用法：

### 1. 基础解析示例 (`basic_parsing`)

演示基本的数据包解析功能：

```bash
./bin/examples/basic_parsing
```

### 2. 数据包分析器 (`packet_analyzer`)

提供数据包统计和分析功能：

```bash
# 使用内置测试数据
./bin/examples/packet_analyzer

# 分析文件中的数据包
./bin/examples/packet_analyzer packets.txt
```

### 3. 实时数据包捕获 (`live_capture`)

实时捕获和解析网络数据包：

```bash
# 列出可用网络接口
./bin/examples/live_capture

# 在指定接口上捕获数据包（Windows需要管理员权限）
./bin/examples/live_capture <interface_number>
```

**注意**: 在Windows上运行需要安装Npcap驱动并以管理员权限运行。

## API 参考

### 核心类

#### BufferView

零拷贝缓冲区视图，提供高效的数据访问：

```cpp
class BufferView {
public:
    // 构造函数
    BufferView(const uint8_t* data, size_t size);
    
    // 基本访问
    uint8_t operator[](size_t index) const;
    size_t size() const;
    const uint8_t* data() const;
    
    // 子视图
    BufferView subview(size_t offset, size_t length = SIZE_MAX) const;
    
    // 类型安全读取
    uint16_t read_be16(size_t offset) const;  // 大端序16位
    uint32_t read_be32(size_t offset) const;  // 大端序32位
    uint16_t read_le16(size_t offset) const;  // 小端序16位
    uint32_t read_le32(size_t offset) const;  // 小端序32位
    
    // SIMD加速查找
    size_t find_byte(uint8_t byte, size_t start_pos = 0) const;
    size_t find_pattern(const uint8_t* pattern, size_t pattern_size, size_t start_pos = 0) const;
};
```

#### BaseParser

所有协议解析器的基类：

```cpp
class BaseParser {
public:
    virtual ~BaseParser() = default;
    
    // 解析接口
    virtual ParseResult parse(const BufferView& buffer, ParseContext& context) = 0;
    
    // 信息接口
    virtual std::string getInfo() const = 0;
    virtual void reset() = 0;
    
    // 协议信息
    const ProtocolInfo& getProtocolInfo() const;
};
```

### 解析结果

```cpp
enum class ParseStatus {
    Pending,           // 等待解析
    InProgress,        // 解析进行中
    Complete,          // 解析完成
    NeedMoreData,      // 需要更多数据
    ParseError,        // 解析错误
    ChecksumError,     // 校验和错误
    InvalidState       // 无效状态
};

struct ParseResult {
    ParseStatus status;        // 解析状态
    size_t bytes_consumed;     // 消耗的字节数
    std::any data;            // 解析结果数据（可选）
};

struct ParseContext {
    std::unordered_map<std::string, std::any> metadata;  // 解析结果存储
    size_t offset = 0;                                   // 当前偏移量
    bool debug_mode = false;                             // 调试模式
};
```

## 性能优化

### SIMD 加速

库自动检测CPU特性并使用相应的SIMD指令：

- **AVX2**: 256位向量操作
- **SSE2**: 128位向量操作
- **标量**: 回退到标量实现

### 内存管理

- **零拷贝**: BufferView不复制数据，只维护指针和大小
- **引用计数**: 自动管理缓冲区生命周期
- **内存对齐**: 优化的内存访问模式

### 编译器优化

推荐的编译选项：

```bash
# GCC/Clang
-O3 -march=native -DNDEBUG

# MSVC
/O2 /arch:AVX2 /DNDEBUG
```

## 扩展新协议

### 1. 创建解析器类

```cpp
#include "parsers/base_parser.hpp"

class MyProtocolParser : public BaseParser {
public:
    MyProtocolParser();
    
    ParseResult parse(const BufferView& buffer, ParseContext& context) override;
    std::string getInfo() const override;
    void reset() override;
    
private:
    // 协议特定的状态和数据
};
```

### 2. 实现解析逻辑

```cpp
ParseResult MyProtocolParser::parse(const BufferView& buffer, ParseContext& context) {
    // 检查缓冲区大小
    if (buffer.size() < MIN_HEADER_SIZE) {
        return {ParseStatus::NEED_MORE_DATA, 0, {}};
    }
    
    // 解析协议头
    // ...
    
    // 返回结果
    return {ParseStatus::SUCCESS, bytes_consumed, result_data};
}
```

### 3. 注册解析器

```cpp
// 创建工厂类
class MyProtocolParserFactory : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create() const override {
        return std::make_unique<MyProtocolParser>();
    }
    
    std::string getProtocolName() const override {
        return "MyProtocol";
    }
    
    std::vector<std::string> getSupportedTypes() const override {
        return {"myprotocol", "MyProtocol", "42"}; // 协议名称和编号
    }
};

// 注册到全局注册表
static bool registered = []() {
    ParserRegistry::getInstance().registerFactory(
        std::make_unique<MyProtocolParserFactory>()
    );
    return true;
}();
```

## 故障排除

### 常见问题

1. **编译错误**: 确保使用支持C++20的编译器
2. **链接错误**: 检查库文件路径和依赖项
3. **运行时错误**: 验证输入数据的有效性

### 调试技巧

```cpp
// 启用详细日志
context.debug_mode = true;

// 检查解析状态
if (result.status != ParseStatus::Complete) {
    std::cerr << "解析失败: " << static_cast<int>(result.status) << std::endl;
    
    switch (result.status) {
        case ParseStatus::NeedMoreData:
            std::cerr << "需要更多数据" << std::endl;
            break;
        case ParseStatus::ParseError:
            std::cerr << "解析错误" << std::endl;
            break;
        case ParseStatus::ChecksumError:
            std::cerr << "校验和错误" << std::endl;
            break;
        default:
            std::cerr << "未知错误" << std::endl;
    }
}

// 打印十六进制数据
void print_hex(const BufferView& buffer) {
    for (size_t i = 0; i < buffer.size(); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << static_cast<int>(buffer[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;
}

// 检查解析结果
void check_parse_results(const ParseContext& context) {
    std::cout << "解析结果:" << std::endl;
    for (const auto& [key, value] : context.metadata) {
        std::cout << "  " << key << ": 已解析" << std::endl;
    }
}
```

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 代码规范

- 使用现代C++特性
- 遵循RAII原则
- 添加适当的注释和文档
- 编写单元测试

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。


## 更新日志

### v1.2.0 (最新)
- ✅ **新增协议支持**: 实现IPv6、ICMP、ICMPv6、SCTP协议解析器
- ✅ **修复状态机**: 解决传输层解析器元数据存储问题
- ✅ **完善ARP**: 实现ARP协议解析器（开发中）
- ✅ **实时捕获**: 集成Npcap支持，提供live_capture示例
- ✅ **链式解析**: 优化协议栈解析流程，支持自动协议识别
- ✅ **代码优化**: 统一代码风格，添加[[nodiscard]]属性

### v1.1.0
- ✅ **基础协议**: 实现以太网、IPv4、TCP、UDP解析器
- ✅ **核心架构**: 建立基于状态机的解析器框架
- ✅ **零拷贝**: 实现BufferView零拷贝缓冲区
- ✅ **跨平台**: 支持Windows、Linux、macOS构建

### v1.0.0
- ✅ **项目初始化**: 建立CMake构建系统
- ✅ **基础设计**: 定义协议解析器接口和架构

## 致谢

感谢所有贡献者和以下开源项目的启发：

- [libpcap](https://www.tcpdump.org/) - 网络数据包捕获库
- [Wireshark](https://www.wireshark.org/) - 网络协议分析器
- [dpdk](https://www.dpdk.org/) - 数据平面开发套件
- [Npcap](https://npcap.com/) - Windows数据包捕获库