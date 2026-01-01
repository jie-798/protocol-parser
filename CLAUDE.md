# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Configure and build (Release mode)
mkdir build && cd build
cmake ..
cmake --build . --config Release

# Build with specific options
cmake .. -DBUILD_EXAMPLES=ON

# Run examples
./bin/examples/modern_live_capture    # Real-time packet capture with GUI
./bin/examples/wireshark_style_gui   # Alternative GUI implementation
```

**Note**: On Windows, live_capture requires Npcap driver installation and administrator privileges.

## Project Architecture

This is a high-performance C++23 network protocol parser library with zero-copy design and SIMD acceleration.

### Core Design Principles

1. **Zero-Copy Architecture**: All data access uses `BufferView` which provides views into memory without copying
2. **Layered Parsing**: Protocol parsers are organized by OSI layer (datalink, network, transport, application)
3. **State Machine Framework**: All parsers inherit from `BaseParser` with state machine support
4. **SIMD Optimization**: BufferView uses AVX2/SSE2 for accelerated pattern matching
5. **Type Safety**: Strong typing with template methods for endian-aware integer parsing

### Key Components

**BufferView** (`include/core/buffer_view.hpp`)
- Zero-copy buffer with reference counting
- SIMD-accelerated search operations (`find_simd`)
- Type-safe endian-aware parsing: `read_be16/32/64`, `read_le16/32/64`
- Subview creation without data duplication: `substr()`, `prefix()`, `suffix()`

**BaseParser** (`include/parsers/base_parser.hpp`)
- Abstract interface for all protocol parsers
- State machine framework via `StateMachine` struct
- `ParseContext` holds metadata across parser layers using `std::any`
- `ParseResult` enum for status reporting
- Parser registration system with `ParserRegistry`

**Protocol Layering**:
```
Datalink Layer (parsers/datalink/)
  ├── EthernetParser (with VLAN tag support)
  └── ARPParser

Network Layer (parsers/network/)
  ├── IPv4Parser (options, fragmentation)
  ├── IPv6Parser (extension headers)
  ├── ICMPParser
  └── ICMPv6Parser

Transport Layer (parsers/transport/)
  ├── TCPParser (options, state tracking)
  ├── UDPParser
  └── SCTPParser

Application Layer (parsers/application/)
  ├── HTTPParser / HTTPSParser
  ├── DNSParser
  ├── FTPParser
  ├── SSHParser
  ├── MQTTParser
  ├── WebSocketParser
  ├── gRPCParser
  └── ... (SMTP, POP3, Telnet, etc.)

Advanced Features:
  ├── Security (parsers/security/)
  │   ├── TLSDeepInspector (vulnerability detection, cipher analysis)
  │   └── IPSecDeepAnalyzer (ESP/AH, IKE analysis)
  ├── Industrial (parsers/industrial/)
  │   ├── ModbusDeepAnalyzer (TCP/RTU/ASCII)
  │   └── DNP3DeepAnalyzer
  └── AI (ai/protocol_detector.hpp)
      └── Naive Bayes classifier for protocol detection
```

## Parser Implementation Pattern

When implementing new protocol parsers:

1. **Inherit from BaseParser** and implement required methods:
   - `get_protocol_info()`: Return protocol metadata
   - `can_parse()`: Check if buffer contains this protocol
   - `parse()`: Main parsing logic using ParseContext
   - `reset()`: Clear state for reuse

2. **Use ParseContext.metadata** to store results for upper layers:
   ```cpp
   context.metadata["protocol_name"] = ParseResultStruct{...};
   ```

3. **Return appropriate ParseResult values**:
   - `Success`: Parsed completely
   - `NeedMoreData`: Incomplete packet
   - `InvalidFormat`: Protocol violation
   - `BufferTooSmall`: Not enough bytes

4. **Leverage BufferView** for all data access:
   ```cpp
   uint16_t field = buffer.read_be16(offset);
   auto payload = buffer.substr(header_size);
   ```

5. **Chain parsers** by reading next-layer protocol from current results:
   ```cpp
   if (ipv4_result.header.protocol == 6) { // TCP
       TCPParser tcp;
       return tcp.parse(context);
   }
   ```

## Code Style

- **C++23 Standard**: Use modern features (constexpr, concepts, std::span)
- **RAII**: All resources managed automatically
- **[[nodiscard]]**: Applied to functions with important return values
- **Namespace**: `protocol_parser::{core,parsers,ai,monitoring,detection}`
- **Error Handling**: Prefer `ParseResult` enum over exceptions
- **Naming**:
  - Classes: `PascalCase`
  - Functions: `snake_case`
  - Members: `trailing_underscore_`
  - Constants: `kPascalCase`

## Important Technical Details

**SIMD Fallback**: BufferView automatically detects CPU features and uses AVX2 → SSE2 → scalar fallback chain.

**Endian Handling**: Network protocols are big-endian. Always use `read_be*` methods for protocol fields.

**Memory Safety**: BufferView includes bounds checking via `can_read()` and `at()` methods for validation.

**Protocol Metadata**: Store parse results in `ParseContext.metadata` using `std::any` for type-erased inter-layer communication.

**Compiler Optimization**: The build system enables architecture-specific optimizations:
- MSVC: `/arch:AVX2`
- GCC/Clang: `-march=native`
- Targets: `-O3` with LTO support

## Testing

Currently, examples serve as integration tests. Run examples to verify functionality:
- Basic packet parsing
- Real-time capture (requires admin privileges)
- GUI-based inspection

## Common Patterns

**Chained Protocol Parsing**:
```cpp
ParseContext ctx{buffer};
EthernetParser eth;
auto result = eth.parse(ctx);
if (result == ParseResult::Success) {
    IPv4Parser ipv4;
    result = ipv4.parse(ctx);
}
```

**Metadata Access**:
```cpp
if (ctx.metadata.contains("ipv4_result")) {
    auto ipv4 = std::any_cast<IPv4ParseResult>(ctx.metadata["ipv4_result"]);
}
```

**Zero-Copy Payload Extraction**:
```cpp
auto payload = buffer.substr(header_size);
// No data copied - payload points into original buffer
```
