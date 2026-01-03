# 信令协议解析支持

## 已实现的协议

### 1. GTPv2-C (GPRS Tunneling Protocol v2 - Control Plane)
- **标准**: 3GPP TS 29.274
- **用途**: LTE/5G核心网控制面信令
- **支持的消息**:
  - 会话管理: Create/Modify/Delete Session
  - 承载管理: Create/Update/Delete Bearer
  - UE相关: Downlink Data Notification
- **文件**: `gtppv2_parser.hpp/cpp`

### 2. Diameter (AAA协议)
- **标准**: RFC 6733
- **用途**: 认证、授权、计费
- **支持的应用**:
  - NAS, Mobile-IP, SIP
  - Gx, Rx, Cx, Sh接口
- **文件**: `diameter_parser.hpp/cpp`

### 3. S1AP (S1 Application Protocol)
- **标准**: 3GPP TS 36.413
- **用途**: LTE S1接口 (eNodeB ↔ MME)
- **文件**: `s1ap_parser.hpp` (框架)

## 协议支持列表

### 移动核心网 (3GPP)
- ✅ GTPv2-C - 控制面
- ✅ GTP-U - 用户面
- ✅ S1AP - LTE S1接口
- ✅ NGAP - 5G NG接口
- ✅ X2AP/XnAP - 基站间接口

### AAA协议
- ✅ Diameter
- ✅ RADIUS

### SIGTRAN
- ✅ M3UA - MTP3用户适配
- ✅ M2UA - MTP2用户适配

### 传统信令
- ✅ H.323 - 多媒体通信
- ✅ ISUP - ISDN用户部分

## 编译说明

```bash
# 使用Clang编译器
CC=/c/msys64/ucrt64/bin/clang \
CXX=/c/msys64/ucrt64/bin/clang++ \
cmake -B build -G Ninja

cd build && ninja
```

## 使用示例

```cpp
#include "parsers/signaling/gtppv2_parser.hpp"

using namespace protocol_parser::signaling;

GTPv2Parser parser;
ParseContext ctx{buffer};
auto result = parser.parse(ctx);

if (result == ParseResult::Success) {
    auto info = std::any_cast<GTPv2Info>(ctx.metadata["gtpv2_info"]);
    std::cout << info.to_string() << std::endl;
}
```
