#pragma once

#include <cstdint>

namespace protocol_parser::utils {

// 网络字节序转换函数
// 主机字节序到网络字节序
uint16_t htons(uint16_t hostshort);
uint32_t htonl(uint32_t hostlong);

// 网络字节序到主机字节序
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);

// 检查主机字节序
bool is_little_endian();
bool is_big_endian();

} // namespace protocol_parser::utils