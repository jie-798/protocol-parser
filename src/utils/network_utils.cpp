#include "utils/network_utils.hpp"
#include <cstdint>

namespace protocol_parser::utils {

// 检查字节序的辅助函数
bool is_little_endian() {
    static const uint16_t test = 0x0001;
    return *reinterpret_cast<const uint8_t*>(&test) == 0x01;
}

bool is_big_endian() {
    return !is_little_endian();
}

// 16位字节序转换
uint16_t htons(uint16_t hostshort) {
    if (is_little_endian()) {
        return ((hostshort & 0xFF00) >> 8) | ((hostshort & 0x00FF) << 8);
    }
    return hostshort;
}

uint16_t ntohs(uint16_t netshort) {
    return htons(netshort);  // 网络到主机和主机到网络是相同的操作
}

// 32位字节序转换
uint32_t htonl(uint32_t hostlong) {
    if (is_little_endian()) {
        return ((hostlong & 0xFF000000) >> 24) |
               ((hostlong & 0x00FF0000) >> 8)  |
               ((hostlong & 0x0000FF00) << 8)  |
               ((hostlong & 0x000000FF) << 24);
    }
    return hostlong;
}

uint32_t ntohl(uint32_t netlong) {
    return htonl(netlong);  // 网络到主机和主机到网络是相同的操作
}

} // namespace protocol_parser::utils