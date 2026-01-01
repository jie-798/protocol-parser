#include "utils/simd_utils.hpp"
#include <algorithm>

namespace protocol_parser::utils {

// ============================================================================
// 静态成员初始化
// ============================================================================

uint32_t SIMDUtils::crc32_table_[256] = {0};
bool SIMDUtils::crc32_table_initialized_ = false;

// ============================================================================
// CRC32 实现
// ============================================================================

void SIMDUtils::init_crc32_table() {
    // 标准 CRC32 多项式 (IEEE 802.3)
    constexpr uint32_t polynomial = 0xEDB88320;

    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        crc32_table_[i] = crc;
    }

    crc32_table_initialized_ = true;
}

uint32_t SIMDUtils::crc32(const uint8_t* data, size_t size) {
#ifdef _MSC_VER
    // MSVC：使用 SSE4.2 硬件指令
    uint32_t crc = 0;
    const uint8_t* ptr = data;
    size_t remaining = size;

    // 处理对齐的 64 位块
    while (remaining >= 8) {
        uint64_t value;
        std::memcpy(&value, ptr, 8);
        crc = _mm_crc32_u64(crc, value);
        ptr += 8;
        remaining -= 8;
    }

    // 处理剩余的 32 位块
    if (remaining >= 4) {
        uint32_t value;
        std::memcpy(&value, ptr, 4);
        crc = _mm_crc32_u32(crc, value);
        ptr += 4;
        remaining -= 4;
    }

    // 处理剩余的 16 位块
    if (remaining >= 2) {
        uint16_t value;
        std::memcpy(&value, ptr, 2);
        crc = _mm_crc32_u16(crc, value);
        ptr += 2;
        remaining -= 2;
    }

    // 处理最后一个字节
    if (remaining >= 1) {
        crc = _mm_crc32_u8(crc, *ptr);
    }

    return crc;
#else
    // GCC/Clang：使用内置函数
    uint32_t crc = 0;
    const uint8_t* ptr = data;
    size_t remaining = size;

    while (remaining >= 8) {
        uint64_t value;
        std::memcpy(&value, ptr, 8);
        crc = __builtin_ia32_crc32di(crc, value);
        ptr += 8;
        remaining -= 8;
    }

    if (remaining >= 4) {
        uint32_t value;
        std::memcpy(&value, ptr, 4);
        crc = __builtin_ia32_crc32si(crc, value);
        ptr += 4;
        remaining -= 4;
    }

    if (remaining >= 2) {
        uint16_t value;
        std::memcpy(&value, ptr, 2);
        crc = __builtin_ia32_crc32hi(crc, value);
        ptr += 2;
        remaining -= 2;
    }

    if (remaining >= 1) {
        crc = __builtin_ia32_crc32qi(crc, *ptr);
    }

    return crc;
#endif
}

uint32_t SIMDUtils::crc32c(const uint8_t* data, size_t size) {
    // CRC32C (Castagnoli) 多项式
    // 注意：需要 SSE4.2 的 CRC32C 指令支持
#ifdef _MSC_VER
    uint32_t crc = 0;
    const uint8_t* ptr = data;
    size_t remaining = size;

    // 使用 ISO3309 多项式的指令
    while (remaining >= 8) {
        uint64_t value;
        std::memcpy(&value, ptr, 8);
        crc = _mm_crc32_u64(crc, value);
        ptr += 8;
        remaining -= 8;
    }

    // ... 处理剩余字节（类似 crc32）

    return crc;
#else
    // 对于不支持的硬件，回退到软件实现
    return crc32_software(data, size);
#endif
}

uint32_t SIMDUtils::crc32_append(uint32_t previous_crc,
                                const uint8_t* data,
                                size_t size) {
    // 流式计算 CRC32
    return crc32(data, size) ^ previous_crc;
}

uint32_t SIMDUtils::crc32_software(const uint8_t* data, size_t size) {
    if (!crc32_table_initialized_) {
        init_crc32_table();
    }

    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < size; ++i) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table_[index];
    }

    return ~crc;
}

// ============================================================================
// 模式匹配实现
// ============================================================================

size_t SIMDUtils::find_pattern_avx2(const uint8_t* data,
                                   size_t data_size,
                                   const uint8_t* pattern,
                                   size_t pattern_size) {
    if (pattern_size == 0 || pattern_size > data_size) {
        return SIZE_MAX;
    }

    if (pattern_size == 1) {
        // 单字节模式
        uint8_t byte = pattern[0];

        // 创建填充向量
        __m256i pattern_vec = _mm256_set1_epi8(byte);

        size_t i = 0;

        // AVX2 搜索（32 字节块）
        while (i + 32 <= data_size) {
            __m256i data_vec = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(data + i)
            );

            __m256i cmp = _mm256_cmpeq_epi8(data_vec, pattern_vec);
            int mask = _mm256_movemask_epi8(cmp);

            if (mask != 0) {
                // 找到匹配，确定具体位置
                unsigned int index = 0;
                _BitScanForward(&index, mask);
                return i + index;
            }

            i += 32;
        }

        // 剩余字节使用标量搜索
        for (; i < data_size; ++i) {
            if (data[i] == byte) {
                return i;
            }
        }

        return SIZE_MAX;
    }

    // 多字节模式：使用两步搜索
    // 1. 快速搜索第一个字节
    // 2. 在匹配位置验证完整模式

    uint8_t first_byte = pattern[0];
    __m256i first_byte_vec = _mm256_set1_epi8(first_byte);

    size_t i = 0;

    while (i + pattern_size <= data_size) {
        // AVX2 搜索第一个字节
        while (i + 32 <= data_size) {
            __m256i data_vec = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(data + i)
            );

            __m256i cmp = _mm256_cmpeq_epi8(data_vec, first_byte_vec);
            int mask = _mm256_movemask_epi8(cmp);

            if (mask != 0) {
                // 找到第一个字节的候选位置
                unsigned int index = 0;
                _BitScanForward(&index, mask);
                size_t candidate = i + index;

                // 验证完整模式
                if (candidate + pattern_size <= data_size) {
                    if (std::memcmp(data + candidate, pattern, pattern_size) == 0) {
                        return candidate;
                    }
                }

                // 跳过已检查的部分
                i = candidate + 1;
                break;
            }

            i += 32;
        }

        // 没有找到，继续
        if (i + 32 > data_size) {
            // 剩余部分使用标量搜索
            for (; i + pattern_size <= data_size; ++i) {
                if (data[i] == first_byte &&
                    std::memcmp(data + i, pattern, pattern_size) == 0) {
                    return i;
                }
            }
            break;
        }
    }

    return SIZE_MAX;
}

size_t SIMDUtils::find_pattern_sse42(const uint8_t* data,
                                    size_t data_size,
                                    const uint8_t* pattern,
                                    size_t pattern_size) {
    // SSE4.2 版本（类似 AVX2，但使用 16 字节块）
    if (pattern_size == 0 || pattern_size > data_size) {
        return SIZE_MAX;
    }

    if (pattern_size == 1) {
        uint8_t byte = pattern[0];
        __m128i pattern_vec = _mm_set1_epi8(byte);

        size_t i = 0;

        while (i + 16 <= data_size) {
            __m128i data_vec = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(data + i)
            );

            __m128i cmp = _mm_cmpeq_epi8(data_vec, pattern_vec);
            int mask = _mm_movemask_epi8(cmp);

            if (mask != 0) {
                unsigned int index = 0;
                _BitScanForward(&index, mask);
                return i + index;
            }

            i += 16;
        }

        for (; i < data_size; ++i) {
            if (data[i] == byte) {
                return i;
            }
        }

        return SIZE_MAX;
    }

    // 多字节模式
    uint8_t first_byte = pattern[0];
    __m128i first_byte_vec = _mm_set1_epi8(first_byte);

    size_t i = 0;

    while (i + pattern_size <= data_size) {
        while (i + 16 <= data_size) {
            __m128i data_vec = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(data + i)
            );

            __m128i cmp = _mm_cmpeq_epi8(data_vec, first_byte_vec);
            int mask = _mm_movemask_epi8(cmp);

            if (mask != 0) {
                unsigned int index = 0;
                _BitScanForward(&index, mask);
                size_t candidate = i + index;

                if (candidate + pattern_size <= data_size) {
                    if (std::memcmp(data + candidate, pattern, pattern_size) == 0) {
                        return candidate;
                    }
                }

                i = candidate + 1;
                break;
            }

            i += 16;
        }

        if (i + 16 > data_size) {
            for (; i + pattern_size <= data_size; ++i) {
                if (data[i] == first_byte &&
                    std::memcmp(data + i, pattern, pattern_size) == 0) {
                    return i;
                }
            }
            break;
        }
    }

    return SIZE_MAX;
}

size_t SIMDUtils::find_multi_pattern_avx2(const uint8_t* data,
                                         size_t data_size,
                                         const uint8_t** patterns,
                                         const size_t* pattern_sizes,
                                         size_t num_patterns,
                                         size_t* found_pattern) {
    // 多模式搜索（简化版：循环搜索每个模式）
    // TODO: 可以使用 Aho-Corasick 算法 + SIMD 优化

    for (size_t pat_idx = 0; pat_idx < num_patterns; ++pat_idx) {
        size_t pos = find_pattern_avx2(data, data_size,
                                      patterns[pat_idx],
                                      pattern_sizes[pat_idx]);
        if (pos != SIZE_MAX) {
            if (found_pattern) {
                *found_pattern = pat_idx;
            }
            return pos;
        }
    }

    return SIZE_MAX;
}

} // namespace protocol_parser::utils
