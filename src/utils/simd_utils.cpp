#include "utils/simd_utils.hpp"
#include <algorithm>
#include <array>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace protocol_parser::utils {

// 跨平台位扫描函数
namespace {
    constexpr std::array<uint32_t, 256> make_crc_table(uint32_t polynomial) noexcept {
        std::array<uint32_t, 256> table{};
        for (uint32_t i = 0; i < table.size(); ++i) {
            uint32_t crc = i;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1) ? (crc >> 1) ^ polynomial : crc >> 1;
            }
            table[i] = crc;
        }
        return table;
    }

    const std::array<uint32_t, 256>& crc32_table() noexcept {
        static const auto table = make_crc_table(0xEDB88320);
        return table;
    }

    const std::array<uint32_t, 256>& crc32c_table() noexcept {
        static const auto table = make_crc_table(0x82F63B78);
        return table;
    }

    uint32_t crc_update(uint32_t previous_crc,
                        const uint8_t* data,
                        size_t size,
                        const std::array<uint32_t, 256>& table) noexcept {
        if (data == nullptr && size != 0) {
            return previous_crc;
        }

        uint32_t crc = ~previous_crc;
        for (size_t i = 0; i < size; ++i) {
            const uint8_t index = static_cast<uint8_t>((crc ^ data[i]) & 0xFF);
            crc = (crc >> 8) ^ table[index];
        }
        return ~crc;
    }

    size_t find_pattern_scalar(const uint8_t* data,
                               size_t data_size,
                               const uint8_t* pattern,
                               size_t pattern_size) noexcept {
        if (pattern_size == 0 || pattern_size > data_size) {
            return SIZE_MAX;
        }

        for (size_t i = 0; i + pattern_size <= data_size; ++i) {
            if (std::memcmp(data + i, pattern, pattern_size) == 0) {
                return i;
            }
        }

        return SIZE_MAX;
    }

    // 查找最低位的 1 的位置（从 0 开始）
    inline unsigned int find_first_set(uint32_t value) {
        if (value == 0) return 32;

        #ifdef _MSC_VER
            unsigned long index = 0;
            _BitScanForward(&index, value);
            return static_cast<unsigned int>(index);
        #else
            // GCC/Clang 内置函数
            return static_cast<unsigned int>(__builtin_ctz(value));
        #endif
    }

    // 对于 64 位值
    inline unsigned int find_first_set(uint64_t value) {
        if (value == 0) return 64;

        #ifdef _MSC_VER
            unsigned long index = 0;
            #ifdef _WIN64
                _BitScanForward64(&index, value);
            #else
                if (static_cast<uint32_t>(value) != 0) {
                    _BitScanForward(&index, static_cast<uint32_t>(value));
                } else {
                    _BitScanForward(&index, static_cast<uint32_t>(value >> 32));
                    index += 32;
                }
            #endif
            return static_cast<unsigned int>(index);
        #else
            return static_cast<unsigned int>(__builtin_ctzll(value));
        #endif
    }
}

// ============================================================================
// CRC32 实现
// ============================================================================

uint32_t SIMDUtils::crc32(const uint8_t* data, size_t size) {
    return crc32_software(data, size);
}

uint32_t SIMDUtils::crc32c(const uint8_t* data, size_t size) {
    return crc32c_software(data, size);
}

uint32_t SIMDUtils::crc32_append(uint32_t previous_crc,
                                const uint8_t* data,
                                size_t size) {
    return crc_update(previous_crc, data, size, crc32_table());
}

uint32_t SIMDUtils::crc32_software(const uint8_t* data, size_t size) {
    return crc_update(0, data, size, crc32_table());
}

uint32_t SIMDUtils::crc32c_software(const uint8_t* data, size_t size) {
    return crc_update(0, data, size, crc32c_table());
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

#if !PROTOCOL_PARSER_UTILS_AVX2
    return find_pattern_scalar(data, data_size, pattern, pattern_size);
#else
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
                unsigned int index = find_first_set(static_cast<uint32_t>(mask));
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
                unsigned int index = find_first_set(static_cast<uint32_t>(mask));
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
#endif
}

size_t SIMDUtils::find_pattern_sse42(const uint8_t* data,
                                    size_t data_size,
                                    const uint8_t* pattern,
                                    size_t pattern_size) {
    // SSE4.2 版本（类似 AVX2，但使用 16 字节块）
    if (pattern_size == 0 || pattern_size > data_size) {
        return SIZE_MAX;
    }

#if !PROTOCOL_PARSER_UTILS_SSE2
    return find_pattern_scalar(data, data_size, pattern, pattern_size);
#else
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
                unsigned int index = find_first_set(static_cast<uint32_t>(mask));
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
                unsigned int index = find_first_set(static_cast<uint32_t>(mask));
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
#endif
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
