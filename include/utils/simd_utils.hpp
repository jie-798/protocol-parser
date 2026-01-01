#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <immintrin.h>

namespace protocol_parser::utils {

/**
 * SIMD 优化工具集
 * 包括 CRC32、模式匹配、字符串操作等
 */
class SIMDUtils {
public:
    // ========================================================================
    // CRC32 校验和计算
    // ========================================================================

    /**
     * 计算 CRC32 校验和（SSE4.2 硬件加速）
     * @param data 数据指针
     * @param size 数据大小
     * @return CRC32 值
     */
    static uint32_t crc32(const uint8_t* data, size_t size);

    /**
     * 计算 CRC32C（Castagnoli 多项式，用于 iSCSI 等）
     */
    static uint32_t crc32c(const uint8_t* data, size_t size);

    /**
     * 分块计算 CRC32（支持流式处理）
     */
    static uint32_t crc32_append(uint32_t previous_crc,
                                 const uint8_t* data,
                                 size_t size);

    // ========================================================================
    // 模式匹配
    // ========================================================================

    /**
     * 快速搜索模式（AVX2 加速）
     * @param data 数据指针
     * @param data_size 数据大小
     * @param pattern 模式指针
     * @param pattern_size 模式大小
     * @return 找到的位置，未找到返回 SIZE_MAX
     */
    static size_t find_pattern_avx2(const uint8_t* data,
                                    size_t data_size,
                                    const uint8_t* pattern,
                                    size_t pattern_size);

    /**
     * 快速搜索模式（SSE4.2 加速）
     */
    static size_t find_pattern_sse42(const uint8_t* data,
                                     size_t data_size,
                                     const uint8_t* pattern,
                                     size_t pattern_size);

    /**
     * 多模式搜索（同时搜索多个模式）
     * @param data 数据指针
     * @param data_size 数据大小
     * @param patterns 模式数组
     * @param pattern_sizes 模式大小数组
     * @param num_patterns 模式数量
     * @param found_pattern 输出：找到的模式索引
     * @return 找到的位置，未找到返回 SIZE_MAX
     */
    static size_t find_multi_pattern_avx2(const uint8_t* data,
                                         size_t data_size,
                                         const uint8_t** patterns,
                                         const size_t* pattern_sizes,
                                         size_t num_patterns,
                                         size_t* found_pattern);

    // ========================================================================
    // 字符串操作
    // ========================================================================

    /**
     * 快速比较两个缓冲区（AVX2 加速）
     * @return 相等返回 true
     */
    static bool equals_avx2(const uint8_t* a, const uint8_t* b, size_t size);

    /**
     * 快速填充内存（AVX2 加速）
     */
    static void memset_avx2(uint8_t* data, uint8_t value, size_t size);

    /**
     * 快速内存复制（AVX2 加速，非对齐）
     */
    static void memcpy_avx2(uint8_t* dst, const uint8_t* src, size_t size);

    // ========================================================================
    // 字节序转换（SIMD 优化）
    // ========================================================================

    /**
     * 批量转换字节序（16 字节块）
     */
    static void swap_bytes_16x8(__m128i* data);

    /**
     * 批量转换字节序（32 字节块）
     */
    static void swap_bytes_32x8(__m256i* data);

    // ========================================================================
    * 网络序整数解析（SIMD 加速）
    // ========================================================================

    /**
     * 批量解析大端序 16 位整数
     * @param data 数据指针
     * @param values 输出数组
     * @param count 要解析的数量
     */
    static void parse_be16_batch(const uint8_t* data,
                                uint16_t* values,
                                size_t count);

    /**
     * 批量解析大端序 32 位整数
     */
    static void parse_be32_batch(const uint8_t* data,
                                uint32_t* values,
                                size_t count);

private:
    // CRC32 查找表（用于无硬件加速的情况）
    static uint32_t crc32_table_[256];
    static bool crc32_table_initialized_;

    static void init_crc32_table();

    // 软件实现 CRC32（回退）
    static uint32_t crc32_software(const uint8_t* data, size_t size);
};

// ============================================================================
// 内联函数实现
// ============================================================================

inline bool SIMDUtils::equals_avx2(const uint8_t* a,
                                  const uint8_t* b,
                                  size_t size) {
    if (size == 0) return true;

    size_t i = 0;

    // AVX2 块（32 字节）
    while (i + 32 <= size) {
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + i));
        __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b + i));
        __m256i cmp = _mm256_cmpeq_epi8(va, vb);

        if (_mm256_movemask_epi8(cmp) != 0xFFFFFFFF) {
            return false;
        }
        i += 32;
    }

    // SSE2 块（16 字节）
    while (i + 16 <= size) {
        __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i));
        __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
        __m128i cmp = _mm_cmpeq_epi8(va, vb);

        if (_mm_movemask_epi8(cmp) != 0xFFFF) {
            return false;
        }
        i += 16;
    }

    // 剩余字节
    while (i < size) {
        if (a[i] != b[i]) return false;
        i++;
    }

    return true;
}

inline void SIMDUtils::memset_avx2(uint8_t* data, uint8_t value, size_t size) {
    // 创建填充模式
    __m256i pattern = _mm256_set1_epi8(value);

    size_t i = 0;

    // AVX2 块
    while (i + 32 <= size) {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(data + i), pattern);
        i += 32;
    }

    // SSE2 块
    __m128i pattern_sse = _mm_set1_epi8(value);
    while (i + 16 <= size) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(data + i), pattern_sse);
        i += 16;
    }

    // 剩余字节
    for (; i < size; ++i) {
        data[i] = value;
    }
}

inline void SIMDUtils::memcpy_avx2(uint8_t* dst,
                                  const uint8_t* src,
                                  size_t size) {
    size_t i = 0;

    // AVX2 块
    while (i + 32 <= size) {
        __m256i data = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), data);
        i += 32;
    }

    // SSE2 块
    while (i + 16 <= size) {
        __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src + i));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(dst + i), data);
        i += 16;
    }

    // 剩余字节
    for (; i < size; ++i) {
        dst[i] = src[i];
    }
}

inline void SIMDUtils::swap_bytes_16x8(__m128i* data) {
    // 使用 SSSE3 的 pshufb 指令
    __m128i shuffle_mask = _mm_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    *data = _mm_shuffle_epi8(*data, shuffle_mask);
}

inline void SIMDUtils::swap_bytes_32x8(__m256i* data) {
    __m256i shuffle_mask = _mm256_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    *data = _mm256_shuffle_epi8(*data, shuffle_mask);
}

inline void SIMDUtils::parse_be16_batch(const uint8_t* data,
                                       uint16_t* values,
                                       size_t count) {
    for (size_t i = 0; i < count; ++i) {
        uint16_t val;
        std::memcpy(&val, data + i * 2, 2);
        values[i] = _byteswap_ushort(val);
    }
}

inline void SIMDUtils::parse_be32_batch(const uint8_t* data,
                                       uint32_t* values,
                                       size_t count) {
    for (size_t i = 0; i < count; ++i) {
        uint32_t val;
        std::memcpy(&val, data + i * 4, 4);
        values[i] = _byteswap_ulong(val);
    }
}

} // namespace protocol_parser::utils
