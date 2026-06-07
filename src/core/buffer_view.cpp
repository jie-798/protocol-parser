#include "core/buffer_view.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#define PROTOCOL_PARSER_X86 1
#else
#define PROTOCOL_PARSER_X86 0
#endif

#if PROTOCOL_PARSER_X86
#include <immintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#if defined(__AVX2__)
#define PROTOCOL_PARSER_HAS_AVX2_INTRINSICS 1
#else
#define PROTOCOL_PARSER_HAS_AVX2_INTRINSICS 0
#endif

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define PROTOCOL_PARSER_HAS_SSE2_INTRINSICS 1
#else
#define PROTOCOL_PARSER_HAS_SSE2_INTRINSICS 0
#endif

namespace protocol_parser::core {

// CPU特性检测
[[maybe_unused]] static bool has_avx2() {
#if PROTOCOL_PARSER_X86
#ifdef _MSC_VER
    int cpui[4]{};
    __cpuidex(cpui, 7, 0);
    return (cpui[1] & (1 << 5)) != 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & (1 << 5)) != 0;
    }
    return false;
#endif
#else
    return false;
#endif
}

[[maybe_unused]] static bool has_sse2() {
#if PROTOCOL_PARSER_X86
#if defined(_M_X64)
    return true;
#elif defined(_MSC_VER)
    int cpui[4]{};
    __cpuid(cpui, 1);
    return (cpui[3] & (1 << 26)) != 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (edx & (1 << 26)) != 0;
    }
    return false;
#endif
#else
    return false;
#endif
}

#if PROTOCOL_PARSER_HAS_AVX2_INTRINSICS || PROTOCOL_PARSER_HAS_SSE2_INTRINSICS
static uint32_t first_set_bit(uint32_t mask) noexcept {
#ifdef _MSC_VER
    unsigned long index = 0;
    _BitScanForward(&index, mask);
    return static_cast<uint32_t>(index);
#else
    return static_cast<uint32_t>(__builtin_ctz(mask));
#endif
}
#endif

// 构造函数实现
BufferView::BufferView(const void* data, size_type size) noexcept
    : data_ptr_(static_cast<const_pointer>(data))
    , size_(size)
    , capacity_(size)
    , ref_count_(nullptr) {
}

BufferView::BufferView(std::span<const uint8_t> span) noexcept
    : data_ptr_(span.data())
    , size_(span.size())
    , capacity_(span.size())
    , ref_count_(nullptr) {
}

BufferView::BufferView(std::string_view sv) noexcept
    : data_ptr_(reinterpret_cast<const_pointer>(sv.data()))
    , size_(sv.size())
    , capacity_(sv.size())
    , ref_count_(nullptr) {
}

// 拷贝构造函数
BufferView::BufferView(const BufferView& other) noexcept
    : data_ptr_(other.data_ptr_)
    , size_(other.size_)
    , capacity_(other.capacity_)
    , ref_count_(other.ref_count_) {
    acquire();
}

// 移动构造函数
BufferView::BufferView(BufferView&& other) noexcept
    : data_ptr_(other.data_ptr_)
    , size_(other.size_)
    , capacity_(other.capacity_)
    , ref_count_(other.ref_count_) {
    other.data_ptr_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
    other.ref_count_ = nullptr;
}

// 拷贝赋值
BufferView& BufferView::operator=(const BufferView& other) noexcept {
    if (this != &other) {
        release();
        data_ptr_ = other.data_ptr_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        ref_count_ = other.ref_count_;
        acquire();
    }
    return *this;
}

// 移动赋值
BufferView& BufferView::operator=(BufferView&& other) noexcept {
    if (this != &other) {
        release();
        data_ptr_ = other.data_ptr_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        ref_count_ = other.ref_count_;
        
        other.data_ptr_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
        other.ref_count_ = nullptr;
    }
    return *this;
}

// 析构函数
BufferView::~BufferView() noexcept {
    release();
}

// 索引访问
uint8_t BufferView::operator[](size_type index) const noexcept {
    return data_ptr_[index];
}

uint8_t BufferView::at(size_type index) const {
    if (index >= size_) {
        throw std::out_of_range("BufferView index out of range");
    }
    return data_ptr_[index];
}

// 子视图创建
BufferView BufferView::substr(size_type offset, size_type count) const noexcept {
    if (offset >= size_) {
        return BufferView();
    }
    
    size_type actual_count = std::min(count, size_ - offset);
    BufferView result;
    result.data_ptr_ = data_ptr_ + offset;
    result.size_ = actual_count;
    result.capacity_ = capacity_ - offset;
    result.ref_count_ = ref_count_;
    result.acquire();
    
    return result;
}

BufferView BufferView::prefix(size_type count) const noexcept {
    return substr(0, count);
}

BufferView BufferView::suffix(size_type count) const noexcept {
    if (count >= size_) {
        return *this;
    }
    return substr(size_ - count, count);
}

// SIMD加速查找实现
BufferView::size_type BufferView::find_simd(uint8_t byte) const noexcept {
    if (empty()) {
        return SIZE_MAX;
    }
    
#if PROTOCOL_PARSER_HAS_AVX2_INTRINSICS
    static bool avx2_supported = has_avx2();
    if (avx2_supported && size_ >= 32) {
        return find_avx2(byte);
    }
#endif

#if PROTOCOL_PARSER_HAS_SSE2_INTRINSICS
    static bool sse2_supported = has_sse2();
    if (sse2_supported && size_ >= 16) {
        return find_sse2(byte);
    }
#endif

    return find_scalar(byte);
}

// AVX2实现
BufferView::size_type BufferView::find_avx2(uint8_t byte) const noexcept {
#if PROTOCOL_PARSER_HAS_AVX2_INTRINSICS
    const __m256i needle = _mm256_set1_epi8(static_cast<char>(byte));
    size_type i = 0;
    
    // 32字节对齐处理
    for (; i + 32 <= size_; i += 32) {
        __m256i haystack = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data_ptr_ + i));
        __m256i cmp = _mm256_cmpeq_epi8(haystack, needle);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        
        if (mask != 0) {
            return i + first_set_bit(mask);
        }
    }
    
    // 处理剩余字节
    for (; i < size_; ++i) {
        if (data_ptr_[i] == byte) {
            return i;
        }
    }
#else
    (void)byte;
#endif
    return SIZE_MAX;
}

// SSE2实现
BufferView::size_type BufferView::find_sse2(uint8_t byte) const noexcept {
#if PROTOCOL_PARSER_HAS_SSE2_INTRINSICS
    const __m128i needle = _mm_set1_epi8(static_cast<char>(byte));
    size_type i = 0;
    
    // 16字节对齐处理
    for (; i + 16 <= size_; i += 16) {
        __m128i haystack = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data_ptr_ + i));
        __m128i cmp = _mm_cmpeq_epi8(haystack, needle);
        uint32_t mask = static_cast<uint32_t>(_mm_movemask_epi8(cmp));
        
        if (mask != 0) {
            return i + first_set_bit(mask);
        }
    }
    
    // 处理剩余字节
    for (; i < size_; ++i) {
        if (data_ptr_[i] == byte) {
            return i;
        }
    }
#else
    (void)byte;
#endif
    return SIZE_MAX;
}

// 标量实现
BufferView::size_type BufferView::find_scalar(uint8_t byte) const noexcept {
    const auto* found = static_cast<const uint8_t*>(
        std::memchr(data_ptr_, byte, size_)
    );
    return found ? static_cast<size_type>(found - data_ptr_) : SIZE_MAX;
}

// 模式查找
BufferView::size_type BufferView::find_simd(const void* pattern, size_type pattern_size) const noexcept {
    if (pattern == nullptr || pattern_size == 0 || pattern_size > size_) {
        return SIZE_MAX;
    }

    const auto* pat = static_cast<const uint8_t*>(pattern);
    if (pattern_size == 1) {
        return find_simd(*pat);
    }

    size_type search_offset = 0;
    const size_type last_candidate = size_ - pattern_size;
    while (search_offset <= last_candidate) {
        const size_type search_size = last_candidate - search_offset + 1;
        const auto* found = static_cast<const uint8_t*>(
            std::memchr(data_ptr_ + search_offset, *pat, search_size)
        );
        if (found == nullptr) {
            return SIZE_MAX;
        }

        const size_type candidate = static_cast<size_type>(found - data_ptr_);
        if (std::memcmp(found + 1, pat + 1, pattern_size - 1) == 0) {
            return candidate;
        }
        search_offset = candidate + 1;
    }

    return SIZE_MAX;
}

// 安全移动
bool BufferView::safe_advance(size_type count) noexcept {
    if (count > size_) {
        return false;
    }
    
    data_ptr_ += count;
    size_ -= count;
    capacity_ -= count;
    return true;
}

bool BufferView::can_read(size_type count, size_type offset) const noexcept {
    return offset <= size_ && count <= size_ - offset;
}

// 转换函数
std::span<const uint8_t> BufferView::as_span() const noexcept {
    return std::span<const uint8_t>(data_ptr_, size_);
}

std::string_view BufferView::as_string_view() const noexcept {
    return std::string_view(reinterpret_cast<const char*>(data_ptr_), size_);
}

// 比较函数
bool BufferView::operator==(const BufferView& other) const noexcept {
    if (size_ != other.size_) {
        return false;
    }
    return std::memcmp(data_ptr_, other.data_ptr_, size_) == 0;
}

bool BufferView::starts_with(const BufferView& prefix) const noexcept {
    if (prefix.size_ > size_) {
        return false;
    }
    return std::memcmp(data_ptr_, prefix.data_ptr_, prefix.size_) == 0;
}

bool BufferView::ends_with(const BufferView& suffix) const noexcept {
    if (suffix.size_ > size_) {
        return false;
    }
    return std::memcmp(data_ptr_ + size_ - suffix.size_, suffix.data_ptr_, suffix.size_) == 0;
}

// 引用计数管理
void BufferView::acquire() const noexcept {
    if (ref_count_) {
        ref_count_->fetch_add(1, std::memory_order_relaxed);
    }
}

void BufferView::release() const noexcept {
    if (ref_count_) {
        if (ref_count_->fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete ref_count_;
        }
    }
}

} // namespace protocol_parser::core