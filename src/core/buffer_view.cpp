#include "core/buffer_view.hpp"
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace protocol_parser::core {

// CPU特性检测
static bool has_avx2() {
#ifdef _MSC_VER
    int cpui[4];
    __cpuid(cpui, 7);
    return (cpui[1] & (1 << 5)) != 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & (1 << 5)) != 0;
    }
    return false;
#endif
}

static bool has_sse2() {
#ifdef _MSC_VER
    int cpui[4];
    __cpuid(cpui, 1);
    return (cpui[3] & (1 << 26)) != 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (edx & (1 << 26)) != 0;
    }
    return false;
#endif
}

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
    
    static bool avx2_supported = has_avx2();
    static bool sse2_supported = has_sse2();
    
    if (avx2_supported && size_ >= 32) {
        return find_avx2(byte);
    } else if (sse2_supported && size_ >= 16) {
        return find_sse2(byte);
    } else {
        return find_scalar(byte);
    }
}

// AVX2实现
BufferView::size_type BufferView::find_avx2(uint8_t byte) const noexcept {
#ifdef __AVX2__
    const __m256i needle = _mm256_set1_epi8(static_cast<char>(byte));
    size_type i = 0;
    
    // 32字节对齐处理
    for (; i + 32 <= size_; i += 32) {
        __m256i haystack = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data_ptr_ + i));
        __m256i cmp = _mm256_cmpeq_epi8(haystack, needle);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        
        if (mask != 0) {
            return i + __builtin_ctz(mask);
        }
    }
    
    // 处理剩余字节
    for (; i < size_; ++i) {
        if (data_ptr_[i] == byte) {
            return i;
        }
    }
#endif
    return SIZE_MAX;
}

// SSE2实现
BufferView::size_type BufferView::find_sse2(uint8_t byte) const noexcept {
#ifdef __SSE2__
    const __m128i needle = _mm_set1_epi8(static_cast<char>(byte));
    size_type i = 0;
    
    // 16字节对齐处理
    for (; i + 16 <= size_; i += 16) {
        __m128i haystack = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data_ptr_ + i));
        __m128i cmp = _mm_cmpeq_epi8(haystack, needle);
        uint16_t mask = _mm_movemask_epi8(cmp);
        
        if (mask != 0) {
            return i + __builtin_ctz(mask);
        }
    }
    
    // 处理剩余字节
    for (; i < size_; ++i) {
        if (data_ptr_[i] == byte) {
            return i;
        }
    }
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
    if (pattern_size == 0 || pattern_size > size_) {
        return SIZE_MAX;
    }
    
    if (pattern_size == 1) {
        return find_simd(*static_cast<const uint8_t*>(pattern));
    }
    
    // 使用Boyer-Moore算法的简化版本
    const auto* pat = static_cast<const uint8_t*>(pattern);
    
    for (size_type i = 0; i <= size_ - pattern_size; ++i) {
        if (std::memcmp(data_ptr_ + i, pat, pattern_size) == 0) {
            return i;
        }
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