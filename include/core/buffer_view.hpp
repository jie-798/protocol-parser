#pragma once

#include <cstdint>
#include <cstring>
#include <atomic>
#include <span>
#include <string_view>
#include <type_traits>
#include <immintrin.h>  // SIMD支持

namespace protocol_parser::core {

/**
 * 高性能零拷贝缓冲区视图
 * 支持SIMD加速和引用计数管理
 */
class BufferView {
public:
    using value_type = uint8_t;
    using size_type = std::size_t;
    using pointer = const uint8_t*;
    using const_pointer = const uint8_t*;
    
    // 构造函数
    BufferView() noexcept = default;
    BufferView(const void* data, size_type size) noexcept;
    BufferView(std::span<const uint8_t> span) noexcept;
    BufferView(std::string_view sv) noexcept;
    
    // 拷贝和移动
    BufferView(const BufferView& other) noexcept;
    BufferView(BufferView&& other) noexcept;
    BufferView& operator=(const BufferView& other) noexcept;
    BufferView& operator=(BufferView&& other) noexcept;
    
    ~BufferView() noexcept;
    
    // 基本访问
    [[nodiscard]] const_pointer data() const noexcept { return data_ptr_; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type capacity() const noexcept { return capacity_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    
    // 索引访问
    [[nodiscard]] uint8_t operator[](size_type index) const noexcept;
    [[nodiscard]] uint8_t at(size_type index) const;
    
    // 子视图创建（零拷贝）
    [[nodiscard]] BufferView substr(size_type offset, size_type count = SIZE_MAX) const noexcept;
    [[nodiscard]] BufferView prefix(size_type count) const noexcept;
    [[nodiscard]] BufferView suffix(size_type count) const noexcept;
    
    // SIMD加速查找
    [[nodiscard]] size_type find_simd(uint8_t byte) const noexcept;
    [[nodiscard]] size_type find_simd(const void* pattern, size_type pattern_size) const noexcept;
    
    // 类型安全解析
    template<typename T>
    [[nodiscard]] T parse_int(size_type offset = 0) const noexcept;
    
    template<typename T>
    [[nodiscard]] T read_be(size_type offset = 0) const noexcept;  // 大端序
    
    template<typename T>
    [[nodiscard]] T read_le(size_type offset = 0) const noexcept;  // 小端序
    
    // 便利方法
    [[nodiscard]] uint16_t read_be16(size_type offset = 0) const noexcept { return read_be<uint16_t>(offset); }
    [[nodiscard]] uint32_t read_be32(size_type offset = 0) const noexcept { return read_be<uint32_t>(offset); }
    [[nodiscard]] uint64_t read_be64(size_type offset = 0) const noexcept { return read_be<uint64_t>(offset); }
    [[nodiscard]] uint16_t read_le16(size_type offset = 0) const noexcept { return read_le<uint16_t>(offset); }
    [[nodiscard]] uint32_t read_le32(size_type offset = 0) const noexcept { return read_le<uint32_t>(offset); }
    [[nodiscard]] uint64_t read_le64(size_type offset = 0) const noexcept { return read_le<uint64_t>(offset); }
    
    // 安全移动
    [[nodiscard]] bool safe_advance(size_type count) noexcept;
    [[nodiscard]] bool can_read(size_type count, size_type offset = 0) const noexcept;
    
    // 转换
    [[nodiscard]] std::span<const uint8_t> as_span() const noexcept;
    [[nodiscard]] std::string_view as_string_view() const noexcept;
    
    // 比较
    [[nodiscard]] bool operator==(const BufferView& other) const noexcept;
    [[nodiscard]] bool starts_with(const BufferView& prefix) const noexcept;
    [[nodiscard]] bool ends_with(const BufferView& suffix) const noexcept;
    
private:
    const_pointer data_ptr_ = nullptr;
    size_type size_ = 0;
    size_type capacity_ = 0;
    mutable std::atomic<uint32_t>* ref_count_ = nullptr;
    
    void acquire() const noexcept;
    void release() const noexcept;
    
    // SIMD实现细节
    size_type find_avx2(uint8_t byte) const noexcept;
    size_type find_sse2(uint8_t byte) const noexcept;
    size_type find_scalar(uint8_t byte) const noexcept;
};

// 模板实现
template<typename T>
T BufferView::parse_int(size_type offset) const noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral type");
    
    if (!can_read(sizeof(T), offset)) {
        return T{};
    }
    
    T result;
    std::memcpy(&result, data_ptr_ + offset, sizeof(T));
    return result;
}

template<typename T>
T BufferView::read_be(size_type offset) const noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral type");
    
    T value = parse_int<T>(offset);
    if constexpr (sizeof(T) == 2) {
        return _byteswap_ushort(value);
    } else if constexpr (sizeof(T) == 4) {
        return _byteswap_ulong(value);
    } else if constexpr (sizeof(T) == 8) {
        return _byteswap_uint64(value);
    } else {
        return value;
    }
}

template<typename T>
T BufferView::read_le(size_type offset) const noexcept {
    return parse_int<T>(offset);  // x86是小端序，直接返回
}

} // namespace protocol_parser::core