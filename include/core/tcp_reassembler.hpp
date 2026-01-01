#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <set>
#include <vector>
#include <memory>
#include <optional>
#include "buffer_view.hpp"

namespace protocol_parser::core {

/**
 * TCP 数据片段
 */
struct TcpSegment {
    uint32_t seq;            // 序列号
    BufferView data;         // 数据
    bool has_syn;            // 包含 SYN 标志
    bool has_fin;            // 包含 FIN 标志

    TcpSegment() : seq(0), has_syn(false), has_fin(false) {}
    TcpSegment(uint32_t s, BufferView d, bool syn = false, bool fin = false)
        : seq(s), data(d), has_syn(syn), has_fin(fin) {}

    // 按序列号排序
    bool operator<(const TcpSegment& other) const {
        return seq < other.seq;
    }
};

/**
 * TCP 流重组器
 * 处理乱序、重传、分片的 TCP 流
 */
class TcpReassembler {
public:
    // 配置参数
    struct Config {
        size_t max_buffer_size = 10 * 1024 * 1024;  // 最大缓冲区大小 (10MB)
        uint32_t max_out_of_order = 1000;            // 最大乱序包数量
        uint32_t timeout_ms = 30000;                 // 超时时间 (30秒)
        bool enable_fast_path = true;                // 启用快速路径（顺序包）
    };

    explicit TcpReassembler(const Config& config = Config{});
    ~TcpReassembler() = default;

    /**
     * 添加 TCP 数据片段
     * @param segment 数据片段
     * @return 如果有新数据可读返回 true
     */
    bool add_segment(const TcpSegment& segment);

    /**
     * 获取重组后的连续数据
     * @return 可读数据，如果没有则返回空 BufferView
     */
    [[nodiscard]] BufferView get_data();

    /**
     * 消费已读数据
     * @param bytes 要消费的字节数
     */
    void consume(size_t bytes);

    /**
     * 获取当前窗口信息
     */
    struct WindowInfo {
        uint32_t expected_seq;       // 期望的下一个序列号
        uint32_t highest_seq;        // 最高序列号
        size_t buffered_bytes;       // 缓冲的字节数
        size_t available_bytes;      // 可读字节数
        uint32_t gap_count;          // 间隙（缺失片段）数量
    };

    [[nodiscard]] WindowInfo get_window_info() const;

    /**
     * 检查是否完整（收到 FIN 且无间隙）
     */
    [[nodiscard]] bool is_complete() const;

    /**
     * 重置重组器
     */
    void reset();

    /**
     * 获取所有片段（调试用）
     */
    [[nodiscard]] const std::map<uint32_t, TcpSegment>& get_segments() const {
        return segments_;
    }

    /**
     * 设置初始序列号（用于 SYN）
     */
    void set_initial_sequence(uint32_t seq);

private:
    // 合并重叠的片段
    void merge_overlapping_segments();

    // 检查并填补间隙
    void fill_gaps();

    // 快速路径：顺序包直接处理
    bool fast_path_add_segment(const TcpSegment& segment);

    Config config_;
    std::map<uint32_t, TcpSegment> segments_;  // 按序列号排序的片段

    uint32_t expected_seq_ = 0;         // 期望的下一个序列号
    uint32_t initial_seq_ = 0;          // 初始序列号
    bool has_initial_seq_ = false;      // 是否已设置初始序列号

    bool has_fin_ = false;              // 是否收到 FIN
    uint32_t fin_seq_ = 0;              // FIN 的序列号

    std::vector<uint8_t> assembled_data_;  // 重组后的数据
    size_t consumed_bytes_ = 0;            // 已消费的字节数

    // 统计信息
    struct Statistics {
        size_t total_segments = 0;
        size_t out_of_order_segments = 0;
        size_t retransmitted_bytes = 0;
        size_t merged_overlaps = 0;
    } stats_;
};

/**
 * TCP 连接跟踪器
 * 管理双向 TCP 流（客户端->服务器，服务器->客户端）
 */
class TcpConnectionTracker {
public:
    enum class Direction {
        ClientToServer,
        ServerToClient
    };

    // 连接标识
    struct ConnectionKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;

        bool operator<(const ConnectionKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            return dst_port < other.dst_port;
        }

        bool operator==(const ConnectionKey& other) const {
            return src_ip == other.src_ip &&
                   dst_ip == other.dst_ip &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port;
        }
    };

    explicit TcpConnectionTracker() = default;
    ~TcpConnectionTracker() = default;

    /**
     * 获取或创建连接的重组器
     */
    TcpReassembler& get_reassembler(const ConnectionKey& key, Direction dir);

    /**
     * 移除连接
     */
    void remove_connection(const ConnectionKey& key);

    /**
     * 清理过期连接
     */
    void cleanup_old_connections();

    /**
     * 获取连接数量
     */
    [[nodiscard]] size_t connection_count() const {
        return connections_.size();
    }

private:
    // 双向重组器
    struct Connection {
        TcpReassembler client_to_server;
        TcpReassembler server_to_client;
        uint64_t last_activity_ms;  // 最后活动时间
    };

    std::map<ConnectionKey, Connection> connections_;
};

// ============================================================================
// TCP 流处理器（高层接口）
// ============================================================================

/**
 * TCP 流处理器
 * 提供更方便的接口处理 TCP 流
 */
class TcpStreamProcessor {
public:
    /**
     * 处理 TCP 包
     * @param src_ip 源 IP
     * @param dst_ip 目的 IP
     * @param src_port 源端口
     * @param dst_port 目的端口
     * @param seq 序列号
     * @param data 数据
     * @param syn SYN 标志
     * @param fin FIN 标志
     * @return 如果有完整的应用层数据返回
     */
    [[nodiscard]] std::optional<BufferView> process_packet(
        uint32_t src_ip,
        uint32_t dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        uint32_t seq,
        BufferView data,
        bool syn = false,
        bool fin = false
    );

    /**
     * 获取连接跟踪器
     */
    [[nodiscard]] TcpConnectionTracker& get_tracker() {
        return tracker_;
    }

    /**
     * 设置数据回调
     * 当有完整数据可用时调用
     */
    using DataCallback = std::function<void(
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        const BufferView& data
    )>;

    void set_data_callback(DataCallback callback) {
        data_callback_ = std::move(callback);
    }

private:
    TcpConnectionTracker tracker_;
    DataCallback data_callback_;
};

} // namespace protocol_parser::core
