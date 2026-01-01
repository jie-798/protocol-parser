#include "core/tcp_reassembler.hpp"
#include <algorithm>
#include <iterator>

namespace protocol_parser::core {

// ============================================================================
// TcpReassembler 实现
// ============================================================================

TcpReassembler::TcpReassembler(const Config& config)
    : config_(config) {
}

TcpReassembler::TcpReassembler()
    : TcpReassembler(Config{}) {
}

void TcpReassembler::set_initial_sequence(uint32_t seq) {
    initial_seq_ = seq;
    expected_seq_ = seq + 1;  // SYN 占用一个序列号
    has_initial_seq_ = true;
}

bool TcpReassembler::fast_path_add_segment(const TcpSegment& segment) {
    // 快速路径：处理顺序到达的包
    if (!config_.enable_fast_path) {
        return false;
    }

    // 检查是否是期望的序列号
    if (segment.seq != expected_seq_) {
        return false;
    }

    // 直接追加到已组装数据
    size_t old_size = assembled_data_.size();
    assembled_data_.insert(assembled_data_.end(),
                          segment.data.data(),
                          segment.data.data() + segment.data.size());

    expected_seq_ += segment.data.size();

    // 处理 SYN/FIN
    if (segment.has_syn) {
        expected_seq_++;
    }
    if (segment.has_fin) {
        has_fin_ = true;
        fin_seq_ = segment.seq + segment.data.size() + 1;
    }

    stats_.total_segments++;
    return true;
}

bool TcpReassembler::add_segment(const TcpSegment& segment) {
    // 尝试快速路径
    if (fast_path_add_segment(segment)) {
        return true;
    }

    // 慢速路径：处理乱序包

    // 检查缓冲区大小限制
    if (segments_.size() >= config_.max_out_of_order) {
        return false;  // 丢弃
    }

    // 计算实际序列号（相对序列号）
    uint32_t rel_seq = segment.seq;
    if (has_initial_seq_) {
        rel_seq = segment.seq - initial_seq_;
    }

    // 检查是否是旧数据（已消费的序列号）
    uint32_t seq_end = segment.seq + segment.data.size();
    if (seq_end <= expected_seq_) {
        // 这是一个旧包或重传
        stats_.retransmitted_bytes += segment.data.size();
        return false;
    }

    // 插入片段
    auto [it, inserted] = segments_.emplace(segment.seq, segment);
    if (!inserted) {
        // 序列号冲突，合并数据
        // TODO: 处理重叠
    }

    stats_.total_segments++;
    if (segment.seq != expected_seq_) {
        stats_.out_of_order_segments++;
    }

    // 处理 FIN
    if (segment.has_fin) {
        has_fin_ = true;
        fin_seq_ = segment.seq + segment.data.size() + 1;
    }

    // 尝试合并和重组
    merge_overlapping_segments();
    fill_gaps();

    return !assembled_data_.empty() ||
           assembled_data_.size() > (consumed_bytes_ + consumed_bytes_);
}

void TcpReassembler::merge_overlapping_segments() {
    if (segments_.empty()) {
        return;
    }

    auto it = segments_.begin();
    auto current = it++;
    uint32_t current_end = current->second.seq + current->second.data.size();

    while (it != segments_.end()) {
        uint32_t next_seq = it->second.seq;
        uint32_t next_end = next_seq + it->second.data.size();

        // 检查重叠
        if (next_seq <= current_end) {
            // 有重叠，合并
            if (next_end > current_end) {
                // 扩展当前片段
                size_t overlap_size = current_end - next_seq;
                size_t new_data_size = next_end - current_end;

                // TODO: 合并数据到 current
                stats_.merged_overlaps++;
                current_end = next_end;
            }

            // 删除下一个片段（已合并）
            it = segments_.erase(it);
        } else {
            // 无重叠，移动到下一个
            current = it;
            current_end = current->second.seq + current->second.data.size();
            ++it;
        }
    }
}

void TcpReassembler::fill_gaps() {
    if (segments_.empty()) {
        return;
    }

    // 从第一个片段开始，检查是否可以连续
    auto it = segments_.begin();

    while (it != segments_.end()) {
        if (it->second.seq == expected_seq_) {
            // 找到期望的片段，添加到已组装数据
            size_t old_size = assembled_data_.size();
            assembled_data_.insert(assembled_data_.end(),
                                  it->second.data.data(),
                                  it->second.data.data() + it->second.data.size());

            expected_seq_ += it->second.data.size();

            if (it->second.has_syn) {
                expected_seq_++;
            }

            // 移除已处理的片段
            it = segments_.erase(it);
        } else {
            // 有间隙，无法继续
            break;
        }
    }

    // 检查 FIN
    if (has_fin_ && expected_seq_ >= fin_seq_) {
        // FIN 已包含在数据中，完成
    }
}

BufferView TcpReassembler::get_data() {
    size_t available = assembled_data_.size() - consumed_bytes_;
    if (available == 0) {
        return BufferView{};
    }

    return BufferView(assembled_data_.data() + consumed_bytes_, available);
}

void TcpReassembler::consume(size_t bytes) {
    size_t available = assembled_data_.size() - consumed_bytes_;
    size_t to_consume = std::min(bytes, available);

    consumed_bytes_ += to_consume;

    // 如果所有数据都已消费，清理缓冲区
    if (consumed_bytes_ == assembled_data_.size()) {
        assembled_data_.clear();
        consumed_bytes_ = 0;
    }
}

TcpReassembler::WindowInfo TcpReassembler::get_window_info() const {
    WindowInfo info;
    info.expected_seq = expected_seq_;
    info.highest_seq = expected_seq_;
    info.buffered_bytes = assembled_data_.size() - consumed_bytes_;
    info.available_bytes = info.buffered_bytes;
    info.gap_count = segments_.size();

    // 计算最高序列号
    for (const auto& [seq, segment] : segments_) {
        uint32_t seg_end = seq + segment.data.size();
        if (seg_end > info.highest_seq) {
            info.highest_seq = seg_end;
        }
        info.buffered_bytes += segment.data.size();
    }

    return info;
}

bool TcpReassembler::is_complete() const {
    if (!has_fin_) {
        return false;
    }

    // 检查是否已收到 FIN 且无间隙
    return segments_.empty() && expected_seq_ >= fin_seq_;
}

void TcpReassembler::reset() {
    segments_.clear();
    assembled_data_.clear();
    consumed_bytes_ = 0;
    expected_seq_ = has_initial_seq_ ? initial_seq_ + 1 : 0;
    has_fin_ = false;
    fin_seq_ = 0;
    stats_ = {};
}

// ============================================================================
// TcpConnectionTracker 实现
// ============================================================================

TcpReassembler& TcpConnectionTracker::get_reassembler(
    const ConnectionKey& key,
    Direction dir) {

    auto [it, inserted] = connections_.emplace(key, Connection{});

    // 更新活动时间
    // TODO: 使用实际时间戳
    it->second.last_activity_ms = 0;

    return (dir == Direction::ClientToServer)
        ? it->second.client_to_server
        : it->second.server_to_client;
}

void TcpConnectionTracker::remove_connection(const ConnectionKey& key) {
    connections_.erase(key);
}

void TcpConnectionTracker::cleanup_old_connections() {
    // TODO: 实现超时清理
    // 遍历所有连接，检查 last_activity_ms
}

// ============================================================================
// TcpStreamProcessor 实现
// ============================================================================

std::optional<BufferView> TcpStreamProcessor::process_packet(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq,
    BufferView data,
    bool syn,
    bool fin) {

    // 创建连接键
    TcpConnectionTracker::ConnectionKey key{
        src_ip, dst_ip, src_port, dst_port, true  // is_tcp = true
    };

    // 确定方向
    // 简单启发式：假设较小端口是客户端
    // 实际应用中应该根据三次握手判断
    auto direction = (src_port < dst_port)
        ? TcpConnectionTracker::Direction::ClientToServer
        : TcpConnectionTracker::Direction::ServerToClient;

    // 获取重组器
    auto& reassembler = tracker_.get_reassembler(key, direction);

    // 处理 SYN
    if (syn) {
        reassembler.set_initial_sequence(seq);
    }

    // 添加片段
    TcpSegment segment{seq, data, syn, fin};
    reassembler.add_segment(segment);

    // 获取可用数据
    auto available_data = reassembler.get_data();
    if (available_data.size() > 0) {
        // 触发回调
        if (data_callback_) {
            data_callback_(src_ip, dst_ip, src_port, dst_port, available_data);
        }
        return available_data;
    }

    return std::nullopt;
}

} // namespace protocol_parser::core
