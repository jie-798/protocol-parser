#include "core/tcp_reassembler.hpp"
#include <algorithm>
#include <chrono>
#include <iterator>
#include <limits>

namespace protocol_parser::core {

namespace {
bool fits_sequence_space(size_t size) noexcept {
    return size <= std::numeric_limits<uint32_t>::max();
}

uint32_t advance_sequence(uint32_t seq, size_t size) noexcept {
    return seq + static_cast<uint32_t>(size);
}

uint32_t data_end_sequence(const TcpSegment& segment) noexcept {
    return advance_sequence(segment.seq, segment.data.size());
}
}

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

    if (!fits_sequence_space(segment.data.size()) ||
        assembled_data_.size() + segment.data.size() > config_.max_buffer_size) {
        return false;
    }

    assembled_data_.insert(assembled_data_.end(),
                          segment.data.data(),
                          segment.data.data() + segment.data.size());

    expected_seq_ = advance_sequence(expected_seq_, segment.data.size());

    // 处理 SYN/FIN
    if (segment.has_syn) {
        expected_seq_++;
    }
    if (segment.has_fin) {
        has_fin_ = true;
        fin_seq_ = advance_sequence(data_end_sequence(segment), 1);
    }

    stats_.total_segments++;
    return true;
}

bool TcpReassembler::add_segment(const TcpSegment& segment) {
    // 尝试快速路径
    if (fast_path_add_segment(segment)) {
        fill_gaps();
        return true;
    }

    if (!fits_sequence_space(segment.data.size()) || segments_.size() >= config_.max_out_of_order) {
        return false;
    }

    size_t buffered_bytes = assembled_data_.size() - consumed_bytes_;
    for (const auto& [seq, buffered_segment] : segments_) {
        (void)seq;
        buffered_bytes += buffered_segment.data.size();
    }
    if (segment.data.size() > config_.max_buffer_size ||
        buffered_bytes > config_.max_buffer_size - segment.data.size()) {
        return false;
    }

    TcpSegment normalized = segment;
    const uint32_t seq_end = data_end_sequence(normalized);
    if (seq_end <= expected_seq_) {
        stats_.retransmitted_bytes += normalized.data.size();
        return false;
    }

    if (normalized.seq < expected_seq_) {
        const size_t overlap = expected_seq_ - normalized.seq;
        stats_.retransmitted_bytes += overlap;
        normalized.seq = expected_seq_;
        normalized.data = normalized.data.substr(overlap);
    }

    const size_t available_before = assembled_data_.size() - consumed_bytes_;
    auto [it, inserted] = segments_.emplace(normalized.seq, normalized);
    if (!inserted) {
        if (data_end_sequence(normalized) > data_end_sequence(it->second)) {
            it->second = normalized;
        } else {
            stats_.retransmitted_bytes += normalized.data.size();
        }
    }

    stats_.total_segments++;
    if (normalized.seq != expected_seq_) {
        stats_.out_of_order_segments++;
    }

    if (segment.has_fin) {
        has_fin_ = true;
        fin_seq_ = advance_sequence(data_end_sequence(segment), 1);
    }

    merge_overlapping_segments();
    fill_gaps();

    return assembled_data_.size() - consumed_bytes_ > available_before;
}

void TcpReassembler::merge_overlapping_segments() {
    if (segments_.empty()) {
        return;
    }

    auto it = segments_.begin();
    auto current = it++;
    uint32_t current_end = data_end_sequence(current->second);

    while (it != segments_.end()) {
        const uint32_t next_seq = it->second.seq;
        const uint32_t next_end = data_end_sequence(it->second);

        if (next_seq < current_end && next_end <= current_end) {
            stats_.merged_overlaps++;
            it = segments_.erase(it);
        } else {
            current = it;
            current_end = next_end;
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
        const uint32_t segment_end = data_end_sequence(it->second);
        if (segment_end <= expected_seq_) {
            stats_.retransmitted_bytes += it->second.data.size();
            it = segments_.erase(it);
            continue;
        }

        if (it->second.seq > expected_seq_) {
            break;
        }

        const size_t offset = expected_seq_ - it->second.seq;
        auto payload = it->second.data.substr(offset);
        assembled_data_.insert(assembled_data_.end(),
                              payload.data(),
                              payload.data() + payload.size());

        expected_seq_ = advance_sequence(expected_seq_, payload.size());

        if (it->second.has_syn) {
            expected_seq_++;
        }

        it = segments_.erase(it);
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
    info.gap_count = segments_.size() > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(segments_.size());

    // 计算最高序列号
    for (const auto& [seq, segment] : segments_) {
        (void)seq;
        uint32_t seg_end = data_end_sequence(segment);
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

TcpConnectionTracker::TcpConnectionTracker(uint64_t timeout_ms)
    : timeout_ms_(timeout_ms) {
}

uint64_t TcpConnectionTracker::current_time_ms() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

TcpReassembler& TcpConnectionTracker::get_reassembler(
    const ConnectionKey& key,
    Direction dir) {

    auto [it, inserted] = connections_.emplace(key, Connection{});
    (void)inserted;

    it->second.last_activity_ms = current_time_ms();

    return (dir == Direction::ClientToServer)
        ? it->second.client_to_server
        : it->second.server_to_client;
}

void TcpConnectionTracker::remove_connection(const ConnectionKey& key) {
    connections_.erase(key);
}

void TcpConnectionTracker::cleanup_old_connections() {
    const uint64_t now = current_time_ms();
    for (auto it = connections_.begin(); it != connections_.end();) {
        const uint64_t last_activity = it->second.last_activity_ms;
        if (last_activity <= now && now - last_activity >= timeout_ms_) {
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
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
