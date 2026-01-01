/**
 * 性能基准测试
 *
 * 测试各个组件的性能：
 * 1. BufferPool 性能（vs 标准 new/delete）
 * 2. SIMD 加速性能（vs 标量实现）
 * 3. TCP 流重组性能
 * 4. 协议检测性能
 * 5. 解析器性能
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <iomanip>
#include <numeric>

#include "core/buffer_pool.hpp"
#include "core/buffer_view.hpp"
#include "utils/simd_utils.hpp"
#include "core/tcp_reassembler.hpp"
#include "detection/protocol_detector.hpp"
#include "parsers/application/http_parser.hpp"
#include "parsers/transport/quic_parser.hpp"
#include "parsers/application/sip_parser.hpp"
#include "parsers/transport/rtp_parser.hpp"

using namespace protocol_parser;
using namespace std::chrono;

// ============================================================================
// 计时辅助类
// ============================================================================

class Timer {
public:
    void start() {
        start_time_ = high_resolution_clock::now();
    }

    double stop_ms() {
        auto end_time = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end_time - start_time_);
        return duration.count() / 1000.0;
    }

    double stop_us() {
        auto end_time_ = high_resolution_clock::now();
        auto duration = duration_cast<nanoseconds>(end_time_ - start_time_);
        return duration.count() / 1000.0;
    }

private:
    time_point<high_resolution_clock> start_time_;
};

// ============================================================================
// 测试数据生成器
// ============================================================================

class TestDataGenerator {
public:
    static std::vector<uint8_t> generate_random(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (auto& byte : data) {
            byte = static_cast<uint8_t>(dis(gen));
        }

        return data;
    }

    static std::vector<uint8_t> generate_pattern(size_t size, uint8_t pattern) {
        std::vector<uint8_t> data(size, pattern);
        return data;
    }

    static std::vector<uint8_t> generate_http_request() {
        const char* http_request =
            "GET /index.html HTTP/1.1\r\n"
            "Host: www.example.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";

        std::vector<uint8_t> data(
            reinterpret_cast<const uint8_t*>(http_request),
            reinterpret_cast<const uint8_t*>(http_request) + strlen(http_request)
        );

        return data;
    }

    static std::vector<uint8_t> generate_sip_invite() {
        const char* sip_invite =
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/UDP pc33.example.com:5060;branch=z9hG4bK776asdhds\r\n"
            "Max-Forwards: 70\r\n"
            "To: Bob <sip:bob@example.com>\r\n"
            "From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
            "Call-ID: a84b4c76e66710@pc33.example.com\r\n"
            "CSeq: 314159 INVITE\r\n"
            "Contact: <sip:alice@pc33.example.com>\r\n"
            "Content-Type: application/sdp\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        std::vector<uint8_t> data(
            reinterpret_cast<const uint8_t*>(sip_invite),
            reinterpret_cast<const uint8_t*>(sip_invite) + strlen(sip_invite)
        );

        return data;
    }
};

// ============================================================================
// 基准测试 1: BufferPool 性能
// ============================================================================

void benchmark_buffer_pool() {
    std::cout << "\n=== BufferPool 性能测试 ===\n";

    const size_t iterations = 1000000;
    const size_t buffer_size = 1514;  // 标准 MTU

    Timer timer;

    // 测试标准 new/delete
    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        uint8_t* data = new uint8_t[buffer_size];
        delete[] data;
    }
    double standard_time = timer.stop_ms();

    // 测试 BufferPool
    core::BufferPool pool;
    pool.warmup();

    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        auto buffer = pool.acquire(buffer_size);
        pool.release(buffer);
    }
    double pool_time = timer.stop_ms();

    // 输出结果
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "标准 new/delete: " << standard_time << " ms ("
              << (iterations / standard_time * 1000) << " ops/sec)\n";
    std::cout << "BufferPool:       " << pool_time << " ms ("
              << (iterations / pool_time * 1000) << " ops/sec)\n";
    std::cout << "性能提升:         " << (standard_time / pool_time) << "x\n";

    auto stats = pool.get_statistics();
    std::cout << "\nBufferPool 统计:\n";
    std::cout << "  缓存命中率: " << (stats.hit_rate() * 100.0) << "%\n";
    std::cout << "  峰值使用:   " << stats.peak_usage << " buffers\n";
}

// ============================================================================
// 基准测试 2: SIMD 性能
// ============================================================================

void benchmark_simd() {
    std::cout << "\n=== SIMD 性能测试 ===\n";

    const size_t data_size = 1024 * 1024;  // 1MB
    auto data = TestDataGenerator::generate_random(data_size);
    core::BufferView buffer(data.data(), data.size());

    Timer timer;

    // 测试 CRC32 计算
    timer.start();
    for (int i = 0; i < 100; ++i) {
        volatile uint32_t crc = utils::SIMDUtils::crc32(buffer.data(), buffer.size());
        (void)crc;
    }
    double crc_time = timer.stop_ms();

    // 测试模式匹配（SIMD）
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};

    timer.start();
    for (int i = 0; i < 1000; ++i) {
        volatile size_t pos = utils::SIMDUtils::find_pattern_avx2(
            buffer.data(), buffer.size(), pattern.data(), pattern.size()
        );
        (void)pos;
    }
    double simd_match_time = timer.stop_ms();

    // 测试模式匹配（标量）
    timer.start();
    for (int i = 0; i < 1000; ++i) {
        auto it = std::search(data.begin(), data.end(),
                            pattern.begin(), pattern.end());
        (void)it;
    }
    double scalar_match_time = timer.stop_ms();

    // 输出结果
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "CRC32 计算 (100次, 1MB):    " << crc_time << " ms ("
              << (100.0 * data_size / 1024 / crc_time) << " MB/s)\n";
    std::cout << "SIMD 模式匹配 (1000次):     " << simd_match_time << " ms\n";
    std::cout << "标量模式匹配 (1000次):      " << scalar_match_time << " ms\n";
    std::cout << "SIMD 加速:                 " << (scalar_match_time / simd_match_time) << "x\n";
}

// ============================================================================
// 基准测试 3: TCP 流重组性能
// ============================================================================

void benchmark_tcp_reassembly() {
    std::cout << "\n=== TCP 流重组性能测试 ===\n";

    const size_t packet_count = 10000;
    const size_t packet_size = 1460;  // 标准 MSS

    core::TcpReassembler reassembler;

    Timer timer;
    size_t total_bytes = 0;

    // 顺序包测试
    std::cout << "顺序包测试:\n";
    timer.start();
    for (size_t i = 0; i < packet_count; ++i) {
        auto data = TestDataGenerator::generate_random(packet_size);
        core::BufferView buffer(data.data(), data.size());

        core::TcpSegment segment{i * packet_size, buffer, false, false};
        reassembler.add_segment(segment);

        total_bytes += packet_size;
    }
    double ordered_time = timer.stop_ms();

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  时间: " << ordered_time << " ms\n";
    std::cout << "  吞吐量: " << (total_bytes / 1024.0 / 1024.0 / (ordered_time / 1000.0))
              << " MB/s\n";

    // 乱序包测试
    std::cout << "\n乱序包测试:\n";
    reassembler.reset();
    std::vector<size_t> order(packet_count);
    std::iota(order.begin(), order.end(), 0);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(order.begin(), order.end(), gen);

    timer.start();
    for (size_t i : order) {
        auto data = TestDataGenerator::generate_random(packet_size);
        core::BufferView buffer(data.data(), data.size());

        core::TcpSegment segment{i * packet_size, buffer, false, false};
        reassembler.add_segment(segment);
    }
    double unordered_time = timer.stop_ms();

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  时间: " << unordered_time << " ms\n";
    std::cout << "  吞吐量: " << (total_bytes / 1024.0 / 1024.0 / (unordered_time / 1000.0))
              << " MB/s\n";
    std::cout << "  性能下降: " << ((unordered_time / ordered_time - 1.0) * 100.0) << "%\n";
}

// ============================================================================
// 基准测试 4: 协议检测性能
// ============================================================================

void benchmark_protocol_detection() {
    std::cout << "\n=== 协议检测性能测试 ===\n";

    detection::ProtocolDetector detector;

    // 生成各种测试数据
    auto http_data = TestDataGenerator::generate_http_request();
    auto sip_data = TestDataGenerator::generate_sip_invite();
    auto random_data = TestDataGenerator::generate_random(1024);

    core::BufferView http_buffer(http_data.data(), http_data.size());
    core::BufferView sip_buffer(sip_data.data(), sip_data.size());
    core::BufferView random_buffer(random_data.data(), random_data.size());

    Timer timer;
    const size_t iterations = 100000;

    // HTTP 检测
    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        volatile auto result = detector.detect(
            0xC0A80101, 0xC0A80102, 12345, 80, http_buffer, true
        );
        (void)result;
    }
    double http_time = timer.stop_us();

    // SIP 检测
    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        volatile auto result = detector.detect(
            0xC0A80101, 0xC0A80102, 12345, 5060, sip_buffer, true
        );
        (void)result;
    }
    double sip_time = timer.stop_us();

    // 随机数据检测
    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        volatile auto result = detector.detect(
            0xC0A80101, 0xC0A80102, 12345, 12345, random_buffer, true
        );
        (void)result;
    }
    double random_time = timer.stop_us();

    // 输出结果
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "HTTP 检测 (" << iterations << " 次):   " << http_time << " us ("
              << (iterations / http_time) << " M ops/sec)\n";
    std::cout << "SIP 检测 (" << iterations << " 次):    " << sip_time << " us ("
              << (iterations / sip_time) << " M ops/sec)\n";
    std::cout << "随机数据检测 (" << iterations << " 次): " << random_time << " us ("
              << (iterations / random_time) << " M ops/sec)\n";
}

// ============================================================================
// 基准测试 5: 解析器性能
// ============================================================================

void benchmark_parsers() {
    std::cout << "\n=== 解析器性能测试 ===\n";

    // HTTP 解析器
    auto http_data = TestDataGenerator::generate_http_request();
    core::BufferView http_buffer(http_data.data(), http_data.size());
    parsers::ParseContext http_ctx{http_buffer};
    parsers::HTTPParser http_parser;

    Timer timer;
    const size_t iterations = 100000;

    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        http_ctx.offset = 0;
        volatile auto result = http_parser.parse(http_ctx);
        (void)result;
    }
    double http_parse_time = timer.stop_us();

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "HTTP 解析 (" << iterations << " 次): " << http_parse_time
              << " us (" << (iterations / http_parse_time) << " M req/sec)\n";

    // SIP 解析器
    auto sip_data = TestDataGenerator::generate_sip_invite();
    core::BufferView sip_buffer(sip_data.data(), sip_data.size());
    parsers::ParseContext sip_ctx{sip_buffer};
    parsers::SipParser sip_parser;

    timer.start();
    for (size_t i = 0; i < iterations; ++i) {
        sip_ctx.offset = 0;
        volatile auto result = sip_parser.parse(sip_ctx);
        (void)result;
    }
    double sip_parse_time = timer.stop_us();

    std::cout << "SIP 解析 (" << iterations << " 次):  " << sip_parse_time
              << " us (" << (iterations / sip_parse_time) << " M req/sec)\n";
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "===========================================\n";
    std::cout << "   协议解析库性能基准测试\n";
    std::cout << "===========================================\n";

    try {
        benchmark_buffer_pool();
        benchmark_simd();
        benchmark_tcp_reassembly();
        benchmark_protocol_detection();
        benchmark_parsers();

        std::cout << "\n===========================================\n";
        std::cout << "   所有测试完成！\n";
        std::cout << "===========================================\n";

    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
