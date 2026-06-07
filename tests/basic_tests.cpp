#include "core/buffer_view.hpp"
#include "core/buffer_pool.hpp"
#include "core/tcp_reassembler.hpp"
#include "utils/simd_utils.hpp"
#include "parsers/datalink/arp_parser.hpp"
#include "parsers/datalink/ethernet_parser.hpp"
#include "parsers/security/tls_deep_inspector.hpp"
#include "parsers/base_parser.hpp"

#include <algorithm>
#include <any>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string_view>

using protocol_parser::core::BufferPool;
using protocol_parser::core::BufferView;
using protocol_parser::core::TcpConnectionTracker;
using protocol_parser::core::TcpReassembler;
using protocol_parser::core::TcpSegment;
using protocol_parser::security::TLSStatistics;
using protocol_parser::utils::SIMDUtils;
using namespace protocol_parser::parsers;

namespace {
int failures = 0;

class DummyParser final : public BaseParser {
public:
    const ProtocolInfo& get_protocol_info() const noexcept override {
        static const ProtocolInfo info{"dummy", 0xF00D, 0, 0, 0};
        return info;
    }

    bool can_parse(const BufferView& buffer) const noexcept override {
        return !buffer.empty();
    }

    ParseResult parse(ParseContext& context) noexcept override {
        context.state = ParserState::Complete;
        return ParseResult::Success;
    }

    void reset() noexcept override {}
};

class DummyFactory final : public ParserFactory {
public:
    std::unique_ptr<BaseParser> create_parser() override {
        return std::make_unique<DummyParser>();
    }

    std::vector<uint16_t> get_supported_types() const override {
        return {0xF00D};
    }
};

void expect(bool condition, const char* expression) {
    if (!condition) {
        std::cerr << "FAILED: " << expression << '\n';
        ++failures;
    }
}
}

#define EXPECT(expression) expect((expression), #expression)

void test_buffer_view_endian_reads() {
    const std::array<uint8_t, 8> bytes{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const BufferView view(bytes.data(), bytes.size());

    EXPECT(view.read_be16(0) == 0x0102);
    EXPECT(view.read_be32(0) == 0x01020304);
    EXPECT(view.read_be64(0) == 0x0102030405060708ULL);
    EXPECT(view.read_le16(0) == 0x0201);
    EXPECT(view.substr(2, 3).size() == 3);
    EXPECT(view.find_simd(0x05) == 4);

    const std::array<uint8_t, 10> haystack{0xaa, 0xbb, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0xaa, 0xbb, 0xcc};
    const std::array<uint8_t, 3> pattern{0xaa, 0xbb, 0xcc};
    const BufferView pattern_view(haystack.data(), haystack.size());
    EXPECT(pattern_view.find_simd(pattern.data(), pattern.size()) == 2);
    EXPECT(pattern_view.find_simd(pattern.data() + 1, 2) == 3);
}

void test_buffer_pool_thread_cache_reuse() {
    BufferPool::Config config;
    config.small_pool_size = 1;
    config.medium_pool_size = 1;
    config.large_pool_size = 1;
    config.extra_large_pool_size = 1;
    config.enable_auto_expand = false;
    config.enable_thread_cache = true;

    BufferPool pool(config);
    auto buffer = pool.acquire(64);
    const auto* first_ptr = buffer.data();
    EXPECT(buffer.size() == 64);
    EXPECT(first_ptr != nullptr);

    pool.release(buffer);
    EXPECT(buffer.data() == nullptr);

    auto cached = pool.acquire(64);
    EXPECT(cached.data() == first_ptr);
    EXPECT(pool.get_statistics().cache_hits == 1);
    pool.release(cached);

    std::array<uint8_t, 16> external_storage{};
    BufferView external(external_storage.data(), external_storage.size());
    const auto before_external_release = pool.get_statistics();
    pool.release(external);
    EXPECT(external.data() == nullptr);
    EXPECT(pool.get_statistics().total_deallocations == before_external_release.total_deallocations);

    auto advanced = pool.acquire(1000);
    const auto* advanced_base = advanced.data();
    EXPECT(advanced.safe_advance(10));
    pool.release(advanced);
    auto reacquired = pool.acquire(1000);
    EXPECT(reacquired.data() == advanced_base);
    pool.release(reacquired);
}

void test_crc32_checksums() {
    constexpr std::string_view input = "123456789";
    const auto* data = reinterpret_cast<const uint8_t*>(input.data());

    EXPECT(SIMDUtils::crc32(data, input.size()) == 0xCBF43926U);
    EXPECT(SIMDUtils::crc32c(data, input.size()) == 0xE3069283U);

    constexpr std::string_view first = "1234";
    constexpr std::string_view second = "56789";
    uint32_t crc = SIMDUtils::crc32(reinterpret_cast<const uint8_t*>(first.data()), first.size());
    crc = SIMDUtils::crc32_append(crc, reinterpret_cast<const uint8_t*>(second.data()), second.size());
    EXPECT(crc == SIMDUtils::crc32(data, input.size()));
}

void test_tcp_reassembler_overlapping_segments() {
    constexpr std::string_view first_payload = "abcdef";
    constexpr std::string_view overlap_payload = "defghi";

    TcpReassembler reassembler;
    reassembler.set_initial_sequence(99);
    TcpSegment overlap_segment{
        103,
        BufferView(overlap_payload.data(), overlap_payload.size()),
        false,
        false
    };
    EXPECT(!reassembler.add_segment(overlap_segment));

    TcpSegment first_segment{
        100,
        BufferView(first_payload.data(), first_payload.size()),
        false,
        false
    };
    EXPECT(reassembler.add_segment(first_segment));

    const auto data_view = reassembler.get_data();
    EXPECT(data_view.as_string_view() == "abcdefghi");
    EXPECT(reassembler.get_segments().empty());
}

void test_tcp_connection_tracker_cleanup() {
    TcpConnectionTracker tracker(0);
    const TcpConnectionTracker::ConnectionKey key{0x0a000001, 0x0a000002, 12345, 80, true};

    (void)tracker.get_reassembler(key, TcpConnectionTracker::Direction::ClientToServer);
    EXPECT(tracker.connection_count() == 1);

    tracker.cleanup_old_connections();
    EXPECT(tracker.connection_count() == 0);
}

void test_tls_statistics_snapshot_copy() {
    TLSStatistics stats;
    stats.record_connection(true);
    stats.handshake_messages++;
    stats.version_counts[0x0304] = 1;

    TLSStatistics snapshot = stats;
    EXPECT(snapshot.total_connections.load() == 1);
    EXPECT(snapshot.successful_handshakes.load() == 1);
    EXPECT(snapshot.handshake_messages.load() == 1);
    EXPECT(snapshot.version_counts.at(0x0304) == 1);

    TLSStatistics assigned;
    assigned = stats;
    EXPECT(assigned.total_connections.load() == 1);
    EXPECT(assigned.successful_handshakes.load() == 1);
}

void test_parser_registry_factory_round_trip() {
    auto& registry = ParserRegistry::instance();
    registry.register_factory(0xF00D, std::make_unique<DummyFactory>());

    auto parser = registry.create_parser(0xF00D);
    EXPECT(parser != nullptr);
    EXPECT(parser->get_protocol_info().name == "dummy");
    EXPECT(registry.create_parser(0xF00E) == nullptr);

    const auto supported_types = registry.get_supported_types();
    EXPECT(std::find(supported_types.begin(), supported_types.end(), 0xF00D) != supported_types.end());
}

void test_ethernet_parser_reuse() {
    const std::array<uint8_t, 18> frame_one{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14
    };
    const std::array<uint8_t, 18> frame_two{
        0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x06,
        0x00, 0x01, 0x08, 0x00
    };

    EthernetParser parser;

    ParseContext first_context{BufferView(frame_one.data(), frame_one.size())};
    EXPECT(parser.parse(first_context) == ParseResult::Success);
    const auto first_result = std::any_cast<EthernetParseResult>(first_context.metadata.at("ethernet_result"));
    EXPECT(first_result.next_protocol == EtherType::IPv4);
    EXPECT(first_result.payload.size() == 4);

    ParseContext second_context{BufferView(frame_two.data(), frame_two.size())};
    EXPECT(parser.parse(second_context) == ParseResult::Success);
    const auto second_result = std::any_cast<EthernetParseResult>(second_context.metadata.at("ethernet_result"));
    EXPECT(second_result.next_protocol == EtherType::ARP);
    EXPECT(second_result.payload.size() == 4);
}

void test_arp_parser_single_call_completion() {
    const std::array<uint8_t, 28> packet{
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x01,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xc0, 0xa8, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x02
    };

    ARPParser parser;
    ParseContext context{BufferView(packet.data(), packet.size())};

    EXPECT(parser.parse(context) == ParseResult::Success);
    EXPECT(context.offset == packet.size());
    const auto result = std::any_cast<ARPParseResult>(context.metadata.at("arp_result"));
    EXPECT(result.header.is_request());
    EXPECT(result.total_length == packet.size());
}

int main() {
    test_buffer_view_endian_reads();
    test_buffer_pool_thread_cache_reuse();
    test_crc32_checksums();
    test_tcp_reassembler_overlapping_segments();
    test_tcp_connection_tracker_cleanup();
    test_tls_statistics_snapshot_copy();
    test_parser_registry_factory_round_trip();
    test_ethernet_parser_reuse();
    test_arp_parser_single_call_completion();
    return failures == 0 ? 0 : 1;
}
