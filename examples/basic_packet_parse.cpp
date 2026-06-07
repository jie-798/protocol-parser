#include "core/buffer_view.hpp"
#include "parsers/datalink/ethernet_parser.hpp"

#include <any>
#include <array>
#include <iomanip>
#include <iostream>

int main() {
    const std::array<uint8_t, 18> frame{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14
    };

    protocol_parser::core::BufferView buffer(frame.data(), frame.size());
    protocol_parser::parsers::ParseContext context{buffer};
    protocol_parser::parsers::EthernetParser parser;

    if (parser.parse(context) != protocol_parser::parsers::ParseResult::Success) {
        std::cerr << "failed to parse ethernet frame\n";
        return 1;
    }

    const auto result = std::any_cast<protocol_parser::parsers::EthernetParseResult>(
        context.metadata.at("ethernet_result")
    );

    std::cout << "ether_type=0x" << std::hex << result.next_protocol
              << " payload_size=" << std::dec << result.payload.size() << '\n';
    return 0;
}
