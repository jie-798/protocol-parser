#include "parsers/base_parser.hpp"
#include <mutex>
#include <unordered_map>

namespace protocol_parser::parsers {

// 解析器注册表实现
ParserRegistry& ParserRegistry::instance() {
    static ParserRegistry registry;
    return registry;
}

void ParserRegistry::register_factory(uint16_t protocol_type, std::unique_ptr<ParserFactory> factory) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    factories_[protocol_type] = std::move(factory);
}

std::unique_ptr<BaseParser> ParserRegistry::create_parser(uint16_t protocol_type) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = factories_.find(protocol_type);
    if (it != factories_.end()) {
        return it->second->create_parser();
    }
    return nullptr;
}

std::vector<uint16_t> ParserRegistry::get_supported_types() const {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    
    std::vector<uint16_t> types;
    types.reserve(factories_.size());
    
    for (const auto& [type, factory] : factories_) {
        types.push_back(type);
    }
    
    return types;
}

} // namespace protocol_parser::parsers