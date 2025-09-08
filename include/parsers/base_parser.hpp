#pragma once

#include "core/buffer_view.hpp"
#include <memory>
#include <string>
#include <unordered_map>
#include <functional>
#include <expected>
#include <any>

namespace protocol_parser::parsers {

// 简化类型引用的using声明
using BufferView = core::BufferView;

/**
 * 解析结果枚举
 */
enum class ParseResult {
    Success,           // 解析成功
    NeedMoreData,      // 需要更多数据
    InvalidFormat,     // 格式错误
    UnsupportedVersion,// 不支持的版本
    BufferTooSmall,    // 缓冲区太小
    InternalError      // 内部错误
};

/**
 * 解析器状态枚举
 */
enum class ParserState {
    Initial,    // 初始状态
    Parsing,    // 解析中
    Complete,   // 解析完成
    Error       // 错误状态
};

/**
 * 协议信息结构
 */
struct ProtocolInfo {
    std::string name;           // 协议名称
    uint16_t type;              // 协议类型
    size_t header_size;         // 头部大小
    size_t min_packet_size;     // 最小包大小
    size_t max_packet_size;     // 最大包大小
};

/**
 * 解析上下文
 */
struct ParseContext {
    BufferView buffer;    // 数据缓冲区
    size_t offset = 0;          // 当前偏移
    ParserState state = ParserState::Initial;
    std::unordered_map<std::string, std::any> metadata;  // 元数据
};

/**
 * 解析器基类
 * 提供状态机框架和通用解析接口
 */
class BaseParser {
public:
    virtual ~BaseParser() = default;
    
    /**
     * 获取协议信息
     */
    [[nodiscard]] virtual const ProtocolInfo& get_protocol_info() const noexcept = 0;
    
    /**
     * 检查是否可以解析给定的缓冲区
     * @param buffer 数据缓冲区
     * @return 如果可以解析返回true，否则返回false
     */
    [[nodiscard]] virtual bool can_parse(const BufferView& buffer) const noexcept = 0;
    
    /**
     * 解析数据包
     * @param context 解析上下文
     * @return 解析结果
     */
    virtual ParseResult parse(ParseContext& context) noexcept = 0;
    
    /**
     * 重置解析器状态
     */
    virtual void reset() noexcept = 0;
    
    /**
     * 获取解析进度（0.0-1.0）
     */
    [[nodiscard]] virtual double get_progress() const noexcept { return 0.0; }
    
    /**
     * 获取错误信息
     */
    [[nodiscard]] virtual std::string get_error_message() const noexcept { return ""; }
    
protected:
    /**
     * 状态转换函数类型
     */
    using StateTransition = std::function<ParseResult(ParseContext&)>;
    
    /**
     * 状态机实现
     */
    struct StateMachine {
        ParserState current_state = ParserState::Initial;
        std::unordered_map<ParserState, StateTransition> transitions;
        
        ParseResult execute(ParseContext& context) {
            auto it = transitions.find(current_state);
            if (it != transitions.end()) {
                return it->second(context);
            }
            return ParseResult::InternalError;
        }
        
        void set_state(ParserState new_state) {
            current_state = new_state;
        }
    };
    
    StateMachine state_machine_;
    std::string error_message_;
};

/**
 * 解析器工厂基类
 */
class ParserFactory {
public:
    virtual ~ParserFactory() = default;
    
    /**
     * 创建解析器实例
     */
    virtual std::unique_ptr<BaseParser> create_parser() = 0;
    
    /**
     * 获取支持的协议类型
     */
    [[nodiscard]] virtual std::vector<uint16_t> get_supported_types() const = 0;
};

/**
 * 解析器注册表
 */
class ParserRegistry {
public:
    static ParserRegistry& instance();
    
    /**
     * 注册解析器工厂
     */
    void register_factory(uint16_t protocol_type, std::unique_ptr<ParserFactory> factory);
    
    /**
     * 创建指定类型的解析器
     */
    [[nodiscard]] std::unique_ptr<BaseParser> create_parser(uint16_t protocol_type);
    
    /**
     * 获取所有支持的协议类型
     */
    [[nodiscard]] std::vector<uint16_t> get_supported_types() const;
    
private:
    std::unordered_map<uint16_t, std::unique_ptr<ParserFactory>> factories_;
};

/**
 * 解析器注册宏
 */
#define REGISTER_PARSER(type, factory_class) \
    namespace { \
        struct factory_class##_registrar { \
            factory_class##_registrar() { \
                ParserRegistry::instance().register_factory(type, std::make_unique<factory_class>()); \
            } \
        }; \
        static factory_class##_registrar factory_class##_registrar_instance; \
    }

} // namespace protocol_parser::parsers