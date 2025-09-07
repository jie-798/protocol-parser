cmake_minimum_required(VERSION 3.20)
project(ProtocolParser VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译选项
if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_options(/arch:AVX2)  # 启用AVX2支持
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
    add_compile_options(-march=native)  # 启用本机CPU优化
endif()

# 包含目录
include_directories(include)

# 查找依赖
find_package(Threads REQUIRED)

# 核心库
add_subdirectory(src)

# 示例程序
option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# 测试 (暂时禁用，目录不存在)
# option(BUILD_TESTS "Build tests" ON)
# if(BUILD_TESTS)
#     enable_testing()
#     add_subdirectory(tests)
# endif()

# 插件 (暂时禁用，目录不存在)
# option(BUILD_PLUGINS "Build plugins" ON)
# if(BUILD_PLUGINS)
#     add_subdirectory(plugins)
# endif()