cmake_minimum_required(VERSION 3.20)
project(ProtocolParser VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 检测编译器环境
if(MINGW OR MSYS)
    message(STATUS "使用MinGW/MSYS2编译器")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
    
    # MSYS2特定设置
    if(MSYS)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_WIN32_WINNT=0x0601")
        # 链接Windows库
        link_libraries(ws2_32)
    endif()
elseif(MSVC)
    message(STATUS "使用MSVC编译器")
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_options(/arch:AVX2)  # 启用AVX2支持
else()
    message(STATUS "使用GCC/Clang编译器")
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
    add_compile_options(-march=native)  # 启用本机CPU优化
endif()

# 包含目录
include_directories(include)

# 查找依赖
find_package(Threads REQUIRED)

# 核心库
add_subdirectory(src)

# 示例程序（已禁用）
option(BUILD_EXAMPLES "Build example programs" OFF)
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