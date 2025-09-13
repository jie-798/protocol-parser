#!/bin/bash
# MSYS2/UCRT64 编译脚本

echo "检测编译环境..."
if [[ "$MSYSTEM" == "UCRT64" ]]; then
    echo "✓ 检测到UCRT64环境"
else
    echo "⚠ 警告: 当前不在UCRT64环境中，建议使用: pacman -S mingw-w64-ucrt-x86_64-gcc"
fi

echo "检查必要的工具..."
if ! command -v cmake &> /dev/null; then
    echo "❌ 未找到cmake，请安装: pacman -S mingw-w64-ucrt-x86_64-cmake"
    exit 1
fi

if ! command -v g++ &> /dev/null; then
    echo "❌ 未找到g++，请安装: pacman -S mingw-w64-ucrt-x86_64-gcc"
    exit 1
fi

echo "✓ 编译工具检查完成"

# 清理并创建构建目录
echo "清理构建目录..."
rm -rf build
mkdir -p build
cd build

echo "配置CMake..."
cmake -G "MinGW Makefiles" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_C_COMPILER=gcc \
      ..

if [ $? -ne 0 ]; then
    echo "❌ CMake配置失败!"
    exit 1
fi

echo "开始编译..."
cmake --build . --parallel $(nproc)

if [ $? -eq 0 ]; then
    echo "✅ 编译成功!"
    echo "可执行文件位置: build/bin/examples/"
    
    # 列出生成的可执行文件
    if [ -d "bin/examples" ]; then
        echo "生成的示例程序:"
        ls -la bin/examples/
    fi
else
    echo "❌ 编译失败!"
    exit 1
fi