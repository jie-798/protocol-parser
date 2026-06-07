@echo off
echo "清理构建目录..."
if exist build rmdir /s /q build
mkdir build
cd build

echo "配置CMake..."
cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON ..
if %errorlevel% neq 0 (
    echo "CMake配置失败!"
    pause
    exit /b 1
)

echo "编译项目..."
cmake --build . --config Release --parallel
if %errorlevel% neq 0 (
    echo "编译失败!"
    pause
    exit /b 1
)

echo "运行测试..."
ctest -C Release --output-on-failure
if %errorlevel% neq 0 (
    echo "测试失败!"
    pause
    exit /b 1
)

echo "编译和测试成功!"
echo "示例程序位置: %CD%\bin\examples\Release\protocol_parser_basic_example.exe"

pause