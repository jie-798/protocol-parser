@echo off
echo "清理构建目录..."
if exist build rmdir /s /q build
mkdir build
cd build

echo "配置CMake..."
cmake -G "Visual Studio 17 2022" -A x64 ..
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

echo "编译成功!"
echo "可执行文件位置: build\bin\examples\"

pause