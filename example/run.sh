#!/data/data/com.termux/files/usr/bin/bash
# run.sh — 完整演示：编译 → 加密 → 验证效果
#
# 用法：
#   ./run.sh <你的签名APK>
#
# 或不带参数用自带的测试 APK（仅验证工具链，不代表真实包）
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
cd "$HERE"

NOX="$ROOT/nox"
APK="${1:-$ROOT/fixtures/sample.apk}"
APK=$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")
PKG="${2:-com.nox.fixture}"

mkdir -p build

echo "══════════════════════════════════════════"
echo " 1. 编译（不加密）"
echo "══════════════════════════════════════════"
"$NOX" build mycode.c -o build/plain.so
echo ""

echo "══════════════════════════════════════════"
echo " 2. 编译 + 加密（一条命令）"
echo "══════════════════════════════════════════"
"$NOX" protect mycode.c --apk "$APK" --package "$PKG" -o build/locked.so
echo ""

echo "══════════════════════════════════════════"
echo " 3. 对比：加密前 vs 加密后"
echo "══════════════════════════════════════════"
echo ""
echo "【加密前】algo_checksum 的机器码（一眼看懂在干什么）:"
objdump -d build/plain.so 2>/dev/null | sed -n '/<algo_checksum>:/,+6p' | sed 's/^/    /'
echo ""
echo "【加密后】同一函数:"
if objdump -d build/locked.so 2>/dev/null | grep -q "algo_checksum"; then
    objdump -d build/locked.so 2>/dev/null | sed -n '/<algo_checksum>:/,+6p' | sed 's/^/    /'
else
    echo "    （函数已不可反汇编 —— 段内是密文）"
fi
echo ""
echo "【段结构】"
readelf -SW build/locked.so 2>/dev/null | grep -E "\.ncx|\.ncxhr" | sed 's/^/    /'
echo ""
echo "【符号表】$(nm build/locked.so 2>/dev/null | wc -l) 个符号（strip 后应为 0）"
echo ""
echo "══════════════════════════════════════════"
echo " 4. 运行验证（模拟已安装环境）"
echo "══════════════════════════════════════════"
mkdir -p "run/$PKG/lib/arm64-v8a"
cp build/locked.so "run/$PKG/lib/arm64-v8a/libdemo.so"
cp "$APK" "run/$PKG/base.apk"

# 驱动不需要手动调 ncguard_unlock —— 库里有 constructor(50)，
# dlopen 时自动解锁（生产也是这个机制）。
# 而且 ncguard_unlock 是内部符号（version script local:*），dlsym 拿不到，
# 这是正确的：外部本来就不该调它。
cat > build/drv.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) { printf("  ✗ dlopen 失败: %s\n", dlerror()); return 2; }
    /* dlopen 成功 + 构造函数跑完 = 解锁链路已走完（失败会 SIGILL/拒绝） */
    int (*f)(void) = dlsym(h, "demo_checksum");
    if (!f) { printf("  ✗ 找不到 demo_checksum\n"); return 3; }
    int got = f();
    printf("  demo_checksum() = %d（期望 1535）\n", got);
    if (got != 1535) return 4;
    /* 再验证一个加密函数能正确执行 */
    int (*g)(int) = dlsym(h, "demo_verify");
    if (g) printf("  demo_verify(0x5A5A) = %d（期望 1）\n", g(0x5A5A));
    return 0;
}
EOF
clang build/drv.c -o build/drv -ldl
( cd "run/$PKG" && bash -c "exec -a $PKG ../../build/drv ./lib/arm64-v8a/libdemo.so" )
echo ""
echo "✅ 全部完成"
