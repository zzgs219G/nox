#!/usr/bin/env bash
# make-static-lib.sh — 把加密设施编译成静态库 libnox.a
#
# 为什么需要它：
#   直接发源码意味着任何拿到 zm 的人都读得到全部实现（含 slot 布局、
#   密钥派生、段名契约）。编译成 .a 后，对方拿到的是目标文件，看不见源码。
#
# ⚠️ 三个必须知道的限制：
#
# ① Python 部分无法二进制化。so-section-lock.py（锁箱算法）、
#    so_section_mark.py（段标记器）仍以源码形式分发。所以 C 实现藏住了，
#    但锁箱格式仍然是公开的。
#    要真正保密只能做服务（对方上传 so，你加密后返回）。
#
# ② .a 与 NDK 版本、编译器版本绑定。对方必须用匹配的 clang 编业务代码。
#    用 clang-XX 编的 .o 不能和 clang-YY 混链。
#    → 分发时应明确标注"适用 NDK 版本"，或按 ABI 各发一个 .a。
#
# ③ 链接时必须加 -Wl,--whole-archive。静态库只链接"被引用"的成员，
#    而 nc_guard_boot.o 的入口是 constructor（无人显式调用），会被整个
#    丢弃。实测：
#        不加：35464 字节 → 5368 字节，加密段 5 个 → 1 个，
#             连 ncguard_unlock 都不见了
#        加了：正常
#    本工具的 --use-static-lib 已自动加这个参数。
#
# 用法：
#     ./make-static-lib.sh                          # 默认当前 clang
#     ANDROID_NDK_HOME=/path/to/ndk ./make-static-lib.sh arm64-v8a
#
# 产物：
#     lib/libnox.a          （默认）
#     lib/arm64-v8a/libnox.a （指定 ABI 时）
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)
GUARD="$ROOT/so-guard"
OUTDIR="$ROOT/lib"

ABI="${1:-host}"
case "$ABI" in
    host)
        CC="${CC:-clang}"
        ;;
    arm64-v8a)
        : "${ANDROID_NDK_HOME:?需要 ANDROID_NDK_HOME}"
        P="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"
        B=$(ls -d "$P"/*/bin/aarch64-linux-android21-clang 2>/dev/null | head -1)
        [ -n "$B" ] || { echo "✗ NDK 里找不到 aarch64 clang"; exit 1; }
        CC="$B"; OUTDIR="$OUTDIR/arm64-v8a"
        ;;
    armeabi-v7a)
        : "${ANDROID_NDK_HOME:?需要 ANDROID_NDK_HOME}"
        P="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"
        B=$(ls -d "$P"/*/bin/armv7a-linux-androideabi21-clang 2>/dev/null | head -1)
        [ -n "$B" ] || { echo "✗ NDK 里找不到 armv7 clang"; exit 1; }
        CC="$B"; OUTDIR="$OUTDIR/armeabi-v7a"
        ;;
    *)
        echo "用法: $0 [host|arm64-v8a|armeabi-v7a]"; exit 2 ;;
esac

echo "编译器: $CC"
echo "输出:   $OUTDIR/libnox.a"

mkdir -p "$OUTDIR/bld"
cd "$OUTDIR/bld"

# 编译参数与 nox 的 CFLAGS_BASE 保持一致（否则行为不同）
#   -fvisibility=hidden  内部符号不外泄（.a 里看不到 ncg_* 的导出面）
#   -fno-ident           去编译器指纹
#   -ffunction/data-sections 配 --gc-sections 瘦身
CFLAGS="-fPIC -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED \
        -I$GUARD"

rm -f *.o
for f in nc_guard_boot nc_guard_probe nc_guard_key nc_guard_paths; do
    # shellcheck disable=SC2086
    "$CC" -c $CFLAGS "$GUARD/$f.c" -o "$f.o"
    printf "  %-20s %s 字节\n" "$f.o" "$(stat -c%s "$f.o")"
done

if command -v llvm-ar >/dev/null 2>&1; then
    AR=llvm-ar
elif command -v ar >/dev/null 2>&1; then
    AR=ar
else
    echo "✗ 找不到 ar / llvm-ar，无法打包静态库"; exit 1
fi
rm -f "$OUTDIR/libnox.a"
"$AR" rcs "$OUTDIR/libnox.a" *.o

echo ""
echo "✅ $OUTDIR/libnox.a ($(stat -c%s "$OUTDIR/libnox.a") 字节)"
echo ""
echo "自查（对方链接时这些符号可见）："
nm "$OUTDIR/libnox.a" 2>/dev/null | grep -c " T \| D " | sed 's/^/  全局符号数: /'
echo ""
echo "对方这样用："
echo "  clang -fPIC -shared -Oz your.c \\"
echo "        -Wl,--whole-archive $OUTDIR/libnox.a -Wl,--no-whole-archive \\"
echo "        -I$GUARD -o libyour.so"
echo "  （或用 nox 的 --use-static-lib，它会自动加参数）"
