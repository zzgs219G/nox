#!/usr/bin/env bash
# make-zip-lib.sh — 打【静态库形态】发行包
#
# 用法：ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-lib.sh [版本号]
#
# 产出：dist/nox-<版本>.zip
#
# 本脚本做两件事（一条命令走完，不需要额外前置步骤）：
#   ① 把 so-guard/*.c 交叉编译成双 ABI 静态库 libnox.a
#   ② 打包：只发 头文件 + Python 工具 + .a，【不发 C 源码】
#
# 与本目录 make-zip-src.sh 的区别（两套并存，按需选用）：
#   make-zip-src.sh  → 发 so-guard/*.c 源码（给要改代码/审查的人）
#   make-zip-lib.sh  → 只发 so-guard/*.h + *.py + lib/<abi>/libnox.a
#
# ⚠️ 三个必须知道的限制（如实，别高估）：
#   ① Python 无法二进制化：so-section-lock.py（锁箱算法）、so_section_mark.py
#      仍是明文。所以 C 实现藏住了，但【锁箱格式依然公开】。
#      要真正保密只能做服务（对方上传 so，服务器加密后返回）。
#   ② .a 与 NDK/编译器版本绑定。用 clang-XX 编的 .o 不能和 clang-YY 混链。
#   ③ 消费方链接时必须加 -Wl,--whole-archive：ncguard_unlock 是 constructor，
#      无人显式引用 → 默认被丢弃。实测"5 个加密段塌成 1 个，连 unlock 都不见了"。
#
# 前置：ANDROID_NDK_HOME 必须指向 NDK（双 ABI 交叉编译要用）。
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
GUARD="$ROOT/scripts/so-guard"
LIBROOT="$ROOT/build-lib"

VER="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
OUT="dist/nox-${VER}.zip"

# ── 1. 编译双 ABI 静态库 ────────────────────────────────────────────
# 编译参数与 nox CLI 的 CFLAGS_BASE 保持一致（否则行为不同）。
#   -fvisibility=hidden        内部符号不外泄（.a 里看不到 ncg_* 导出面）
#   -fno-ident                 去编译器指纹
#   -ffunction/data-sections   配消费方 --gc-sections 瘦身
#   -DNC_GUARD_SECTIONED       启用段标记（不加则 __attribute__((section)) 不生效）
CFLAGS="-fPIC -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED \
        -I$GUARD"
LIB_SRCS="nc_guard_boot nc_guard_probe nc_guard_key nc_guard_paths"

: "${ANDROID_NDK_HOME:?双 ABI 交叉编译需要 ANDROID_NDK_HOME（指向 NDK 根目录）}"
_prebuilt="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"
AR=$(command -v llvm-ar || command -v ar) || {
    echo "✗ 找不到 ar / llvm-ar，无法打包静态库" >&2; exit 1; }

rm -rf "$LIBROOT"
for abi in arm64-v8a armeabi-v7a; do
    case "$abi" in
        arm64-v8a)   _tgt=aarch64-linux-android21-clang ;;
        armeabi-v7a) _tgt=armv7a-linux-androideabi21-clang ;;
    esac
    CC=$(ls -d "$_prebuilt"/*/bin/"$_tgt" 2>/dev/null | head -1)
    [ -n "$CC" ] || { echo "✗ NDK 里找不到 $_tgt" >&2; exit 1; }

    _out="$LIBROOT/$abi"
    mkdir -p "$_out"
    echo "[$abi] 编译器: $CC"
    for f in $LIB_SRCS; do
        # shellcheck disable=SC2086
        "$CC" -c $CFLAGS "$GUARD/$f.c" -o "$_out/$f.o"
        printf "  %-20s %s 字节\n" "$f.o" "$(stat -c%s "$_out/$f.o")"
    done
    "$AR" rcs "$_out/libnox.a" "$_out"/*.o
    rm -f "$_out"/*.o
    echo "  → $_out/libnox.a ($(stat -c%s "$_out/libnox.a") 字节)"
done

# ── 2. 打包 ─────────────────────────────────────────────────────────
echo ""
echo "打包 $OUT ..."
rm -rf dist build-zip
mkdir -p dist build-zip/nox

STAGE="build-zip/nox"

# 工具
cp nox "$STAGE/"
chmod +x "$STAGE/nox"

# 设施：头文件 + Python + 双 ABI 静态库（无 .c）
# ⚠️ 头文件必须发：消费方 protect.sh 要拷它进 NDK 工程，
#    make-sig-hash.sh 要从它抽 NC_SEC_CONST 段名。
# ⚠️ .a 必须按 ABI 分目录：Application.mk 固定
#    APP_ABI := armeabi-v7a arm64-v8a，NDK 只从 <abi>/ 子目录取库。
#    放错层级 = 链接期找不到 = 空壳 so。
mkdir -p "$STAGE/so-guard/lib"
cp scripts/so-guard/*.h scripts/so-guard/*.py "$STAGE/so-guard/"
rm -rf "$STAGE/so-guard/__pycache__"
cp -R "$LIBROOT"/arm64-v8a "$LIBROOT"/armeabi-v7a "$STAGE/so-guard/lib/"

# 样本与示例
mkdir -p "$STAGE/fixtures"
cp fixtures/sample.c fixtures/make-fixture-apk.py "$STAGE/fixtures/"
if [ -f fixtures/sample.apk ]; then
    cp fixtures/sample.apk "$STAGE/fixtures/"
else
    echo "  ⚠ fixtures/sample.apk 不存在，包内自测将无法零参数运行"
fi

mkdir -p "$STAGE/example"
cp example/mycode.c example/run.sh "$STAGE/example/"
chmod +x "$STAGE/example/run.sh"

# 自测与文档
cp test.sh "$STAGE/"
chmod +x "$STAGE/test.sh"
cp README.md "$STAGE/"
cp AGENTS.md "$STAGE/"   # AI 接手维护时的必读契约

# 包内快速上手说明
cat > "$STAGE/QUICKSTART.md" <<'EOF'
# 三分钟上手（静态库形态）

本包**不含 C 源码**，加密设施以 `so-guard/lib/<abi>/libnox.a` 形式提供。

## 1. 解压并自测

    unzip nox-*.zip && cd nox
    ./test.sh

## 2. 用你自己的代码

    ./nox protect 你的代码.c --apk 你的签名APK -o libyour.so --abi arm64-v8a

## 必须知道的三条

1. **链接必须加 `-Wl,--whole-archive`**
   `ncguard_unlock` 是 constructor，无人显式引用 → 默认会被丢弃。
   不加的后果：加密段 5 个塌成 1 个，连 unlock 都不见了。
   `nox` 工具已自动处理；手工链接时要自己加。

2. **`.a` 与 NDK/编译器版本绑定**
   用 clang-XX 编的 `.o` 不能和 clang-YY 混链。请用配套 NDK 版本。

3. **Python 工具仍是明文**
   `so-section-lock.py`（锁箱算法）无法编译，锁箱格式依然公开。
   本形态藏的是 C 实现，不是锁箱协议。
EOF

# ── 打包 ──
cd build-zip
if command -v zip >/dev/null 2>&1; then
    zip -qr "../$OUT" "nox"
else
    python3 - "$OUT" "nox" <<'PY'
import os, sys, zipfile
out, base = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(os.path.join('..', out), 'w', zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, p)
print('已用 python zipfile 打包')
PY
fi
cd "$ROOT"
rm -rf build-zip

echo ""
echo "✅ $OUT ($(stat -c%s "$OUT") 字节)"
echo ""
echo "包内清单："
if command -v unzip >/dev/null 2>&1; then
    unzip -l "$OUT" | tail -30
else
    python3 -c "
import zipfile,sys
with zipfile.ZipFile('$OUT') as z:
    for i in z.infolist(): print('  %8d  %s' % (i.file_size, i.filename))
"
fi
