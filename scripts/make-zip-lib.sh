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

# ── Amice 混淆（2026-11-06，用户要求）────────────────────────────────
# 为什么在【发布时】混淆而不是消费方编译时：
#   本脚本产出的是 libnox.a（已编译好的机器码），消费方直接链接。
#   Amice 是编译期 LLVM pass，只能在【编译源码】时生效 —— 消费方拿到 .a
#   后已经无法再混淆里面的函数了。
#   这正是之前混淆空转的根因：消费方开了 AMICE_MBA=true，但
#   nc_guard_boot.c 是以 .a 形式链接进来的，插件碰不到它。
#   实测证据（2026-11-05）：ncg_boot_key 里 HKDF 调用处
#   （adrp+add 取 "nc-boot-v1"）在混淆前后的反汇编逐条指令一致。
#
# 用法：设了 AMICE_BUNDLE 就混淆，没设就普通编译（默认，保持向后兼容）
#   AMICE_BUNDLE=/path/to/amice-android-ndk-rXX-linux-x86_64 ./scripts/make-zip-lib.sh
#
# 混淆只作用于带 NC_OBF 标注的函数（nc_guard_boot.c 里的 3 个解密链函数），
# 不是全局 —— 全局混淆会把 RC4/HMAC/ELF 解析也搅乱，收益为零且体积翻倍。
if [[ -n "${AMICE_BUNDLE:-}" ]]; then
    [[ -f "$AMICE_BUNDLE/amice/lib/libamice.so" ]] || {
        echo "✗ AMICE_BUNDLE 指向的目录缺 amice/lib/libamice.so: $AMICE_BUNDLE" >&2
        exit 1
    }
    [[ -d "$AMICE_BUNDLE/amice/llvm-lib" ]] || {
        echo "✗ 缺 amice/llvm-lib —— 插件依赖的 host libLLVM.so 在此（官方 NDK 不含）" >&2
        exit 1
    }
    CFLAGS+=" -DNC_AMICE_ANNOTATE -fpass-plugin=$AMICE_BUNDLE/amice/lib/libamice.so"
    # 打印 pass 的跳过原因（VMP 遇到不支持的函数会静默保留原实现，
    # 没有日志就分不清"混淆生效"和"被跳过"——2026-11-06 实测踩过：
    # ncg_xor_key 的 VMP 指令数反而从 210 降到 15，实际是被跳过+退回原样）
    export RUST_LOG="${RUST_LOG:-amice=debug}"
    echo "▶ Amice 混淆已启用（只作用于 NC_OBF 标注的函数）"
else
    echo "▶ 未设 AMICE_BUNDLE，普通编译（无混淆）"
fi
# ⚠️ 必须包含 nc_guard_jni：它提供 Java_com_nc_link_NcLink_selftest()。
#    jian_box 的 inject-javacheck.py 会注入对 NcLink.selftest() 的调用，
#    缺这个符号 → UnsatisfiedLinkError → Guard 的 .catch 判定"so 缺失"
#    → fail-closed 杀进程（真机实测：装完启动即闪退，logcat 报
#      No implementation found for NcLink.selftest）。
#    这不是可选项 —— 漏了它整包起不来。
# nc_guard_xor（2026-11-06）：XOR_KEY 重组，从 boot.c 拆出以便单独 VMP
LIB_SRCS="nc_guard_boot nc_guard_probe nc_guard_key nc_guard_paths nc_guard_jni nc_guard_xor nc_guard_crypto"

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

    # 混淆时编译器必须来自 bundle 自带的 NDK：
    # Amice 插件按 LLVM 主版本编译，与 NDK clang 严格绑定。错配不是报错，
    # 是段错误（实测 CI 42055440429：clang 18 加载 r29 插件 → exit 139）。
    if [[ -n "${AMICE_BUNDLE:-}" ]]; then
        _bundle_ndk=$(find "$AMICE_BUNDLE" -maxdepth 1 -type d -name 'android-ndk-*' | head -1)
        [[ -n "$_bundle_ndk" ]] || {
            echo "✗ bundle 里找不到自带的 NDK（期望 android-ndk-rXX/）" >&2
            echo "  插件与 NDK clang 必须配套，用别的 NDK 会段错误" >&2
            exit 1
        }
        _bcc=$(ls -d "$_bundle_ndk"/toolchains/llvm/prebuilt/*/bin/"$_tgt" 2>/dev/null | head -1)
        [[ -n "$_bcc" ]] || { echo "✗ bundle NDK 里找不到 $_tgt" >&2; exit 1; }
        CC="$_bcc"
        export LD_LIBRARY_PATH="$AMICE_BUNDLE/amice/llvm-lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi

    _out="$LIBROOT/$abi"
    mkdir -p "$_out"
    echo "[$abi] 编译器: $CC"
    for f in $LIB_SRCS; do
        # shellcheck disable=SC2086
        #
        # ⚠️ VMP 文件清单（2026-11-06）：
        #   VMP 与 annotate 互斥 —— annotate 会把函数地址写进
        #   @llvm.global.annotations，vm_virtualize 判定 "has non-call
        #   address uses" 并跳过（实测 CI 42075245237 的 debug 日志）。
        #   所以这些文件不含 annotate，改用文件级 AMICE_VM_VIRTUALIZE。
        #
        #   判断标准：这个文件里的函数是否【全部】值得保护、且没有会被
        #   VMP 跳过的构造。满足才可以整文件开。
        #     nc_guard_xor     → ncg_xor_key（1 个）
        #     nc_guard_crypto  → ncg_boot_key + ncguard_stub_recover（2 个）
        #   两个都是"造钥匙的配方"，且都已用 check-vmp-eligibility.py 预检
        #   （无取自身地址等 non-call use）。
        #   nc_guard_boot.c 不能进这份清单 —— 它还有 25+ 个无关函数
        #   （含 open/pread/close 重型 I/O），整文件 VMP 会让体积暴涨。
        case "$f" in
            nc_guard_xor|nc_guard_crypto) _vmp=1 ;;
            *) _vmp=0 ;;
        esac
        if [[ "$_vmp" == "1" && -n "${AMICE_BUNDLE:-}" ]]; then
            # ── VMP profile 选择（2026-11-06）──────────────────────────
            # 默认用本仓库自带的 nox-vmp-func（= 官方 ruoke 示例同款配置）：
            #   runtime.scope = func          每函数独立分派运行时
            #   handler_clone = func          每函数独立 handler 副本
            # 而不是 Amice 内置的 amice-simple-vmp（module 级共享）——
            # 后者让 6~7 个受保护函数共用一套解释器/opcode 编码，
            # 攻击者逆一次 VM 语义就能读全部，成本不是 ×N 而是 ×1。
            #
            # ⚠️ 为什么用 AMICE_VM_PROFILE_PATH 而不是 annotate("vm_profile=...")：
            #    annotate 会与 VMP 自身的地址引用检查冲突（本文件上方已说明
            #    两者互斥），所以只能走环境变量这条路。
            # ⚠️ 关掉 nox-vmp-func 的办法：设 AMICE_VMP_PROFILE=simple
            #    回退到内置 profile（体积小一半，但失去函数级隔离）。
            _vmpprof="${AMICE_VMP_PROFILE:-func}"
            if [[ "$_vmpprof" == "func" ]]; then
                _profdir="$GUARD/vmp-profile-func"
                [[ -f "$_profdir/manifest.toml" ]] || {
                    echo "✗ VMP profile 缺失: $_profdir/manifest.toml" >&2
                    echo "  该目录是函数级隔离的配置源，缺了会静默退回 module 共享" >&2
                    echo "  如需回退：AMICE_VMP_PROFILE=simple" >&2
                    exit 1
                }
                AMICE_VM_VIRTUALIZE=true AMICE_VM_PROFILE_PATH="$_profdir" \
                    "$CC" -c $CFLAGS "$GUARD/$f.c" -o "$_out/$f.o"
            else
                AMICE_VM_VIRTUALIZE=true "$CC" -c $CFLAGS "$GUARD/$f.c" -o "$_out/$f.o"
            fi
        else
            "$CC" -c $CFLAGS "$GUARD/$f.c" -o "$_out/$f.o"
        fi
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
# VMP profile（2026-11-06）：函数级隔离的配置源。
# ⚠️ 必须随包发：消费方的源码形态若自己开混淆（protect.sh 的 AMICE_BUNDLE
#    分支）需要它；且 amice bundle 里【不含】profile 源码（profile 是编进
#    libamice.so 的），所以只能我们提供。
# ⚠️ 体积 628 KB（isa.vm 184K + lowering.vm 420K），压完约 60 KB。
#    不能省：缺了它 make-zip-lib.sh 会 fail-fast（见 VMP 分支的检查）。
if [ -d scripts/so-guard/vmp-profile-func ]; then
    cp -R scripts/so-guard/vmp-profile-func "$STAGE/so-guard/"
fi
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

# 混淆相关的验收工具（2026-11-06）
# 为什么必须进包：这两个脚本的用途是"验产物"，而消费方拿到的正是产物。
# 不发的话，消费方无法确认自己手里的 .a 到底有没有 VMP —— 而那正是
# 本项目最容易误判的一点（曾在确认 VMP 的产物上，用 grep 特征指令的
# 办法得出完全相反的结论；正确判据是看目标文件的 VM 子段数）。
mkdir -p "$STAGE/scripts"
cp scripts/check-obf.sh scripts/check-vmp-eligibility.py "$STAGE/scripts/"
chmod +x "$STAGE/scripts/check-obf.sh" "$STAGE/scripts/check-vmp-eligibility.py"

# 版本标记：解压后 `cat nox/VERSION` 即知版本，不用回仓库查 tag。
# 消费者（artifact-pipeline 的 ensure_nox）也靠它做版本校验与日志。
printf '%s\n' "$VER" > "$STAGE/VERSION"

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
