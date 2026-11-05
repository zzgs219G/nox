#!/usr/bin/env bash
# check-obf.sh — 判断混淆/VMP 到底有没有生效（验【目标文件】，不验 so）
#
# 用法：
#   ./scripts/check-obf.sh                          # 默认查包内 .a（源码树：scripts/so-guard/lib）
#   ./scripts/check-obf.sh <libnox.a>               # 查指定静态库
#   ./scripts/check-obf.sh <某个 .o>                # 直接查单个目标文件
#
# 为什么需要这个脚本（2026-11-06 实测踩过的两个误判）：
#
#   误判 ① 用指令数当判据 → 错。
#     同一个 ncg_xor_key（源码 8 行）三种状态实测：
#         无混淆 -Oz : 指令数 15,  .o 1280 B
#         MBA+FLA    : 指令数 210, .o ~2KB    （文档记录值，未复测）
#         VMP        : 指令数 31,  .o 22720 B, 14 个 VM 子段
#     VMP 的 31 比无混淆的 15 只多 16 条，比 MBA+FLA 的 210 少 7 倍。
#     "数字变小"既可能是被跳过（15），也可能是 VMP（31）→ 不可判。
#
#   误判 ② 在链接后的 libnc.so 上 grep 特征指令 → 全是噪声。
#     一个【确认 VMP】的产物上实测：
#         sub sp,sp,#0xc0        命中 9 处  ← 全是 1.6KB 证书缓冲的普通栈帧
#         movk ..., lsl #48      命中 56 处 ← 第一处是 "APK Sig "/"Block 42"
#                                              （APK 签名块 magic，来自 nc_guard_key.c）
#     链接后 nc_guard_key.c 会贡献同样的指令，信噪比接近 0。
#
#   可靠判据只有一个：目标文件里有没有 VM 子段（.text..L.L__<hash> 等）。
#   只有 VMP 才会把解释器/字节码/常量池拆成独立命名单元，普通编译不产生。
#
# 退出码：0 = 至少一个函数确认 VMP 生效；1 = 未检出 VMP；2 = 用法/环境错误
set -uo pipefail

RED=''; GRN=''; YEL=''; RST=''
if [ -t 1 ]; then RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'; fi
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*"; }
warn() { printf '  %s⚠%s %s\n' "$YEL" "$RST" "$*"; }

# ── 定位工具（Termux 上是 llvm-*；NDK 里也有一套）─────────────────
_llvm() {
    local n="$1"
    if command -v "$n" >/dev/null 2>&1; then command -v "$n"; return 0; fi
    for p in "${ANDROID_NDK_HOME:-}/toolchains/llvm/prebuilt"/*/bin/"$n"; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}
READELF=$(_llvm llvm-readelf) || READELF=$(command -v readelf) || true
OBJDUMP=$(_llvm llvm-objdump) || OBJDUMP=$(command -v objdump) || true
NM=$(_llvm llvm-nm) || NM=$(command -v nm) || true
AR=$(_llvm llvm-ar) || AR=$(command -v ar) || true

for t in "$READELF" "$OBJDUMP" "$NM" "$AR"; do
    [ -n "$t" ] || { echo "✗ 缺 readelf/objdump/nm/ar 之一，无法检查" >&2; exit 2; }
done

here=$(cd "$(dirname "$0")" && pwd)
TARGET="${1:-}"

# 默认目标：包内/仓库内的 .a（两种布局都试）
if [ -z "$TARGET" ]; then
    for c in "$here/../scripts/so-guard/lib/arm64-v8a/libnox.a" \
             "$here/so-guard/lib/arm64-v8a/libnox.a" \
             "$here/../so-guard/lib/arm64-v8a/libnox.a"; do
        [ -f "$c" ] && { TARGET=$c; break; }
    done
fi
[ -n "$TARGET" ] && [ -f "$TARGET" ] || {
    echo "✗ 找不到目标（指定一个 .a 或 .o）" >&2
    echo "  用法: $0 <libnox.a|某个.o>" >&2
    exit 2
}

W=$(mktemp -d "${TMPDIR:-/tmp}/check-obf.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT

# ── 展开目标：.a → 抽出成员；.o → 直接检查 ─────────────────────────
objs=()
case "$TARGET" in
    *.a)
        ( cd "$W" && "$AR" x "$TARGET" ) || { echo "✗ ar x 失败: $TARGET" >&2; exit 2; }
        for f in "$W"/*.o; do [ -f "$f" ] && objs+=("$f"); done
        echo "静态库: $TARGET"
        echo "成员  : $(cd "$W" && ls *.o 2>/dev/null | tr '\n' ' ')"
        ;;
    *.o)
        objs=("$TARGET")
        echo "目标文件: $TARGET"
        ;;
    *)
        echo "✗ 不认识的文件类型（要 .a 或 .o）: $TARGET" >&2; exit 2 ;;
esac
[ ${#objs[@]} -gt 0 ] || { echo "✗ 静态库里没有 .o 成员" >&2; exit 2; }

echo ""
echo "── 逐目标文件：VM 子段数（唯一可靠判据）──"
vmp_hits=0
for o in "${objs[@]}"; do
    name=$(basename "$o")
    # .text..L.L__<16 hex> / .rodata..L.L__<16 hex> 等，均为 VMP 生成
    nsub=$("$READELF" -SW "$o" 2>/dev/null | grep -c 'L\.L__' || true)
    size=$(stat -c%s "$o" 2>/dev/null || echo 0)
    if [ "${nsub:-0}" -gt 0 ]; then
        ok "$(printf '%-24s %7d B   VM 子段 %s' "$name" "$size" "$nsub")"
        vmp_hits=$((vmp_hits+1))
    else
        printf '  %s  %-24s %7d B   VM 子段 0\n' '·' "$name" "$size"
    fi
done

# ── 对确认 VMP 的目标文件，给出函数级明细 ──────────────────────────
if [ "$vmp_hits" -gt 0 ]; then
    echo ""
    echo "── VMP 目标文件里各函数本体的指令数（仅供参考，不能当判据）──"
    for o in "${objs[@]}"; do
        nsub=$("$READELF" -SW "$o" 2>/dev/null | grep -c 'L\.L__' || true)
        [ "${nsub:-0}" -gt 0 ] || continue
        echo "  $(basename "$o"):"
        # 列出该目标文件里的所有函数符号（T/t）
        "$NM" --defined-only "$o" 2>/dev/null | awk '$2 ~ /^[Tt]$/ {print $3}' > "$W/fns.txt"
        while read -r fn; do
            [ -n "$fn" ] || continue
            n=$("$OBJDUMP" -d --disassemble-symbols="$fn" "$o" 2>/dev/null \
                | grep -cE '^\s+[0-9a-f]+:' || true)
            printf '    %-28s %5s 条指令\n' "$fn" "${n:-0}"
        done < "$W/fns.txt"
        # VM 子段清单（去重，前 6 个，够看出结构）
        "$READELF" -SW "$o" 2>/dev/null | grep -o '[.][a-z]*[.]*[.]L[.]L__[0-9a-f]*' \
            | sort -u | head -6 | while read -r s; do
                printf '    段 %s\n' "$s"
            done
    done
fi

echo ""
echo "── 结论 ──"
if [ "$vmp_hits" -gt 0 ]; then
    ok "$vmp_hits 个目标文件确认 VMP 生效（有 VM 子段）"
    echo ""
    echo "  ⛔ 不要再用下面这两条（在 libnc.so 上命中全是无关代码）："
    echo "     objdump -d libnc.so | grep -c 'sub sp, sp, #0xc0'"
    echo "     objdump -d libnc.so | grep -c 'movk.*lsl #48'"
    exit 0
else
    bad "未检出 VMP（所有目标文件 VM 子段数 = 0）"
    echo ""
    echo "  排查顺序："
    echo "    ① 编译时是否带 AMICE_VM_VIRTUALIZE / -fpass-plugin=libamice.so"
    echo "    ② RUST_LOG=amice=debug 重编，grep 'skip function'"
    echo "       → 'has non-call address uses' = annotate 与 VMP 互斥（见流程文档 4.3.4①）"
    echo "    ③ 插件与 clang 主版本是否匹配（错配是 SIGSEGV 不是报错）"
    exit 1
fi
