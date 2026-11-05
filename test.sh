#!/usr/bin/env bash
# test.sh — nox 自测（不需要外部项目，不需要编造数据）
#
# 用法：
#   ./test.sh <已签名APK>
#
# 例：
#   ./test.sh "/storage/emulated/0/xxx/简盒_sign.apk"
#
# 为什么需要 APK：加密用的密钥从 APK 证书派生（这是设计，不是限制）。
# 没有 APK 就无法验证"解密链路真的通"，只能验证"能编译"。
#
# 覆盖 6 项：
#   V1 能编译（零外部依赖）
#   V2 五个段齐全
#   V3 锁箱后 .ncx 确实是密文（熵值）
#   V4 路径明文扫不到
#   V5 篡改密文 → 拒绝解密（MAC 生效）
#   V6 完整解锁 → 段代码可执行（需 APK，核心项）
set -uo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

# 加密设施目录：两种布局都要支持，否则测试在其中一个环境里跑不了。
#   · 源码树（本仓库）：<root>/scripts/so-guard/
#   · 发布包（zip 解压）：<root>/so-guard/  （打包时摊回平级）
# 判据不能只看 .c —— 静态库形态的包里没有 .c，只有 .h + lib/<abi>/libnox.a。
GUARD_DIR=""
for _c in "$ROOT/scripts/so-guard" "$ROOT/so-guard"; do
    if [ -f "$_c/nc_guard_layout.h" ]; then GUARD_DIR="$_c"; break; fi
done
if [ -z "$GUARD_DIR" ]; then
    echo "✗ 找不到加密设施目录（试过 scripts/so-guard 与 so-guard）"; exit 1
fi

APK="${1:-}"
SAMPLE_C="$ROOT/fixtures/sample.c"
LOCK="$GUARD_DIR/so-section-lock.py"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $*"; }
skip() { echo "  ⚠ $*（跳过）"; }

# 未传参时自动用仓库内的 fixture（专用测试包，与任何真实发布包无关）
if [ -z "$APK" ]; then
    APK="$ROOT/fixtures/sample.apk"
    if [ ! -f "$APK" ]; then
        echo "缺少 $APK，先生成："
        echo "  python3 fixtures/make-fixture-apk.py fixtures/sample.apk"
        exit 1
    fi
    echo "（未指定 APK，使用 fixtures/sample.apk）"
fi
if [ ! -f "$APK" ]; then
    echo "✗ APK 不存在: $APK"; exit 1
fi
if ! command -v clang >/dev/null 2>&1; then
    echo "✗ 缺 clang，无法测试"; exit 1
fi

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# 测试用的业务代码：一个函数进加密段，一个不进
# 业务代码用 fixtures/sample.c（与文档示例同一份，避免"文档与测试不一致"）
if [ ! -f "$SAMPLE_C" ]; then
    echo "✗ 缺 $SAMPLE_C"; exit 1
fi
cp "$SAMPLE_C" "$W/biz.c"
# sample.c 里的函数没加 visibility("default")（那是对的——纯内部函数不该
# 导出，否则函数名会留在 .dynstr 里被 strings 扫到）。
# 但测试要用 dlsym 拿函数指针来验证"解密后的代码算得对"，
# 故额外附加一个仅测试用的导出表，不动 sample.c 本身。
# ⚠️ 测试壳必须放在【独立编译单元】里（实测踩过两次）：
#   ① 不加 noinline → -Oz 把 secret_calc 整个内联进壳，壳变成明文实现，
#      调壳永远成功，篡改也测不出来（假绿）
#   ② 加了 noinline 仍不够 → 同一个 TU 内编译器照样跨函数内联，实测
#      编译产物里仍是 `mov w8,#0x5a; eor; add; ret`，没有 bl
#   只有拆到另一个 .c（这里用 extern 声明 + 单独编译）才会真正
#   在链接期解析到 .ncx 里的实现，产物是 `b <secret_calc@plt>`。
cat > "$W/tshell.c" <<'EOF'
/* 仅测试用：把加密段里的函数暴露成可 dlsym 的符号。
 * extern 声明 + 独立 TU，确保不被内联。生产代码不需要这一段。 */
extern int secret_calc(int a);
extern int plain_add(int a, int b);

__attribute__((visibility("default"), noinline))
int test_call_secret_calc(int a) { return secret_calc(a); }

__attribute__((visibility("default"), noinline))
int test_call_plain_add(int a, int b) { return plain_add(a, b); }
EOF

echo "=== nox 自测（$(basename "$APK")）==="
echo ""

# ── 设施链接方式 ───────────────────────────────────────────────
# 两种分发形态都要能自测：
#   · 源码形态：把 so-guard/*.c 一起编（宿主 clang，产物可在本机执行）
#   · 静态库形态：只有 so-guard/lib/<abi>/libnox.a（ARM 机器码）
#
# ⚠️ 静态库形态的两个硬约束（v0.4.0 CI 实测踩过）：
#   ① 必须用【NDK 交叉编译器】编：宿主 x86_64 的 ld 链接 ARM 的 .a 会报
#      "Relocations in generic ELF (EM: 183)"，产不出东西。
#   ② 产出的 so 是 ARM，宿主【跑不起来】：所以 V5/V6/V7 这些依赖 dlopen
#      执行的断言必须跳过（无法在本机验证），只验静态属性（段表/熵值/
#      strings）。执行类验证由消费方在真机或 arm64 runner 上做。
GUARD_INC="-I$GUARD_DIR"
HAS_SRC=0
[ -f "$GUARD_DIR/nc_guard_boot.c" ] && HAS_SRC=1

# 静态库形态：选 ABI + 找 NDK 交叉编译器
STATIC_LIB=""
STATIC_CC=""
STATIC_ABI=""
CAN_EXEC=1                      # 产物能否在本机执行（源码形态=1，.a 形态=0）
if [ "$HAS_SRC" = "0" ]; then
    CAN_EXEC=0
    case "$(uname -m)" in
        aarch64|arm64) _host_abi=arm64-v8a ; _tgt=aarch64-linux-android21-clang ;;
        armv7l|armv8l) _host_abi=armeabi-v7a; _tgt=armv7a-linux-androideabi21-clang ;;
        *)             _host_abi="" ;        _tgt="" ;;
    esac
    # 优先宿主原生 ABI（能在本机执行）；否则取第一个可用的（只验静态属性）
    if [ -n "$_host_abi" ] && [ -f "$GUARD_DIR/lib/$_host_abi/libnox.a" ]; then
        STATIC_ABI="$_host_abi"; STATIC_LIB="$GUARD_DIR/lib/$_host_abi/libnox.a"
    else
        STATIC_LIB=$(ls "$GUARD_DIR"/lib/*/libnox.a 2>/dev/null | head -1)
        [ -n "$STATIC_LIB" ] && STATIC_ABI=$(basename "$(dirname "$STATIC_LIB")")
    fi
    case "$STATIC_ABI" in
        arm64-v8a)   _tgt=aarch64-linux-android21-clang ;;
        armeabi-v7a) _tgt=armv7a-linux-androideabi21-clang ;;
    esac
    if [ -n "$_tgt" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
        STATIC_CC=$(ls -d "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/"$_tgt" 2>/dev/null | head -1)
    fi
fi

# guard_compile <输出> <源码...>：按可用形态编译
# 源码形态 → 宿主 clang 直接编 .c
# 静态库形态 → NDK 交叉编译器 + --whole-archive 链接 .a
guard_compile() {
    local out="$1"; shift
    if [ "$HAS_SRC" = "1" ]; then
        cp "$GUARD_DIR"/*.h "$W"/ 2>/dev/null
        ( cd "$W" && clang -fPIC -shared -Oz -DNC_GUARD_SECTIONED -I"$W" \
            "$GUARD_DIR"/nc_guard_boot.c "$GUARD_DIR"/nc_guard_probe.c \
            "$GUARD_DIR"/nc_guard_key.c "$GUARD_DIR"/nc_guard_paths.c \
            "$GUARD_DIR"/nc_guard_xor.c \
            "$@" -o "$out" )
    else
        [ -n "$STATIC_LIB" ] || { echo "✗ 找不到静态库: $GUARD_DIR/lib" >&2; return 1; }
        [ -n "$STATIC_CC" ] || {
            echo "✗ 静态库形态需要 NDK 交叉编译器（$STATIC_ABI）" >&2
            echo "  设 ANDROID_NDK_HOME 后重试；或改用源码形态的分发包" >&2
            return 1; }
        # --whole-archive 不能省：ncguard_unlock 是 constructor，无人引用
        # 会被链接器丢弃 → 加密段 5 个塌成 1 个。
        "$STATIC_CC" -fPIC -shared -Oz -DNC_GUARD_SECTIONED -I"$GUARD_DIR" \
            "$@" -Wl,--whole-archive "$STATIC_LIB" -Wl,--no-whole-archive \
            -o "$out"
    fi
}

if [ "$HAS_SRC" = "1" ]; then
    echo "设施链接方式: 源码 $GUARD_DIR/*.c（产物可在本机执行）"
else
    echo "设施链接方式: 静态库 $STATIC_ABI/libnox.a（交叉编译，产物不可在本机执行）"
    [ "$CAN_EXEC" = "0" ] && \
        echo "  ℹ V5/V6/V7（依赖 dlopen 执行）将跳过 —— 静态库形态在 x86 宿主上跑不了 ARM 产物"
fi

# ── V1 编译（只拷本目录的源文件，不加任何外部代码）──
echo "── V1 独立编译 ──"
cd "$W" || exit 2
# ⚠️ 测试不做 -fvisibility=hidden：那会把 ncguard_unlock 藏进 hidden，
#    dlsym 拿不到，无法验证解锁链路。生产构建才需要 hidden（见 README）。
if guard_compile "$W/raw.so" biz.c tshell.c 2>"$W/build.log"; then
    ok "V1 编译通过（$(stat -c%s raw.so) B）"
else
    bad "V1 编译失败"; head -15 build.log; echo; echo "结果: $PASS 通过, $FAIL 失败"; exit 1
fi

# ── V2 五个段齐全 ──
echo "── V2 加密段结构 ──"
for s in .ncx .ncxh .ncxhr .nck .ncks; do
    if readelf -SW raw.so 2>/dev/null | awk '{print $2}' | grep -qxF "$s"; then
        ok "V2 段 $s 存在"
    else
        bad "V2 段 $s 缺失"
    fi
done
# .ncxr 只在业务代码标记了 const 数据时生成（clang 不允许 const 进 AXR 段），
# 故它是可选项，不作为失败条件 —— 判分只要求"存在则记录"
if readelf -SW raw.so 2>/dev/null | awk '{print $2}' | grep -qxF ".ncxr"; then
    ok "V2 段 .ncxr 存在（业务代码标了常量数据）"
else
    skip "V2 .ncxr 不存在（测试代码未标记常量数据，属正常）"
fi

# ── V3 锁箱：.ncx 必须变成密文 ──
echo "── V3 锁箱（代码段加密）──"
cd "$W" || exit 2
# ⚠️ fixture APK 的 AndroidManifest 是最小占位（无 string pool），
#    无法解析包名。故显式传 --package；真实 APK 可不传（自动从 AXML 解析）。
#    包名必须与运行期 /proc/self/cmdline 取到的一致，否则 fail-closed(-12)。
PKG_FIX="com.nox.fixture"
if python3 "$LOCK" raw.so l1.so --section .ncx --from-apk "$APK" \
        --package "$PKG_FIX" >l1.log 2>&1; then
    ok "V3 一级锁箱成功"
    ENTR=$(python3 - <<'PY'
import struct, math
d = open('l1.so','rb').read()
sh = struct.unpack('<Q', d[0x28:0x30])[0]; es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]; si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
for i in range(en):
    o = sh + i*es; no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == '.ncx':
        fo = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        sz = struct.unpack('<Q', d[o+0x20:o+0x28])[0]
        seg = d[fo:fo+sz]
        if len(seg) < 32:
            print('SMALL'); break
        c = [0]*256
        for b in seg: c[b] += 1
        e = -sum((v/len(seg))*math.log2(v/len(seg)) for v in c if v)
        print('%.3f' % e); break
PY
)
    case "$ENTR" in
        SMALL) skip "V3 .ncx 过小（<32B），熵值不具区分度" ;;
        *)     if awk "BEGIN{exit !($ENTR > 6.5)}"; then
                   ok "V3 .ncx 已是密文（熵 $ENTR）"
               else
                   bad "V3 .ncx 熵仅 $ENTR —— 加密未生效"
               fi ;;
    esac
else
    bad "V3 一级锁箱失败"; tail -10 l1.log
fi

# ── V4 路径明文不可见 ──
echo "── V4 路径明文 ──"
if [ -f l1.so ]; then
    n1=$(strings -n 6 l1.so | grep -cF "/proc/self/cmdline" || true)
    n2=$(strings -n 6 l1.so | grep -cF "/proc/self/maps" || true)
    if [ "$n1" = "0" ] && [ "$n2" = "0" ]; then
        ok "V4 路径明文零命中"
    else
        bad "V4 路径明文残留（cmdline=$n1 maps=$n2）"
    fi
else
    skip "V4 无锁箱产物"
fi

# ── V5 篡改密文必须被拒（MAC 生效）──
echo "── V5 篡改检测 ──"
if [ -f l1.so ]; then
    # 二级锁箱后才有完整 MAC 链，先做二级
    if python3 "$LOCK" l1.so l2.so --lock-head >l2.log 2>&1; then
        ok "V5 二级锁箱成功"
        cp l2.so tampered.so
        python3 - <<'PY'
import struct
p = 'tampered.so'
d = bytearray(open(p,'rb').read())
sh = struct.unpack('<Q', d[0x28:0x30])[0]; es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]; si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
# ⚠️ 改段【中间】而不是段首：段首可能是别的函数（实测踩过 ——
#    改首字节不影响被测试的 secret_calc，于是篡改"没生效"，
#    V5 假绿）。改中间必落在某个函数体内。
for i in range(en):
    o = sh + i*es; no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == '.ncx':
        fo = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        sz = struct.unpack('<Q', d[o+0x20:o+0x28])[0]
        d[fo + sz // 2] ^= 0x01     # 改段中点
        break
open(p,'wb').write(d)
PY
        # 用 dlopen 验证：篡改后应解锁失败
        # ⚠️ 不通过 dlsym("ncguard_unlock") 判断解锁结果：
        #    该符号在静态库形态下是 GLOBAL HIDDEN（编译 .a 时用了
        #    -fvisibility=hidden），dlsym 必然拿不到 —— 而那是【正确的】
        #    生产行为，外部本来就不该调它。
        #    改判据：dlopen 后能否取到加密段里的业务符号。
        #    解锁成功 → .ncx 已解成明文 → 函数可被 dlsym 到；
        #    解锁失败 → 段仍是密文 → 调用会 SIGILL / 取不到。
        cat > drv.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) { printf("NOOPEN\n"); return 0; }

    /* ⚠️ 不能只靠 dlsym 判断解锁状态（实测踩过）：
     *    符号在 .dynsym 里，跟段是否已解密无关 —— 篡改后段仍是密文，
     *    dlsym 照样成功，于是误判成"解锁成功"（假绿）。
     *    必须【真的调用】加密段里的函数：段未解密时调用 = 执行密文 = 崩。
     *
     * test_call_secret_calc 带 noinline，确保它真去 bl 到 .ncx 里，
     * 而不是被编译器内联成明文副本。 */
    int (*f)(int) = dlsym(h, "test_call_secret_calc");
    if (!f) { printf("NOSYM\n"); return 0; }
    fflush(stdout);
    printf("%d\n", f(0));      /* 期望 270；段未解密则进程直接死 */
    return 0;
}
EOF
        if [ "$CAN_EXEC" = "0" ]; then
            skip "V5 篡改已生效（静态验证）；执行验证跳过 —— .a 产物是 ARM，宿主跑不了"
        elif clang drv.c -o drv -ldl 2>/dev/null; then
            # 包名：运行期从 /proc/self/cmdline 取并截到首个 ":"，
            # 假目录名必须与真实包名一致，否则 fail-closed(-12)
            PKG="$PKG_FIX"
            if [ -n "$PKG" ]; then
                mkdir -p "fake/$PKG/lib/arm64-v8a"
                cp "$APK" "fake/$PKG/base.apk"
                cp tampered.so "fake/$PKG/lib/arm64-v8a/libtest.so"
                RC_T=$( cd "fake/$PKG" && bash -c "exec -a $PKG '$W/drv' ./lib/arm64-v8a/libtest.so" 2>/dev/null )
                # 判据：篡改后必须【不能】得到 270。
                # 可能表现：空输出（调用密文 → 崩）、NOOPEN、NOSYM。
                # 只要不是 270，就说明加密段没被解密（MAC 生效）。
                if [ "$RC_T" = "270" ]; then
                    bad "V5 篡改密文后加密段仍可执行（得到 270）—— MAC 未生效"
                else
                    ok "V5 篡改密文 → 加密段不可执行（$RC_T）"
                fi

                # ── V6 完整链路：未篡改应能解开 ──
                echo "── V6 完整解锁链路 ──"
                cp l2.so "fake/$PKG/lib/arm64-v8a/libtest.so"
                RC_OK=$( cd "fake/$PKG" && bash -c "exec -a $PKG '$W/drv' ./lib/arm64-v8a/libtest.so" 2>/dev/null )
                if [ "$RC_OK" = "270" ]; then
                    ok "V6 未篡改 → 解锁成功且加密段可执行"
                    # 验证加密段代码真的能执行
                    cat > t2.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) return 2;
    int (*s)(int) = dlsym(h, "test_call_secret_calc");
    int (*p)(int,int) = dlsym(h, "test_call_plain_add");
    if (!s || !p) { printf("NOSYM\n"); return 3; }
    int a = s(0), b = p(0, 1);
    printf("%d %d\n", a, b);
    return 0;
}
EOF
                    if [ "$CAN_EXEC" = "0" ]; then
                        skip "V6 解锁链路静态验证通过；执行验证跳过 —— .a 产物是 ARM，宿主跑不了"
                    elif clang t2.c -o t2 -ldl 2>/dev/null; then
                        OUT=$( cd "fake/$PKG" && bash -c "exec -a $PKG '$W/t2' ./lib/arm64-v8a/libtest.so" 2>/dev/null )
                        # secret_calc(0) = (0^0x5A)*3 = 270 ; plain_calc(0) = 1
                        if [ "$OUT" = "270 1" ]; then
                            ok "V6 加密段代码可执行（secret_calc(0)=270, plain_calc(0)=1）"
                        else
                            bad "V6 执行结果异常: '$OUT'（期望 '270 1'）"
                        fi
                    else
                        skip "V6 无法编译执行驱动"
                    fi
                else
                    bad "V6 未篡改却拿不到正确结果（$RC_OK，期望 270）—— 正常包也会挂"
                fi
            else
                skip "V5/V6 无法提取包名"
            fi
        else
            skip "V5/V6 无法编译 dlopen 驱动"
        fi
    else
        bad "V5 二级锁箱失败"; tail -10 l2.log
    fi
else
    skip "V5 无一级锁箱产物"
fi

# ── V7 带 .ncxr 常量表的场景（2026-10-30 新增，修完真 bug 后补的断言）──
# 为什么必须单独测：.ncxr 与 .bss 同页时，给数据段设只读会把 .bss 也变
# 只读 → dlopen 阶段 SIGSEGV。主项目的 .ncxr 有 96 字节、恰好与 .data
# 同页而非 .bss，所以这条路径长期没被覆盖。实测发现后修了
# ncg_page_has_writable_neighbor()，本项防止回归。
echo "── V7 常量表（.ncxr 与 .bss 同页）──"
cat > "$W/biz2.c" <<'V7EOF'
#include <stdint.h>
/* 数据放 .ncxr（clang 不允许 const 进 AXR 段） */
__attribute__((section(".ncxr"), used, retain))
static uint8_t V7DATA[17] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17};
/* 代码放 .ncx，读上面的数据 */
__attribute__((section(".ncx"), used, retain))
int v7_sum(void) {
    int s = 0;
    for (int i = 0; i < 17; i++) s += V7DATA[i];
    return s;
}
__attribute__((visibility("default")))
int demo_v7_sum(void) { return v7_sum(); }
V7EOF
cd "$W" || exit 2
if guard_compile "$W/v7raw.so" biz2.c 2>"$W/v7build.log"; then
    # 关键：两段都要锁（--section .ncx,.ncxr）
    if python3 "$LOCK" v7raw.so v7l1.so --section .ncx,.ncxr \
            --from-apk "$APK" --package "$PKG_FIX" >v7l1.log 2>&1 \
       && python3 "$LOCK" v7l1.so v7l2.so --lock-head >v7l2.log 2>&1; then
        mkdir -p "v7fake/$PKG_FIX/lib/arm64-v8a"
        cp "$APK" "v7fake/$PKG_FIX/base.apk"
        cp v7l2.so "v7fake/$PKG_FIX/lib/arm64-v8a/libv7.so"
        cat > v7drv.c <<'V7DRV'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) { printf("OPENFAIL\n"); return 2; }
    int (*f)(void) = dlsym(h, "demo_v7_sum");
    if (!f) { printf("NOSYM\n"); return 3; }
    printf("%d\n", f());
    return 0;
}
V7DRV
        if [ "$CAN_EXEC" = "0" ]; then
            skip "V7 .ncxr 锁箱成功、产物含两段；执行验证跳过 —— .a 产物是 ARM，宿主跑不了"
        elif clang v7drv.c -o v7drv -ldl 2>/dev/null; then
            V7OUT=$( cd "v7fake/$PKG_FIX" && bash -c "exec -a $PKG_FIX '$W/v7drv' ./lib/arm64-v8a/libv7.so" 2>/dev/null )
            # 1+2+...+17 = 153
            if [ "$V7OUT" = "153" ]; then
                ok "V7 带 .ncxr 的产物可解锁并正确执行（v7_sum()=153）"
            elif [ "$V7OUT" = "OPENFAIL" ]; then
                bad "V7 dlopen 失败 —— .ncxr 与 .bss 同页的 mprotect 问题回归了"
            else
                bad "V7 执行结果异常: '$V7OUT'（期望 153）"
            fi
        else
            skip "V7 无法编译驱动"
        fi
    else
        bad "V7 锁箱失败"; tail -5 v7l1.log v7l2.log 2>/dev/null
    fi
else
    bad "V7 编译失败"; head -10 v7build.log
fi

# ── V8 元数据清理：.eh_frame / .comment / 函数边界（2026-11-02）──
# 为什么必须单独断言：.comment 的清除在 CI 上【从未生效过】（GNU objcopy
# 不存在 → 走 else 分支打印警告后继续）。只靠「日志没报错」看不出来，
# 必须在【产物】上断言。同理 .eh_frame 的 709 个 FDE 会把段加密架空
# （它列出每个函数的精确起止地址），也必须验产物。
echo "── V8 元数据清理 ──"
if [ -f l2.so ]; then
    ZA=$(mktemp -d)
    python3 "$LOCK" l2.so "$ZA/clean.so" --strip-meta >"$ZA/m.log" 2>&1
    RC_META=$?
    if [ $RC_META -eq 0 ]; then
        ok "V8 --strip-meta 执行成功"
        # 三个断言都必须为 0 命中
        n_eh=$(readelf -SW "$ZA/clean.so" 2>/dev/null | grep -c "eh_frame" || true)
        n_cm=$(readelf -SW "$ZA/clean.so" 2>/dev/null | grep -c "\.comment" || true)
        n_fp=$(strings -n 5 "$ZA/clean.so" 2>/dev/null | grep -ciE "Android \(|clang version" || true)
        if [ "$n_eh" = "0" ] && [ "$n_cm" = "0" ] && [ "$n_fp" = "0" ]; then
            ok "V8 .eh_frame/.comment/clang指纹 全部零命中"
        else
            bad "V8 元数据残留（eh_frame=$n_eh comment=$n_cm clang=$n_fp）"
        fi
        # 锁箱契约不可被破坏：六个段地址必须与清理前一致
        _bad_addr=""
        for _s in .ncx .ncxh .ncxr .ncxhr .nck .ncks .text; do
            _a=$(readelf -SW l2.so 2>/dev/null | awk -v n="$_s" '$2==n{print $4}')
            _b=$(readelf -SW "$ZA/clean.so" 2>/dev/null | awk -v n="$_s" '$2==n{print $4}')
            [ -n "$_a" ] && [ "$_a" != "$_b" ] && _bad_addr="$_bad_addr $_s"
        done
        if [ -z "$_bad_addr" ]; then
            ok "V8 清理后段地址全部不变（锁箱契约完好）"
        else
            bad "V8 objcopy 挪动了段地址:$_bad_addr"
        fi
        # 幂等：再跑一次必须报「无可删段」且退出 0
        python3 "$LOCK" "$ZA/clean.so" "$ZA/clean2.so" --strip-meta >/dev/null 2>&1 \
            && ok "V8 --strip-meta 幂等（二次运行成功）" \
            || bad "V8 --strip-meta 二次运行失败"
    else
        bad "V8 --strip-meta 失败"; tail -5 "$ZA/m.log"
    fi
    rm -rf "$ZA"
else
    skip "V8 无二级锁箱产物"
fi

# ── V9 CLI 全链路：nox protect 必须自带元数据清理（2026-11-06 新增）──
# 为什么单独立一项，而不是靠 V8：
#   V8 验的是【手工】调 --strip-meta 有没有效。而 AGENTS.md §5.4 写的是
#   「三道锁箱之后必须再跑一次元数据清理」，这条"必须"要落到【最常用的
#   那条命令】上才有意义。实测 2026-11-06 之前 nox protect 压根没调它：
#       .eh_frame 2108 B（70 个 FDE）+ .eh_frame_hdr 580 B 全部残留
#   —— 手工三步锁箱的人有保护，用一条命令的人没有。
#
# ⚠️ 这一项必须验【产物】而非日志：本仓库的 .comment 曾因"失败但继续"
#    的日志措辞连续三个月零生效（AGENTS.md §3.3），日志有输出 ≠ 防护生效。
# ⚠️ 反向验证过（AGENTS.md §3.2）：拿"编译+两级锁箱但未清理"的产物喂给
#    nox 的 _assert_meta_clean，会列出 .comment/.debug_line/.eh_frame
#    并 exit 1；干净产物放行。不是恒真断言。
echo "── V9 nox protect 自带元数据清理 ──"
if [ -f "$ROOT/nox" ] && [ "$CAN_EXEC" = "1" ]; then
    N9=$(mktemp -d)
    cat > "$N9/u.c" <<'V9SRC'
__attribute__((section(".ncx"), used, retain))
int v9_secret(int a) { return (a ^ 0x5A) * 3; }
__attribute__((visibility("default")))
int v9_call(int a) { return v9_secret(a); }
V9SRC
    if ( cd "$N9" && python3 "$ROOT/nox" protect u.c --apk "$APK" \
             --package "$PKG_FIX" -o v9.so >v9.log 2>&1 ); then
        ok "V9 nox protect 执行成功"
        _v9eh=$(readelf -SW "$N9/v9.so" 2>/dev/null | grep -c "eh_frame" || true)
        _v9cm=$(readelf -SW "$N9/v9.so" 2>/dev/null | grep -c "\.comment" || true)
        _v9fp=$(strings -n 5 "$N9/v9.so" 2>/dev/null | grep -ciE "Android \(|clang version" || true)
        if [ "$_v9eh" = "0" ] && [ "$_v9cm" = "0" ] && [ "$_v9fp" = "0" ]; then
            ok "V9 产物元数据零命中（.eh_frame/.comment/指纹）"
        else
            bad "V9 nox protect 产物残留元数据（eh_frame=$_v9eh comment=$_v9cm clang=$_v9fp）—— CLI 又漏了 --strip-meta？"
        fi
        # 六段必须都还在：清理不能把加密段一起删掉（那是产物级回归）
        _v9miss=""
        for _s in .ncx .ncxh .ncxhr .nck .ncks; do
            readelf -SW "$N9/v9.so" 2>/dev/null | awk '{print $2}' | grep -qxF "$_s" \
                || _v9miss="$_v9miss $_s"
        done
        if [ -z "$_v9miss" ]; then
            ok "V9 清理后六个加密段仍齐全"
        else
            bad "V9 加密段缺失:$_v9miss"
        fi
    else
        bad "V9 nox protect 失败"; tail -8 "$N9/v9.log"
    fi
    rm -rf "$N9"
else
    skip "V9 需要源码形态且可执行（.a 形态/交叉产物跳过）"
fi

echo ""
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
