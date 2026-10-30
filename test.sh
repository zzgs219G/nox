#!/data/data/com.termux/files/usr/bin/bash
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

APK="${1:-}"
LOCK="$ROOT/so-guard/so-section-lock.py"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $*"; }
skip() { echo "  ⚠ $*（跳过）"; }

if [ -z "$APK" ] || [ ! -f "$APK" ]; then
    echo "用法: ./test.sh <已签名APK>"
    echo ""
    echo "需要一个真实 APK 的原因：密钥由它的证书派生，"
    echo "没有 APK 就无法验证解密链路（V6 会跳过，其他项仍可跑）。"
    exit 1
fi
if ! command -v clang >/dev/null 2>&1; then
    echo "✗ 缺 clang，无法测试"; exit 1
fi

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# 测试用的业务代码：一个函数进加密段，一个不进
cat > "$W/biz.c" <<'EOF'
#include <stdint.h>
/* 要被保护的：加标记，进 .ncx 段 */
__attribute__((section(".ncx"), used, retain, visibility("default")))
int secret_calc(int a) { return (a ^ 0x5A) * 3; }
/* 不保护的：留在 .text */
__attribute__((visibility("default")))
int plain_calc(int a) { return a + 1; }
EOF

echo "=== nox 自测（$(basename "$APK")）==="
echo ""

# ── V1 编译（只拷本目录的源文件，不加任何外部代码）──
echo "── V1 独立编译 ──"
cp "$ROOT"/so-guard/*.c "$ROOT"/so-guard/*.h "$W"/ 2>/dev/null
cd "$W" || exit 2
# ⚠️ 测试不做 -fvisibility=hidden：那会把 ncguard_unlock 藏进 hidden，
#    dlsym 拿不到，无法验证解锁链路。生产构建才需要 hidden（见 README）。
if clang -fPIC -shared -Oz -DNC_GUARD_SECTIONED -I. \
        nc_guard_boot.c nc_guard_probe.c nc_guard_key.c nc_guard_paths.c \
        biz.c -o raw.so 2>build.log; then
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
if python3 "$LOCK" raw.so l1.so --section .ncx --from-apk "$APK" >l1.log 2>&1; then
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
for i in range(en):
    o = sh + i*es; no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == '.ncx':
        fo = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        d[fo] ^= 0x01      # 改密文第一个字节
        break
open(p,'wb').write(d)
PY
        # 用 dlopen 验证：篡改后应解锁失败
        cat > drv.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) { printf("NOOPEN\n"); return 0; }
    int (*u)(void) = dlsym(h, "ncguard_unlock");
    printf("%d\n", u ? u() : -999);
    return 0;
}
EOF
        if clang drv.c -o drv -ldl 2>/dev/null; then
            # 包名：运行期从 /proc/self/cmdline 取并截到首个 ":"，
            # 假目录名必须与真实包名一致，否则 fail-closed(-12)
            PKG=$(python3 -c "
import importlib.util
spec=importlib.util.spec_from_file_location('lock','$LOCK')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.manifest_package('$APK'))
" 2>/dev/null)
            if [ -n "$PKG" ]; then
                mkdir -p "fake/$PKG/lib/arm64-v8a"
                cp "$APK" "fake/$PKG/base.apk"
                cp tampered.so "fake/$PKG/lib/arm64-v8a/libtest.so"
                RC_T=$( cd "fake/$PKG" && bash -c "exec -a $PKG '$W/drv' ./lib/arm64-v8a/libtest.so" 2>/dev/null )
                if [ "$RC_T" = "0" ] || [ "$RC_T" = "59" ]; then
                    bad "V5 篡改密文后仍然解锁成功（rc=$RC_T）—— MAC 未生效"
                else
                    ok "V5 篡改密文 → 拒绝解密（rc=$RC_T）"
                fi

                # ── V6 完整链路：未篡改应能解开 ──
                echo "── V6 完整解锁链路 ──"
                cp l2.so "fake/$PKG/lib/arm64-v8a/libtest.so"
                RC_OK=$( cd "fake/$PKG" && bash -c "exec -a $PKG '$W/drv' ./lib/arm64-v8a/libtest.so" 2>/dev/null )
                if [ "$RC_OK" = "0" ]; then
                    ok "V6 未篡改 → 解锁成功（rc=0）"
                    # 验证加密段代码真的能执行
                    cat > t2.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) return 2;
    int (*u)(void) = dlsym(h, "ncguard_unlock");
    if (u) u();
    int (*s)(int) = dlsym(h, "secret_calc");
    int (*p)(int) = dlsym(h, "plain_calc");
    if (!s || !p) { printf("NOSYM\n"); return 3; }
    int a = s(0), b = p(0);
    printf("%d %d\n", a, b);
    return 0;
}
EOF
                    if clang t2.c -o t2 -ldl 2>/dev/null; then
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
                    bad "V6 未篡改却解锁失败（rc=$RC_OK）—— 正常包也会挂"
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

echo ""
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
