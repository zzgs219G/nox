#!/usr/bin/env bash
# make-zip.sh — 打发行包
#
# 用法：./make-zip.sh [版本号]
#
# 产出：dist/nox-<版本>.zip
#
# 包含什么：
#   nox                 一条命令的工具
#   so-guard/*.c *.h    加密设施源码
#   so-guard/*.py       锁箱工具
#   fixtures/           样本 APK 与示例 C（可直接跑自测）
#   example/            完整可跑的例子
#   test.sh             自测
#   README.md           使用说明
#
# ⚠️ 分发形态：默认用 lib/libnox.a（预编译静态库），不发 C 源码。
#    这么做是有取舍的：
#      · C 实现藏住了（拿不到 .c）
#      · Python 工具仍是源码（无法二进制化），所以锁箱格式仍公开
#      · .a 与编译器版本绑定，对方必须用匹配的 clang
#    用 SOURCE_MODE=1 可改回发源码（给要改代码的人）。
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)

VER="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
OUT="dist/nox-${VER}.zip"

echo "打包 $OUT ..."
rm -rf dist build-zip
mkdir -p dist build-zip/nox-${VER}

STAGE="build-zip/nox-${VER}"

# ── 工具 ──
cp nox "$STAGE/"
chmod +x "$STAGE/nox"

# ── 设施源码 ──
mkdir -p "$STAGE/so-guard"
if [ "${SOURCE_MODE:-0}" = "1" ]; then
    echo "分发形态: 源码（SOGURCE_MODE=1）"
    cp so-guard/*.c so-guard/*.h so-guard/*.py "$STAGE/so-guard/"
    rm -rf "$STAGE/so-guard/__pycache__"
    # 源码模式也要带 .a，方便不想编的人
    if [ -f lib/libnox.a ]; then cp lib/libnox.a "$STAGE/lib/"; fi
else
    echo "分发形态: 静态库（C 源码不外泄）"
    # 只发头文件（.ncx/.ncxr 标记需要）+ Python 工具 + .a
    cp so-guard/*.h "$STAGE/so-guard/"
    cp so-guard/*.py "$STAGE/so-guard/"
    rm -rf "$STAGE/so-guard/__pycache__"
    # ⚠️ .a 是机器码，必须按架构分别提供（实测踩过：
    #    只发 host 架构的 .a，用户在 aarch64 上链接报
    #    "is incompatible with aarch64linux"，整个包不可用）。
    #    这里把所有已生成的架构都打进去；缺的由 CI/用户自行补。
    mkdir -p "$STAGE/lib"
    _n=0
    for d in lib/*/; do
        [ -d "$d" ] || continue
        abi=$(basename "$d")
        [ -f "$d/libnox.a" ] || continue
        mkdir -p "$STAGE/lib/$abi"
        cp "$d/libnox.a" "$STAGE/lib/$abi/"
        _n=$((_n+1))
    done
    # ⚠️ 【不】打包 lib/libnox.a（单架构兜底路径）—— 实测踩过：
    #    发布包里的 lib/libnox.a 是 CI runner 编的 x86-64。
    #    用户在 aarch64 上会先找到它、发现架构不对、回落到源码模式，
    #    而包里没有源码 → 自测必然失败，且报错信息指向"缺 .c"，
    #    完全不提"拿错了架构"这个真因。
    #    只发按架构分目录的，让选择逻辑干净：有匹配的用，没有就明说。
    #    （源码仓库里保留 lib/libnox.a 供本地开发，只是不进发布包）
    # ── 宿主架构别名（让包内 ./test.sh 能跑起来）──────────────
    # arm64-v8a 与 aarch64 是同一架构的两个名字：前者是 Android ABI 名，
    # 后者是 uname -m 的返回值。包里只有前者时，在 ARM Linux/macOS 上
    # test.sh 的 _host_arch() 会返回 aarch64 → 找不到 → 回落源码模式
    # → 包里无源码 → 失败。
    # 补一份别名目录，两个名字都能命中（内容相同，多占 47KB，值得）。
    if [ -f "$STAGE/lib/arm64-v8a/libnox.a" ] && [ ! -d "$STAGE/lib/aarch64" ]; then
        mkdir -p "$STAGE/lib/aarch64"
        cp "$STAGE/lib/arm64-v8a/libnox.a" "$STAGE/lib/aarch64/"
        _n=$((_n+1))
    fi
    echo "  已打包 $_n 个静态库（按架构分目录）"
    if [ "$_n" = "0" ]; then
        echo "  ⚠ 没有任何 libnox.a —— 对方只能自己跑 make-static-lib.sh"
    fi
fi

# ── 样本与示例 ──
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

# ── 自测与文档 ──
cp test.sh "$STAGE/"
chmod +x "$STAGE/test.sh"
cp README.md "$STAGE/"
cp AGENTS.md "$STAGE/"   # AI 接手维护时的必读契约

# ── 包内单独的快速上手说明 ──
cat > "$STAGE/QUICKSTART.md" <<'EOF'
# 三分钟上手

## 1. 解压

    unzip nox-*.zip && cd nox-*

## 2. 先跑自测，确认工具链正常

    ./test.sh

应该看到 `13 通过 0 失败`。用的是包内自带的测试 APK，与任何真实包无关。

## 3. 看看完整例子

    cd example && ./run.sh

它会：编译 → 加密 → 对比加密前后的机器码 → 运行验证返回正确。
**这一步最直观**：你会看到加密前 `mov w0, #0x5ff` 一眼看懂，
加密后连函数都反汇编不出来了。

## 4. 用你自己的代码

改 `example/mycode.c`，给你要保护的函数加两行：

    __attribute__((section(".ncx"), used, retain))
    int 你的函数(void) { ... }

然后：

    cd example
    ./run.sh /path/to/你的签名APK 你的包名

或者直接用工具：

    ./nox protect 你的代码.c --apk 你的签名APK -o libyour.so

产物放进 APK 的 `lib/arm64-v8a/` 目录。

---

# 必须知道的四条

## 1. 必须给 APK，不能只给 so

密钥由 **APK 的签名证书**派生。运行时从已安装的 APK 重读证书，
读不到就拒绝解密（返回 -12）。

所以它只能保护**Android App 里的 so**，不能保护独立 so / Linux 程序。

## 2. 只能保护你加过标记的函数，且必须重新编译

不能加密已经编好的成品 so —— 没有 `.ncx` 段就没有可加密的东西。

## 3. 用错 APK 会解不开

`--apk` 必须是**最终签名用的那个证书**对应的包。
换 keystore 重签 → 证书变 → 解不开。这是设计，不是 bug。

## 4. 挡的是静态分析，不是动态调试

代码要执行，就必然有明文的一刻。有 Frida 的人可以蹲到那个瞬间。
这套东西的作用是：`strings`、反汇编、静态审计这些手段失效。

---

# 常见问题

**Q: 加密后函数名还在吗？**
默认不在。`nox protect` 会自动 strip。但如果你给函数加了
`visibility("default")`，名字会留在 `.dynstr`（strip 删不掉动态符号表）——
只有需要从 Java 侧 dlsym 的 JNI 入口才该加。

**Q: 提示 "产物里没有 .ncx 段"？**
你的代码没用 `__attribute__((section(".ncx"), used, retain))` 标任何函数。
参考 `fixtures/sample.c`。

**Q: 运行返回 -11？**
MAC 校验失败。常见原因：锁箱用了 `--section .ncx` 但产物里有 `.ncxr`
（两边覆盖范围不一致）。`nox protect` 会自动探测所有段，不会踩这个坑。

**Q: 想保护常量表？**
用 `.ncxr` 而不是 `.ncx`（clang 不允许 const 数据进可执行段）。
注意常量必须真的被代码引用，否则会被 `--gc-sections` 回收。
详见 `fixtures/sample.c` 里的注释。
EOF

# ── 打包 ──
cd build-zip
if command -v zip >/dev/null 2>&1; then
    zip -qr "../$OUT" "nox-${VER}"
else
    # 没有 zip 命令时用 python 的 zipfile
    python3 - "$OUT" "nox-${VER}" <<'PY'
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
