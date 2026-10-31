#!/usr/bin/env bash
# make-zip-src.sh — 打【源码形态】发行包
#
# 用法：./scripts/make-zip-src.sh [版本号]
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
# 与本目录 make-zip-lib.sh 的区别（两套并存，按需选用）：
#   本脚本           → 发 C 源码（消费方 artifact-pipeline 用这套）
#   make-zip-lib.sh  → 只发头文件 + .a（C 实现不外泄）
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

VER="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
OUT="dist/nox-${VER}.zip"

echo "打包 $OUT ..."
rm -rf dist build-zip
mkdir -p dist build-zip/nox

# ⚠️ 包内顶层目录固定为 nox/，【不带版本号】。
# 版本号只出现在 zip 文件名上（dist/nox-<VER>.zip）——
# 两者职责不同：
#   · 文件名带版本 → 下载/归档时能区分版本
#   · 内层目录固定 → 解压路径稳定，消费方（如 artifact-pipeline 的
#     tools/nox.zip）可以硬编码 "$TOOLS/nox/so-guard"，换版零改动
# 这与 tools/dex2c.zip→Dex2C/、tools/dpt-shell.zip→executable/ 的约定一致。
# 历史：原为 nox-${VER}，导致换版后解压路径变化、引用全失效。
STAGE="build-zip/nox"

# ── 工具 ──
cp nox "$STAGE/"
chmod +x "$STAGE/nox"

# ── 设施源码 ──
mkdir -p "$STAGE/so-guard"
cp scripts/so-guard/*.c scripts/so-guard/*.h scripts/so-guard/*.py "$STAGE/so-guard/"
rm -rf "$STAGE/so-guard/__pycache__"

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

    unzip nox-*.zip && cd nox

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
    zip -qr "../$OUT" "nox"
else
    # 没有 zip 命令时用 python 的 zipfile
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
