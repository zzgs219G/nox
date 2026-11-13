# nox

把 C 代码里标记过的函数段加密进独立 ELF 段，运行时由 so 自己解开。
密钥绑定 APK 签名证书 —— 没有对应 APK 就解不开。

## 文档

| 你要做什么 | 看哪份 |
|---|---|
| **第一次接触**（10 分钟搞清两套 VMP 和各段的归属） | [docs/so防护架构.md](docs/so防护架构.md) **§0 现状速查** |
| **动手用起来**（编译、锁箱、验收） | [docs/流程文档.md](docs/流程文档.md) |
| **改段布局 / 排查段相关崩溃** | [docs/so防护架构.md](docs/so防护架构.md) **§15 段架构最终版** |
| **接手维护**（坑、时序约束、验证边界） | [docs/交接文档.md](docs/交接文档.md) |
| **遇到具体坑 / 想知道某段代码为什么这样写** | [docs/踩坑记录.md](docs/踩坑记录.md)（**K-01~K-11 数据库式，grep 查**） |
| **查某个改动为什么这么做** | [docs/变更历史.md](docs/变更历史.md)（2026-11-13 起） |
| 改代码前的硬约束（冻结清单、加密纪律） | [AGENTS.md](AGENTS.md) |

> ⚠️ `docs/so防护架构.md` 原名《混淆计划》，里面 §1–§13 是历史记录，
> 有些表述已过时（如"VMP 已关闭"）。**当前状态只看 §0 和 §15。**

判断混淆/VMP 有没有生效（只看目标文件，不看 so）：

```bash
./scripts/check-obf.sh <libnox.a>    # 0=VMP 生效，1=未检出
```

## 三十秒上手

```bash
# 你的代码先标记
#   __attribute__((section(".ncx"), used, retain))
#   int my_secret(int a) { ... }

./nox protect mycode.c --apk app-release.apk -o libmy.so
```

一条命令做完：编译 → 一级锁箱（`.ncx`）→ 二级锁箱（`.ncxh`）→ 元数据清理 → 去符号。

**必须有已签名的 APK** —— 密钥由它的证书派生，运行期读不到证书就拒绝解密。

## 它不能做什么

- ❌ 加密别人已经编好的 so（没有 `.ncx` 段就没有可加密的单元）
- ❌ 独立 so / Linux 程序（没有 APK 证书 → `-12` fail-closed）
- ❌ 挡住愿意花时间逆向的人（代码要执行，必然有明文的一刻）

## 自测

```bash
./test.sh      # V1–V10（判据 0 失败）
```

**不写死总数**：断言数随环境分支变化（`.ncxr` 缺失会 skip、`.a` 形态会 skip
执行类断言）。判据是 **0 失败**，不是某个固定数字。
当前源码形态 + ARM 宿主实测：**23 通过 0 失败**（2026-11-08 复测）。

V5/V6/V7 依赖 `dlopen` 执行。源码形态下产物是本机架构，会真跑；
`.a` 形态（`HAS_SRC=0`）产物是 ARM，宿主跑不了 → 跳过（打印"静态验证"）。
**真机验证不能省**。

> **不需要 Amice / Rust / LLVM SDK 就能开发、测试、发普通版。**
> 混淆（需 848MB 的 Amice bundle）只是发版的**可选项**，不影响任何开发工作。
> 详见 [交接文档 §0.5](docs/交接文档.md)。

## 发版

```bash
ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-lib.sh v1.2.3          # 静态库形态
ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-src.sh v1.2.3          # 源码形态

# 带代码混淆（需 Amice bundle）
AMICE_BUNDLE=/path/to/amice-android-ndk-r29-linux-x86_64 \
  ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-lib.sh v1.2.3-obf
```
