# nox

把 C 代码里标记过的函数段加密进独立 ELF 段，运行时由 so 自己解开。
密钥绑定 APK 签名证书 —— 没有对应 APK 就解不开。

## 文档

| 你要做什么 | 看哪份 |
|---|---|
| **动手用起来**（编译、锁箱、验收） | [docs/流程文档.md](docs/流程文档.md) |
| **接手维护**（坑、时序约束、验证边界） | [docs/交接文档.md](docs/交接文档.md) |
| **继续做混淆**（剩余工作、优先级、验收清单） | [docs/混淆计划.md](docs/混淆计划.md) |
| 改代码前的硬约束（冻结清单、加密纪律） | [AGENTS.md](AGENTS.md) |

## 三十秒上手

```bash
# 你的代码先标记
#   __attribute__((section(".ncx"), used, retain))
#   int my_secret(int a) { ... }

./nox protect mycode.c --apk app-release.apk -o libmy.so
```

一条命令做完：编译 → 一级锁箱（`.ncx`）→ 二级锁箱（`.ncxh`）→ 元数据清理。

**必须有已签名的 APK** —— 密钥由它的证书派生，运行期读不到证书就拒绝解密。

## 它不能做什么

- ❌ 加密别人已经编好的 so（没有 `.ncx` 段就没有可加密的单元）
- ❌ 独立 so / Linux 程序（没有 APK 证书 → `-12` fail-closed）
- ❌ 挡住愿意花时间逆向的人（代码要执行，必然有明文的一刻）

## 自测

```bash
./test.sh      # 18 项
```

V5/V6/V7 依赖 `dlopen` 执行，在 x86 宿主上跑 ARM 产物时会跳过 ——
**真机验证不能省**。

## 发版

```bash
ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-lib.sh v1.2.3          # 静态库形态
ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-src.sh v1.2.3          # 源码形态

# 带代码混淆（需 Amice bundle）
AMICE_BUNDLE=/path/to/amice-android-ndk-r29-linux-x86_64 \
  ANDROID_NDK_HOME=/path/to/ndk ./scripts/make-zip-lib.sh v1.2.3-obf
```
