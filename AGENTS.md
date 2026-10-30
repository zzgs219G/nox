# AGENTS.md — AI 改动本仓库前的必读契约

> 给 AI（以及人类）的硬约束。**改任何代码前先读完本文。**
> 违反下列任何一条，改动视为无效，必须回滚。

本仓库是 `apk-protect-action` 项目里 so 段加密设施的**独立分发版**。
能力、契约、边界与源头一致，但**去掉了一切外部依赖**（不再需要主项目的
任何文件即可编译）。

---

## 0. 三十秒了解这是什么

把 C 代码里标记过的函数加密进单独的段，运行时由 so 自己解开。

```c
__attribute__((section(".ncx"), used, retain))
int my_func(void) { ... }        /* 这个函数会被加密 */
```

构建期锁箱 → 磁盘上是密文 → 运行时自解谜 → 才可执行。

**它不能加密已编好的成品 so**（没有 `.ncx` 段就没有可加密的单元）。
**它必须配合已签名 APK 使用**（密钥由 APK 证书派生，读不到就 fail-closed）。

---

## 1. 冻结模块清单（⛔ 禁止修改，除非用户在当次对话中明确点名）

下列文件的改动会破坏**所有历史产物**的兼容性。它们不是"代码"，是**格式契约**。

### 1.1 `so-guard/nc_guard_layout.h` — 契约唯一真相源

含 6 个段名、2 个 slot 尺寸（96/112）、8 个偏移、2 个 magic seed、
1 张 XOR 碎片表，带 `_Static_assert` 挡偏移重叠。

**改任一常量 = 破坏所有已发布的包。** 必须同时做到：

1. 同步 `so-guard/so-section-lock.py`（它从本头文件抽取常量的正则）
2. 同步 `so-guard/nc_guard_boot.c`（消费这些常量的 C 侧）
3. 跑 `./test.sh` 全绿（14 项）
4. 若是**扩容** slot，还要重新生成 `lib/*/libnox.a`

⚠️ 本文件零 include、零逻辑 —— 这是刻意的，任何工具链都能编。
不要把逻辑塞进来。

### 1.2 段名（6 个，改名等于换格式）

```
.ncx    加密代码段（AXR 可执行）
.ncxr   加密常量表（AWR 不可执行）
.ncxh   unlock 本体（二级锁箱对象）
.ncxhr  master 数据段（AWR 32B）
.nck    一级密钥槽（96B）
.ncks   二级 stub 密钥槽（112B）
```

**改段名 = 所有历史产物的锁箱/开箱契约失效。** 不要为了"更好看"改。

### 1.3 `so-guard/so-section-lock.py` 的密钥派生

```
k_so    = HKDF(master, SHA256(certDER), "nc-so-v1"+pkg, 16)
k_so_r  = HKDF(master, SHA256(certDER), "nc-so-r-v1"+pkg, 16)
k_mac   = HKDF(master, SHA256(certDER), "nc-so-mac-v1"+pkg, 16)
```

三个 label **必须互不相同**。复用同一把钥匙 = 知道 RC4 密钥就能伪造 MAC，
完整性校验形同虚设。改 label 必须同步 `nc_guard_key.c` 的
`ncg_derive_k_so/k_mac/k_so_r`。

---

## 2. 三条不能违反的加密纪律

违反任一条都会导致**静默失效**（构建全绿、功能为零），比报错危险得多。

### 2.1 stub 只能调 `.text` 里的函数

`ncg_stub_recover` 在明文 `.text`，它在 `.ncxh` 尚未解开时就要工作。
调 `.ncxh` 里的函数（如 `ncg_rc4`）= 执行密文 = SIGILL。

本项目已踩过**两次**同一个坑（head 段锁箱、master 解密的 RC4）。

### 2.2 数据段不能用 `.ncx`

clang 拒绝让 `const` 数据进 AXR 段：
```
causes a section type conflict
```
常量表必须用 `.ncxr`（AWR）。**已踩过三次。**

### 2.3 mprotect 粒度是页，同页有可写段时必须保持 RW

`.ncxr`（17B）与 `.bss`（9968B）同页时，给它设 `PROT_READ` 会把整页
（含 `.bss`）变只读 → 之后任何 `.bss` 写入即 SIGSEGV。

2026-10-30 实测崩过，修法见 `ncg_page_has_writable_neighbor()`。
**判据是"同页有没有 SHF_WRITE 的段"，不是"这段是不是数据"。**

---

## 3. 允许的改动方式

### 3.1 改 C 实现 → 必须重新生成静态库

发布包发的是 `lib/<abi>/libnox.a`（机器码），**不是源码**。

```bash
./make-static-lib.sh host            # 本机架构
./make-static-lib.sh arm64-v8a       # 需 ANDROID_NDK_HOME
./make-static-lib.sh armeabi-v7a
```

**只改 .c 不重新生成 .a = 改动对分发用户完全无效。**

### 3.2 改测试 → 必须做反向验证

`test.sh` 现在有 14 项。**新增"篡改/拒绝/失败"类断言时，必须验证它
失败时真的会红**，否则就是恒真断言。

本项目踩过的三种假绿（同一个 V5 断言上叠加）：
- 判据用 `dlsym` 而非真调用 → 符号在 `.dynsym` 里，与段是否解密无关
- 测试壳被 `-Oz` 内联成明文副本 → 必须拆到独立编译单元（extern 声明）
- 篡改段首字节而段首是别的函数 → 改段中点

### 3.3 不许静默降级

任何"取不到数据就当通过"的写法都是红线。历史教训：
- `lock_head` 段缺失时 `return 0`（成功）→ 自解谜没发生但流水线全绿
- 证书读不到时降级用固定密钥 → 证书绑定完全失效

正确做法一律 **fail-closed**：拿不到就拒绝，并给出人话报错。

---

## 4. 改动后的必做动作（不论大小）

```bash
./test.sh          # 必须 14 通过 0 失败
```

外加按改动类型：

| 改了什么 | 还要做什么 |
|---|---|
| `.c` 实现 | `./make-static-lib.sh <abi>` 重新生成 `.a` |
| `test.sh` 断言 | 反向验证：故意改坏 → 确认转红 → 恢复 |
| `make-zip.sh` / `nox` | 打 zip → **解压到干净目录** → 跑 `./test.sh` |
| CI workflow | 本地 `python3 -c "import yaml;yaml.safe_load(...)"` + 手动触发一次 |

⚠️ **"本地跑通"不等于"发出去的包能用"。** 本项目因此连续踩了 5 个坑：

1. shebang 写死 Termux 绝对路径 → Ubuntu 上 `bad interpreter`（exit 126）
2. `Dl_info`/`dladdr` 在 glibc 下需 `_GNU_SOURCE` → 编译失败
3. 只发 x86-64 的 `.a` → aarch64 链接报 `incompatible`
4. 交叉编译用了宿主 `strip` → `Unable to recognise the architecture`
5. 包里留 x86 兜底库 → 用户命中它、架构不对、回落源码、报无关错误

**验证分发的唯一方式：下载自己发的 release，在目标架构上跑一遍。**

---

## 5. 分发形态契约

### 5.1 发布包不含加密设施的 `.c`

打包逻辑在 `make-zip.sh`：默认静态库形态，只放 `.h` + `.py` + `lib/*/libnox.a`。
CI 有反向断言 —— 包内出现 `nc_guard_*.c` 即失败。

`SOURCE_MODE=1 ./make-zip.sh` 可发源码版（给要改代码的人），但要在
提交信息里说明理由。

### 5.2 必须按架构分发 `.a`

`.a` 是机器码，与 CPU 绑死。当前提供：

```
lib/arm64-v8a/libnox.a      AArch64   ← Android 主力
lib/armeabi-v7a/libnox.a    ARM       ← Android 旧设备
lib/aarch64/libnox.a        AArch64   ← ARM Linux/macOS 宿主自测（与前者的别名）
```

**`arm64-v8a` 与 `aarch64` 是同一架构的两个名字**（Android ABI 名 vs
`uname -m` 返回值），都要有，否则一边找不到。

链接 `.a` 必须加 `-Wl,--whole-archive`：`nc_guard_boot.o` 的入口是
`constructor`（无人显式调用），不加会被整个丢弃 → 加密段从 5 个剩 1 个。

### 5.3 已知无法隐藏的部分（如实，不要试图"修好"）

```
C 实现        ✅ 藏在 .a 里（机器码）
头文件契约    ❌ 必须公开（编译需要：段名、slot 布局）
Python 工具   ❌ 必须公开（无编译形态，.pyc 可反编译）
```

**读 `so-section-lock.py` 就能知道锁箱格式。** 这是 Python 的固有限制，
不是实现缺陷。要真正保密只能服务化（对方上传 so，服务器加密后返回）。

---

## 6. 架构债（下次重构应优先处理）

**"选哪个架构的 .a"这个决策散落在 4 处**，每修一处就发现下一处：

```
nox          find_static_lib()
test.sh      _host_arch() / _static_lib()
make-zip.sh  打包时遍历 lib/*/
CI           冒烟测试里指定 --abi
```

应抽成 `scripts/pick-lib.sh` 供四处 `source`。在那之前，**改选库逻辑
必须四处一起看**。

---

## 7. 一句话交接

> 改了 `.c` 就重打 `.a`；改了断言就反向验证；
> 打了包就在**别的架构**上解压跑一次；拿不准就 `fail-closed` 报错，
> 别静默放过。
