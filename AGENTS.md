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
(分发形态是源码，无预编译产物需要重生成)

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

⚠️ **已知泄露（2026-11-02 审计，决定不修）**：这 6 个名字是自解释的，
`readelf -S` 一眼看出「6 层加密结构 + 96/112 两个密钥槽」。
但改名要动 `nc_guard_layout.h` 的 6 个宏 + `artifact-pipeline/scripts/pipelines/protect.sh`
的 26 处字面量 + 全部测试断言，收益只是「降低可发现性」。
`so加固第二阶段计划-2026-10-28.md` §4.4 已给过结论：**`★☆☆☆☆`，
风险收益不成比例**。真正的解法是改按段索引定位（A 任务），不是改名字。

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

### 3.1 分发形态是源码，没有预编译产物

发布包发的是 `so-guard/*.c` 源码，用户在自己机器上编译。
**改 .c 直接生效，不需要重打任何二进制。**

（2026-10 曾短暂改为发 `lib/<abi>/libnox.a` 静态库，已废弃。原因：
① `.a` 与 CPU 架构绑死，跨架构分发要维护架构矩阵，为此连续踩了 5 个坑；
② 源码本来就公开在 GitHub 上，藏 `.a` 只挡得住"下载 zip 的人"。
若将来确需藏源码，正确做法是服务化，不是发 `.a`。）

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
- **`.comment` 移除失败时打印 `⚠️ ... 继续但不阻塞`** → 该防护
  **连续三个月零生效**（2026-10-21 → 2026-11-02），因为 CI 上没有
  GNU `objcopy`，每次都走 else 分支。**日志里有输出 ≠ 防护生效。**

正确做法一律 **fail-closed**：拿不到就拒绝，并给出人话报错。

**推论（2026-11-02 补充）**：如果某步确实不能阻塞出包（如可选优化），
那它**必须在产物侧有断言**（`test.sh` 里验产物），不能只靠日志。

### 3.4 加密了内容 ≠ 隐藏了结构

六段加密把**字节**变成了密文，但以下段会让结构原样可读：

| 段 | 泄露 |
|---|---|
| `.eh_frame` / `.eh_frame_hdr` | 每个函数的精确起止地址（709 个 FDE） |
| `.gcc_except_table` | 异常处理块边界 |
| `.symtab`（若未 strip） | 函数名 |
| 段名 / 段尺寸 | 有多少个加密段、密钥槽多大 |

**评估加密效果时必须问一句「还有什么没加密但能推出结构」**，而不是
只看「加密了几段」。见 §5.4 的 `--strip-meta`。

---

## 4. 改动后的必做动作（不论大小）

```bash
./test.sh          # 必须 18 通过 0 失败（2026-11-02 起；此前是 14 项）
```

外加按改动类型：

| 改了什么 | 还要做什么 |
|---|---|
| `.c` 实现 | **双 ABI 编译**（arm64 + v7a）；改动涉及 ELF 解析时两 ABI 都要验段表 |
| `test.sh` 断言 | 反向验证：故意改坏 → 确认转红 → 恢复 |
| `scripts/make-zip-*.sh` / `nox` | 打 zip → **解压到干净目录** → 跑 `./test.sh` |
| `so-section-lock.py` | 用**真机产物**跑一遍 `--strip-meta`，确认 `.eh_frame`/`.comment` 归零且段地址未变 |
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

### 5.1 两套打包脚本，产物形态不同

都在 `scripts/`：

| 脚本 | 产物 | 用途 |
|---|---|---|
| `make-zip-src.sh` | 含 `so-guard/*.c` 源码 | 给要改代码/审查的人 |
| `make-zip-lib.sh` | 只含 `*.h` + `*.py` + `lib/<abi>/libnox.a` | **C 实现不外泄**（当前发版默认） |

两者包内顶层都是 `nox/`，且都能通过 `./test.sh` 14 项。

**发版（CI）用 `make-zip-lib.sh`**，需要 `ANDROID_NDK_HOME`（交叉编译双 ABI）。
CI 有两条反向断言：
- 包内**不得**出现 `so-guard/*.c`（静态库形态的核心契约）
- `.a` 必须是真 ARM 机器码（`arm64-v8a` → AArch64，`armeabi-v7a` → ARM）

### 5.2 静态库形态的两条硬约束

**① 链接必须加 `-Wl,--whole-archive`**

`ncguard_unlock` 是 `constructor`，无人显式引用 → 链接器按需拉取时整个丢弃
→ `.ncxh/.ncxhr/.nck/.ncks` 四段被 `--gc-sections` 回收。
实测：不加该参数时 **5 个加密段塌成 1 个，连 unlock 都不见了**。
必须用 `--no-whole-archive` 收尾，否则 libc 等也会被全量拉入。

`nox` CLI 已自动处理；手工链接时要自己加。

**② `.a` 与架构/NDK 版本绑定**

`make-zip-lib.sh` 按 `Application.mk` 的 `APP_ABI` 编双 ABI，
`nox` 在包内多 ABI 时默认选 `arm64-v8a`，可用 `--abi` 覆盖。
用 clang-XX 编的 `.o` 不能和 clang-YY 混链。

### 5.3 已知无法隐藏的部分（如实，不要试图"修好"）

```
C 实现        ❌ 公开（源码分发）
头文件契约    ❌ 公开（编译需要：段名、slot 布局）
Python 工具   ❌ 公开（无编译形态，.pyc 可反编译）

也就是说：**这个包目前完全没有隐藏实现**。它就是一套开源工具，
靠"抬高逆向成本"提供价值，不靠"藏住算法"。
```

**读 `so-section-lock.py` 就能知道锁箱格式。** 这是 Python 的固有限制，
不是实现缺陷。要真正保密只能服务化（对方上传 so，服务器加密后返回）。

---

### 5.4 产物元数据清理（`--strip-meta`，2026-11-02）

**三道锁箱之后必须再跑一次元数据清理**，否则前面的加密收益被大幅抵消。

```bash
# 顺序不可颠倒：先 lock → 再 lock-head → 最后 strip-meta
python3 so-section-lock.py in.so out.so --section .ncx,.ncxr --from-apk app.apk
python3 so-section-lock.py out.so out.so --lock-head
python3 so-section-lock.py out.so out.so --strip-meta      # ← 新增
```

### 为什么必须放在【最后】

`objcopy` 会重写 ELF 文件。`lock`/`lock-head` 已经把**链接期 `sh_addr`**
写进了 `.nck`/`.ncks` 槽，任何挪动都会让运行期基址计算全错，
且崩溃点是 `.ncxh` 里的 SIGILL —— 症状完全不指向 objcopy。

实测 `--remove-section` 对本产物不改任何 `sh_addr`/`sh_offset`，
**但不要把顺序建立在这个实测结论上**，把顺序本身做对。

### 删什么 / 为什么

| 段 | 泄露什么 | 实测数据 |
|---|---|---|
| `.eh_frame` + `.eh_frame_hdr` | **每个函数的精确起止地址** | 709 个 FDE；`.ncx` 内 15 个函数（4/200/1500/820/…B），`.ncxh` 内 8 个（208/480/372/…B） |
| `.comment` | 完整工具链指纹 | `Android (13691557, +pgo, +bolt, +lto, +mlgo) clang version 18.0.4` + LLVM commit hash |
| `.debug_*` | libc++ 源码路径 | `out/llvm-project/libcxxabi/src/...`（`--strip-all` 删不掉，属 `.debug_line`） |

**`.eh_frame` 是最反直觉的一项**：六段都加密了，但异常表把
「有几个函数、每个多大」原样公布。加密了内容 ≠ 隐藏了结构。

### 代价（如实）

失去 C++ 异常栈回溯，崩溃时 tombstone 的 backtrace 会残缺。
`nc_guard`/`sig_check` 全是 C；dex2c 产物用 `EX_LandingPad` + 显式
`goto` 分发，不依赖 `.eh_frame`。**排障时用未清理的中间产物。**

### 删不掉的部分（如实，别试图"修好"）

libc++ 的 5 条源码路径（`out/llvm-project/libcxxabi/src/demangle/*.h` 等）
落在 **`.rodata`**，是 `__cxa_demangle` 的断言消息与文件路径常量。
删了 demangle 会崩。它们只泄露 NDK 版本，**不泄露 `nc_*` 实现**。

> ⚠️ 曾有外部报告写「那是 `__cxa_demangle` 的调试信息，`--strip-all`
> 会一并去掉」—— **不准确**。`.rodata` 里的静态字符串 `--strip-all` 不碰。

### 断言在哪

`test.sh` 的 **V8**（4 项）：执行成功 / 三类元数据产物侧零命中 /
清理后段地址不变 / 幂等。必须验**产物**而不是看日志——
`.comment` 曾因「失败但继续」的日志措辞失效三个月无人发现。

---

### 5.5 反多开路径白名单（`ncg_apk_path_fault`，2026-11-02）

**不是判定点，是数据依赖**。异常安装路径 → 污染 `k_so` → 解出乱码 →
MAC 失败 → fail-closed。调用方**没有 `if`**，攻击者无法「把某个判断
改成 `return 1`」绕过。

| | 路径 |
|---|---|
| 白名单 | `/data/app/`、`/mnt/expand/`、`/data/user_de/` |
| 黑名单 | `/data/user/`（双开）、`/data/data/`（虚拟空间）、`/data/local/tmp/` |

**与 Epic 的刻意差异**：Epic 用 `pause()` 硬拒。中国 ROM 的应用双开走
`/data/user/<uid>/`，硬拒会让**所有双开用户直接闪退** —— 那是产品事故
不是安全收益。

### 生产宏 `NCG_PATH_STRICT`

- 生产（`artifact-pipeline/scripts/lib/lib-ndk.sh` 的 `APP_CFLAGS`）**定义**
- 宿主测试（`test.sh`）**不定义** → 放行

理由：Termux 家目录就在 `/data/data/com.termux/` 下，与「虚拟空间」
前缀相同，光看前缀无法区分；测试用相对路径加载产物必然命中黑名单。

**边界（如实）**：若有人用「不加该宏」的方式自建生产产物，本项失效。
但生产链路由 `lib-ndk.sh` 统一控制。

### 规则表用 XOR 0x5A 加密存储

直接写 `"/data/user/"` 会让 `strings -n 6 | grep /data/user` 一行扫出来，
等于告诉攻击者「我们在查双开」。加密后文件里只有 `0x75 0x3E 0x3B ...`。
**这是混淆不是加密**，别高估。

---

### 5.6 ELF32 支持（2026-11-02）

`APP_ABI := armeabi-v7a arm64-v8a`，**v7a 产物是 ELF32**
（`Class: ELF32 / Machine: ARM / shentsize 40`）。

此前 `nc_guard_boot.c` 三处 ELF 解析全硬编码 `Elf64_Ehdr`/`Elf64_Shdr`，
用 ELF64 结构读 ELF32 文件会得到 `e_shoff = 0x28000900200034`
（真实 `0x335a8`，把 `e_phoff` + `e_shoff` 两个 32 位字段拼成一个 64 位读）
→ `pread` 读回 0 字节 → `boot_key` 失败 → `.ncx` 不解密 → **32 位设备启动即 SIGILL**。

现统一走 `ncg_elf_hdr` / `ncg_elf_shdr` 两个 `.text` 内的轻量抽象，
按 `e_ident[EI_CLASS]` 分派，产出统一的 `ncg_shdr_t`。

**三条纪律**：
1. 抽象必须放 `.text`（明文）—— `ncg_boot_key` 要在 `.ncxh` 尚未解密时
   就算出来，而 `.ncxh` 里的 `ncg_find_section` 也消费同一套函数。
   两边都调它，它自己不能在任何加密段，否则「用密文解密文」。
2. 不要放进 `nc_guard_layout.h` —— 那是常量契约文件，**零 include 零逻辑**
   是刻意约束（会被拷进各种 NDK 工程）。
3. **任何 ELF 解析改动必须双 ABI 验证**，不能只测 arm64。

---

## 6. 分发形态的历史教训（不要走回头路）

2026-10 曾花大量精力把分发改成预编译 `.a`，想藏住 C 实现。结果是：

| 踩的坑 | 症状 |
|---|---|
| 只发 x86-64 的 .a | aarch64 链接报 `incompatible` |
| nox 按 ABI 选了，test.sh 没同步 | 自测用错架构 |
| test.sh 回落策略硬凑 | 用 AArch64 库编 x86 目标 |
| 交叉编译用宿主 strip | `Unable to recognise the architecture` |
| 包里留 x86 兜底库 | 用户命中它、报无关错误 |

**根因**：`.a` 是机器码，与架构绑死；而"选哪份"的决策天然散落在
nox / test.sh / 打包脚本 / CI 四处。

**2026-10-31 重新启用，但不是"走回头路"**——当年的坑已逐条堵住：

| 当年的坑 | 现在怎么解决 |
|---|---|
| 只发 x86-64 的 `.a` | `make-zip-lib.sh` 用 `Application.mk` 同款双 ABI 交叉编译 |
| nox 按 ABI 选了，test.sh 没同步 | `test.sh` 按 `uname -m` 选宿主原生 `.a`，同一套 `guard_compile()` 函数 |
| test.sh 回落策略硬凑 | 无回落：无源码就找 `.a`，找不到直接 fail-fast 报路径 |
| 交叉编译用宿主 strip | 打包不 strip；`nox` 用 NDK 的 `llvm-strip` |
| 包里留 x86 兜底库 | 只编 `arm64-v8a` + `armeabi-v7a`，无兜底 |
| CI 断言方向（曾断言"禁止 .a"） | 已反转为「禁止 `.c` + 校验 `.a` 架构」 |

**仍要记住的分发纪律**：
- 公开仓库发 `.a` 只能挡住"下载 zip 的人"，挡不住"看仓库的人"。
  **前提是仓库私有**，否则 `.a` 的收益只是形式上的。
- `so-section-lock.py` 仍是明文（Python 无法编译），
  所以锁箱格式始终公开——`.a` 藏的是 C 实现，不是协议。

## 7. 一句话交接

> 改了 `.c` 就打 `.a` 包；改了断言就反向验证；
> 打了包就在**别的架构**上解压跑一次；拿不准就 `fail-closed` 报错，
> 别静默放过。
