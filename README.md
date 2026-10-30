# nox — so 段加密设施

把 C 代码中标记过的函数段加密，运行时由 so 自己解开。

## 当前状态：可单独编译

✅ **本仓库已零外部源码依赖，可独立编译。**

```bash
clang -fPIC -shared -Oz -fvisibility=hidden -DNC_GUARD_SECTIONED \
      nc_guard_boot.c nc_guard_probe.c nc_guard_key.c nc_guard_paths.c \
      your_code.c -o libyour.so
```

（`nc_guard_jni.c` 可选，仅提供 JNI 自检入口。）

### 编译后还需一步：锁箱

编译出的 so 里 `.ncx` 段仍是明文，必须用 `so-section-lock.py` 加密：

```bash
python3 so-section-lock.py libyour.so libyour.locked.so \
        --section .ncx --from-apk your-app.apk
python3 so-section-lock.py libyour.locked.so libyour.final.so --lock-head
```

**必须提供已签名的 APK** —— 密钥由它的证书派生（见下方"重要约束"）。

---

## 它是什么

不是通用 so 加密器。它只能加密**你写代码时主动标记过的函数**。

标记方式（编译期属性）：

```c
__attribute__((section(".ncx"), used, retain))
int my_secret(int a) { return (a ^ 0x5A) * 3; }
```

编译器会把这个函数单独放进 `.ncx` 段，构建期工具才有东西可加密。

**不能做的事**：加密别人已经编好的 so。没有 `.ncx` 段就没有可加密的单元。

## 它怎么工作

```
构建期（编译完之后、打包之前）
  .ncx   （代码段）  → RC4(k_so)
  .ncxr  （常量表）  → RC4(k_so_r)
  .ncxh  （解锁本体）→ SHA-256-CTR(k_stub)
  .ncxhr （master）  → SHA-256-CTR(k_stub)
  .nck / .ncks（密钥槽）→ 用 boot_key 再加密一层

运行期（so 被加载时）
  明文 stub → 解密钥槽 → 恢复 k_stub → 解 .ncxh → 解 .ncxhr 得 master
           → 派生 k_so → 验 MAC → 解 .ncx/.ncxr → 此时代码才可执行
```

## 重要约束：必须有 APK

密钥由 **APK 的签名证书**派生：

```
k_so = HKDF(master, SHA256(证书DER), "nc-so-v1" + 包名, 16)
```

运行期从已安装的 APK 重读证书，**读不到就拒绝解密**（返回 -12）。

这意味着：

| 场景 | 能否使用 |
|---|---|
| Android App 里的 so | ✅ 可以 |
| 独立 so / Linux 程序 | ❌ 不行（没有 APK 证书） |

这是**故意的设计**：允许降级就等于允许攻击者把签名剥掉后照常运行。

## 文件说明

| 文件 | 作用 |
|---|---|
| `nc_guard_layout.h` | 契约唯一真相源：段名、尺寸、偏移、magic seed。零逻辑，带 `_Static_assert` |
| `nc_guard_boot.c` | 自解谜引导：明文 stub（`.text`）+ unlock 本体（`.ncxh` 密文） |
| `nc_guard_key.c` | SHA-256 / HMAC / HKDF / APK 证书 DER 定点读取 |
| `nc_guard_paths.c/.h` | 两条 `/proc` 路径的密文表（自包含，不再依赖外部生成器） |
| `gen-paths.py` | 生成上面那张密文表（一次性工具，可重跑） |
| `nc_guard_probe.c` | `.ncx` / `.nck` 两段的唯一定义处 + 样例消费者 |
| `nc_guard_jni.c` | JNI 自检入口（返回 59 = 全链路通过） |
| `so-section-lock.py` | 构建期锁箱：加密段、写密钥槽、熵值安检 |
| `so_section_mark.py` | 自动给函数打段标记（按函数头正则匹配） |

## 强度边界（如实）

这是**提高成本**，不是**不可破解**。

- 挡得住：`strings` 扫描、静态反汇编直读、只拿到 so 没有 APK 的人
- 挡不住：愿意花时间逆向的人（代码要执行，必然有明文的一刻）、
  Frida 蹲点、PLT/GOT hook

## 来源

本仓库是 `apk-protect-action` 项目中 `scripts/so-guard/` 的镜像，
同步于该项目的提交（详见 `SOURCE.txt`）。

### 独立化改造（2026-10-30）

此前本设施 `#include "sig_log_data.h"`（主项目 sigcheck 模块生成的表），
导致脱离主项目时编译失败：

```
nc_guard_boot.c:56:10: fatal error: 'sig_log_data.h' file not found
```

现已改为自包含：`nc_guard_paths.c` 自带两条 `/proc` 路径的密文
（只这两条，成本极低），不再依赖任何外部生成器。

**验证**：不拷贝任何 sigcheck 文件，仅凭本目录 + 一段业务代码即可编译通过，
且 `.ncx/.ncxr/.ncxh/.nck/.ncks` 五段齐全。
