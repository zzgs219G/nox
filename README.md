# nox — so 段加密设施

把 C 代码中标记过的函数段加密，运行时由 so 自己解开。

## 当前状态：**尚不可独立使用**

⚠️ **本仓库目前只是一个快照，还不能单独编译。**

设施依赖主项目生成的 `sig_log_data.h`（用于隐藏两条 `/proc` 路径），
导致脱离主项目时编译直接失败：

```
nc_guard_boot.c:56:10: fatal error: 'sig_log_data.h' file not found
```

改造计划见主项目 `docs/计划-so-guard独立化.md`。**在改造完成前，请勿把本仓库当作可用依赖。**

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
同步于该项目的提交（详见 `SOURCE.txt`）。后续改造将在此仓库进行。
