/* nc_guard_strdec.c — 字符串段（.ncxs）运行期解密
 *
 * ═══ 为什么需要这个文件 ═══════════════════════════════════════════════
 *
 * `AGENTS.md §0.5` 写过：C 的字符串字面量永远进 `.rodata`，而 `.rodata`
 * 不在锁箱范围 → `strings libnc.so` 一条命令读出所有业务字符串。
 *
 * 实测（2026-11-28，云端真实产物）：
 *   `.rodata` 134,644 B，其中可读串 284 条 / 4,734 B —— 全部明文。
 *   含 JNI 签名、SharedPreferences 键名、路径模板、错误文案。
 *
 * ═══ 为什么只加密字符串，不加密整个 .rodata ═════════════════════════
 *
 * 用户约束：「不能大量加密（否则无法利用压缩）」—— 实测证实：
 *   整个 `.rodata` RC4 后，zlib 从 39,346 B 涨到 134,695 B（+242%）。
 *   只加密字符串（4,734 B）：39,346 → 41,034 B（+4.3%）。
 *
 * 原因：加密让数据变高熵，zlib 完全失效。而 `.rodata` 里 115KB 是
 * 低熵的表/索引（熵≈3，本来也压不动）、14KB 高熵 —— 加密它们只会
 * 让 APK 暴涨，收益接近零（看不出含义的东西不需要加密）。
 *
 * 所以本机制【只处理显式标记的字符串】，不做自动全量加密。
 *
 * ═══ 用法 ═══════════════════════════════════════════════════════════
 *
 *     static const char nc_key[] __attribute__((section(NC_SEC_STR)))
 *         = "shared_pref_token";
 *
 *     char buf[64];
 *     if (ncguard_str(nc_key, buf, sizeof(buf)) == 0) {
 *         use(buf);
 *         ncguard_str_wipe(buf, sizeof(buf));
 *     }
 *
 * ═══ 时序约束（违反会崩）═══════════════════════════════════════════
 *
 * ⚠️⚠️ 本文件全部代码必须在 `.text`（明文），且【不调用 .ncxh 里的函数】。
 *    `.ncxh` 里的 ncg_find_section / ncg_resolve_self 在解锁前是密文，
 *    调它们 = 执行密文 = SIGILL（AGENTS.md §2.1，本项目已踩过两次）。
 *    所以这里只用 .text 可用的：ncg_elf_hdr / ncg_elf_shdr / dladdr / ksha256。
 * ⚠️ 只能在 ncguard_unlock() 完成【之后】调用（需要 master 已解锁）。
 * ⚠️ 未锁箱（开发期）时 master 全零 → 退化为 memcpy（段本就是明文），
 *    与其它机制的"未锁即明文"语义一致。
 *
 * ═══ 边界（如实）═══════════════════════════════════════════════════
 *
 * ⚠️ 这不是加密数据，是隐藏字符串。攻击者能 hook `ncguard_str` 或
 *    dump 解密后的栈，仍拿得到明文。它挡的是「静态 strings 一条命令」。
 */
/* ⚠️ _GNU_SOURCE 必须在【所有 #include 之前】定义（2026-11-28 CI 实测）：
 *    Dl_info / dladdr 在 glibc 下只有定义了它才可见。
 *    Termux（bionic）默认暴露，Ubuntu CI 的 glibc 不暴露 →
 *    `error: use of undeclared identifier 'Dl_info'`，V1 编译失败。
 *    这是本项目第三次踩同一个坑（AGENTS.md §6 第 2 条）。
 *    ⚠️ 放在任何 #include 之后都无效 —— 预处理器已经处理完头文件了。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "nc_guard_layout.h"
#include "nc_guard_internal.h"
#include "nc_guard_key.h"

/* CTR 域：与 .ncxh(0x01) / .ncxhr(0x02) 都不同，避免 keystream 复用。 */
#define NC_CTR_DOM_STR  0x03

/* ── 段查找（本文件私有，只用 .text 里的 ELF 解析）────────────────────
 *
 * ⚠️ 为什么不复用 ncg_find_section：它在 .ncxh（密文段）。字符串解密
 *    可能在 .ncxh 尚未解开时被调用（例如别的 constructor 里读字符串），
 *    那时它是密文 → SIGILL。这跟 ncg_boot_key 必须自带 ELF 解析是
 *    同一个理由（见 AGENTS.md §5.6 纪律一）。
 */
__attribute__((noinline))
static int ncg_str_find_sec(const char *so_path, const char *name,
                            ncg_shdr_t *out) {
    if (!so_path || !name || !out) return -1;
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;

    uint8_t cls;
    uint64_t shoff;
    uint16_t shnum, shstrndx, shentsize;
    if (ncg_elf_hdr(fd, &cls, &shoff, &shnum, &shstrndx, &shentsize) != 0) {
        close(fd);
        return -1;
    }

    /* shstrtab 段头 */
    ncg_shdr_t strsh;
    if (ncg_elf_shdr(fd, cls, shoff, shentsize, shstrndx, &strsh) != 0
        || strsh.size == 0 || strsh.size > (1u << 20)) {
        close(fd);
        return -1;
    }

    /* 逐段比对名字。段名表不大（实测 <2KB），边读边比，不整表缓存 ——
     * 少一次 malloc，也少一处需要擦的临时缓冲。 */
    char nm[64];
    ncg_shdr_t sh;
    int found = -1;
    for (uint16_t i = 0; i < shnum; i++) {
        if (ncg_elf_shdr(fd, cls, shoff, shentsize, i, &sh) != 0) break;
        if (sh.name_off >= strsh.size) continue;
        off_t off = (off_t)(strsh.offset + sh.name_off);
        ssize_t n = pread(fd, nm, sizeof(nm) - 1, off);
        if (n <= 0) continue;
        nm[n] = '\0';
        /* 只比到第一个 NUL：段名不会跨过它 */
        if (strcmp(nm, name) == 0) {
            *out = sh;
            found = 0;
            break;
        }
    }
    close(fd);
    return found;
}

/* 取镜像基址 + 自身 so 路径。
 * ⚠️ 用 dladdr（libc），不用 ncg_resolve_self（.ncxh）。 */
__attribute__((noinline))
static int ncg_str_self(const void *addr, uintptr_t *base, char *path,
                        size_t cap) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(addr, &info) == 0 || !info.dli_fbase || !info.dli_fname)
        return -1;
    *base = (uintptr_t)info.dli_fbase;
    strncpy(path, info.dli_fname, cap - 1);
    path[cap - 1] = 0;
    return 0;
}

/* 读证书 DER + 包名（供字符串段派生密钥）。
 *
 * ⚠️ 只读不派生、不做 pkg_fault/path_fault 污染：字符串段的密钥
 *    必须与锁箱侧完全一致，而那个派生不含污染（污染只作用于 k_so，
 *    目的是让异常安装路径解不开业务代码；字符串是次要资产，若也走
 *    污染链，任何路径判定差异都会让字符串莫名其妙乱码）。
 *
 * 返回 0 / -12 定位不到 APK / -13 证书读不出 / -14 包名对不上。
 */
__attribute__((noinline))
static int ncg_str_cert_pkg(const char *so_path, uint8_t *der,
                            size_t *der_len, char *pkg, size_t pkgcap) {
    char apk_path[512];
    apk_path[0] = '\0';
    if (ncg_find_apk_path(so_path, apk_path, sizeof(apk_path)) != 0) return -12;
    if (ncg_apk_first_cert_der(apk_path, der, 1536, der_len) != 0) return -13;
    if (ncg_self_pkg(pkg, pkgcap) != 0) return -14;
    return 0;
}

/* 把 .ncxs 里从 s 开始的字符串解密到 out（含 NUL）。
 *
 * 返回 0 成功 / -1 失败。失败时 out 为空串，绝不返回半解密内容 ——
 * 半解密看起来像乱码，容易被误判成"加密算法错了"，排障成本极高。
 */
__attribute__((noinline))
int ncguard_str(const char *s, char *out, size_t cap) {
    if (!s || !out || cap == 0) return -1;
    out[0] = '\0';

    uintptr_t base = 0;
    char path[512];
    if (ncg_str_self((const void *)&ncguard_str, &base, path,
                     sizeof(path)) != 0) {
        return -1;
    }

    ncg_shdr_t sh;
    if (ncg_str_find_sec(path, NC_SEC_STR, &sh) != 0) return -1;
    if (sh.size == 0 || (sh.flags & SHF_ALLOC) == 0) return -1;

    const char *lo = (const char *)(base + sh.addr);
    const char *hi = lo + sh.size;
    if (s < lo || s >= hi) return -1;      /* 不是本段的字符串 */

    size_t n = strnlen(s, (size_t)(hi - s));
    if (n >= cap) return -1;

    /* 先取 master：它由 unlock 写进 .ncxhr，全零 = 未锁 */
    ncg_shdr_t ro;
    if (ncg_str_find_sec(path, NC_SEC_HEADRO, &ro) != 0 || ro.size < 32) {
        return -1;
    }
    const uint8_t *master = (const uint8_t *)(base + ro.addr);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= master[i];
    if (acc == 0) {
        /* 未锁（开发期）：段本来就是明文 */
        memcpy(out, s, n);
        out[n] = '\0';
        return 0;
    }

    uint8_t der[1536];
    size_t der_len = 0;
    char pkg[128];
    if (ncg_str_cert_pkg(path, der, &der_len, pkg, sizeof(pkg)) != 0) {
        ncg_wipe(der, sizeof(der));
        return -1;
    }
    uint8_t cert_sha[32];
    ksha256(der, der_len, cert_sha);
    ncg_wipe(der, sizeof(der));

    uint8_t key[16];
    int krc = ncg_derive_k_str_from_cert(master, cert_sha, pkg, key);
    ncg_wipe(cert_sha, sizeof(cert_sha));
    if (krc != 0) { out[0] = '\0'; return -1; }

    /* 段内偏移决定 counter 起点 —— 必须精确，否则解出乱码 */
    if (ncg_ctr_xor_off(key, NC_CTR_DOM_STR, (uint32_t)(s - lo),
                        (const uint8_t *)s, (uint8_t *)out,
                        (uint32_t)n) != 0) {
        ncg_wipe(key, sizeof(key));
        out[0] = '\0';
        return -1;
    }
    out[n] = '\0';
    ncg_wipe(key, sizeof(key));
    return 0;
}

/* 擦除调用方缓冲（与 ncguard_str 成对使用）。
 * ⚠️ 明文在栈上驻留越久越容易被 dump，用完立刻擦。 */
void ncguard_str_wipe(char *buf, size_t cap) {
    if (buf) ncg_wipe(buf, cap);
}
