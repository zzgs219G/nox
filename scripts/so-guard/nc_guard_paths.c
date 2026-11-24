/* nc_guard_paths.c — 路径密文表 + 解密（设施自包含，2026-10-30）
 *
 * 背景与强度边界见 nc_guard_paths.h 的文件头。此处只写实现要点。
 *
 * 密钥流结构（与 gen-paths.py 逐字节一致）：
 *     ks_i    = SHA256(key[16] || msg_id_be32 || counter_be64)
 *     cipher  = plain XOR ks          counter 从 0 起，每块 32 字节
 *
 * 域分离（msg_id）为什么必要：
 *   两条路径若共用同一段密钥流，即构成 two-time pad —— 已知一条明文
 *   （"/proc/self/maps" 极好猜）就能 XOR 出另一条。主项目的
 *   make-sig-log.py 有同样的设计，且实测过"相同前缀 → 相同密文"
 *   从 6/6 降到 0/6。这里沿用同一思路。
 *
 * ⚠️ 本文件【不加段标记】，故编译进 .text（明文段）。这是必须的：
 *   ncg_boot_key() 要对整个 .text 算 CRC 做代码自绑定，而它调用的
 *   任何函数都必须在 .text 里（stub 纪律：stub 只能调 .text 的函数）。
 *   若把本文件标进 .ncxh，就是"用密文解密文"——本文件已踩过两次的坑。
 *
 * ⚠️ 本文件被 ncg_boot_key 的 CRC 区间覆盖是【好事】：
 *   攻击者改这里的解密代码 → CRC 变 → k_stub 变 → .ncxh 解不开。
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>      /* access（非 ARM 分支）*/
#include <fcntl.h>       /* AT_FDCWD */
#include <sys/syscall.h> /* __NR_faccessat：内联 svc（2026-11-24）*/

#include "nc_guard_paths.h"
#include "nc_guard_key.h"    /* ksha256（已在 .text，且被 khmac 复用）*/

/* ── 由 gen-paths.py 生成的密文常量 ──────────────────────────────────
 * 重跑 `python3 scripts/so-guard/gen-paths.py` 可重新生成。
 * 改动本区块必须同步 gen-paths.py 的 KEY / PATHS，否则解出乱码。 */

static const uint8_t ncg_path_key[16] = {
    0x4F, 0x1C, 0x8A, 0x73, 0xD5, 0x26, 0xE9, 0x0B,
    0x37, 0xC4, 0x6F, 0x92, 0xA1, 0x58, 0xED, 0x30,
};

/* msg_id=0  明文 "/proc/self/cmdline"（18 字节） */
static const uint8_t ncg_path_blob_cmdline[] = {
    0x0C, 0x5E, 0x07, 0x23, 0x1B, 0x38, 0x49, 0x0B, 0xB4, 0x5A, 0x06, 0x60,
    0xCB, 0x28, 0x90, 0x5E, 0x99, 0xF6,
};

/* msg_id=1  明文 "/proc/self/maps"（15 字节） */
static const uint8_t ncg_path_blob_maps[] = {
    0x34, 0x1E, 0x51, 0xB5, 0x66, 0x52, 0x68, 0x5B, 0x45, 0x7C, 0xC8, 0x1F,
    0x90, 0x6A, 0xBC,
};

/* msg_id=2  明文 "/storage/emulated/0/xixin_debug"（31 字节）
 * 2026-11-24 追加：报告哨兵（原 nc_guard_report.c 里的明文字面量，
 * 0 信息逆向 5 秒命中，现按 cmdline/maps 同款密文化 —— 用户决策：
 * 开源阶段可维护性优先，日志常开 + 藏字符串）。 */
static const uint8_t ncg_path_blob_sentinel[] = {
    0x29, 0x2B, 0xE0, 0xAD, 0xAD, 0x85, 0xA8, 0x0B, 0x45, 0xD3, 0x20, 0x9E,
    0xC0, 0x33, 0x45, 0xD6, 0xB8, 0x07, 0x4A, 0xC2, 0xA5, 0x39, 0x22, 0x7E,
    0x20, 0x58, 0xD2, 0x54, 0x77, 0x4F, 0x86,
};

/* msg_id=3  明文 "/storage/emulated/0/Android/data/"（33 字节） */
static const uint8_t ncg_path_blob_anddata[] = {
    0x63, 0xE9, 0x78, 0xE5, 0x0E, 0x02, 0x75, 0x7B, 0x5D, 0x48, 0xEE, 0xF6,
    0xA8, 0x0C, 0x00, 0xF6, 0xEE, 0x3E, 0xD4, 0xE4, 0xC7, 0x92, 0x52, 0xEE,
    0x08, 0x40, 0x01, 0x32, 0x26, 0x69, 0x82, 0x7A, 0x70,
};

/* msg_id=4  明文 "/files/ncguard_log.md"（21 字节） */
static const uint8_t ncg_path_blob_logname[] = {
    0xA4, 0x9D, 0x2B, 0xD4, 0xF4, 0xC0, 0xF9, 0x6E, 0xF2, 0x6B, 0x30, 0xC4,
    0x92, 0x9C, 0x1C, 0x06, 0x24, 0xBA, 0x7E, 0x47, 0xD6,
};

/* msg_id=5  明文 "NCG_REPORT_PATH"（15 字节） */
static const uint8_t ncg_path_blob_envname[] = {
    0xFE, 0xAB, 0xF0, 0xCB, 0x81, 0x8A, 0x73, 0x32, 0xA1, 0xBC, 0x42, 0x21,
    0x35, 0x2E, 0x9C,
};

/* 表：与 ncg_path_id 一一对应。顺序必须与枚举一致。 */
static const struct {
    const uint8_t *blob;
    uint8_t        len;
} ncg_path_tab[NCG_PATH_COUNT] = {
    { ncg_path_blob_cmdline,  (uint8_t)sizeof(ncg_path_blob_cmdline) },
    { ncg_path_blob_maps,     (uint8_t)sizeof(ncg_path_blob_maps) },
    { ncg_path_blob_sentinel, (uint8_t)sizeof(ncg_path_blob_sentinel) },
    { ncg_path_blob_anddata,  (uint8_t)sizeof(ncg_path_blob_anddata) },
    { ncg_path_blob_logname,  (uint8_t)sizeof(ncg_path_blob_logname) },
    { ncg_path_blob_envname,  (uint8_t)sizeof(ncg_path_blob_envname) },
};

/* ── 密钥流解密（就地写入调用方缓冲）───────────────────────────────
 *
 * 为什么复用 ksha256 而不是另写一个哈希：
 *   项目纪律是"密码学原语必须复用仓内已验证实现，不重造轮子"——
 *   nc_guard_key.c 的 ksha256 已被三组 NIST 向量钉死，且已在 .text。
 *   自己再写一份等于引入第二个可能出错的实现（历史上手写 SHA-256
 *   压缩函数出过错："abc" 应 ba7816bf，实得 554144d9）。
 *
 * 为什么不用 RC4：
 *   RC4 需要 256 字节 S 盒初始化循环，那是"这是 RC4"的活招牌，且会
 *   撑大 .text 里攻击者唯一能直读的部分。SHA-256 已在本 so 里
 *   （签名校验/证书派生都在用），加它不暴露任何新线索。
 *
 * ⚠️ 与 ncg_ctr_xor（nc_guard_boot.c，用于 .ncxh 解密）的区别：
 *   那个是 21(16+1+4) 字节消息、dom 用 1 字节；这里是 28(16+4+8) 字节
 *   消息、msg_id 4 字节 + counter 8 字节。两者【故意不同】，因为它们
 *   保护的对象不同，且混用会削弱域分离。不要"统一"它们。 */
__attribute__((noinline))
static void ncg_path_ctr_xor(const uint8_t *blob, uint8_t msg_id, uint8_t n,
                             char *out) {
    uint8_t msg[28];
    uint8_t ks[32];
    uint32_t i = 0;

    memcpy(msg, ncg_path_key, 16);

    while (i < n) {
        uint32_t blk = i / 32;          /* 块号 = counter */
        uint32_t off = i % 32;          /* 块内偏移 */

        /* 消息 = key[16] || msg_id_be32 || counter_be64
         * ⚠️ counter 是 be64（8 字节）：[20..23] 高 32 位恒 0、[24..27] 低 32 位。
         *    2026-11-24 修：首版写 msg[20..23]=blk、msg[24..27]=0 —— 那是
         *    be32 在低位 + 高位置零，与 gen-paths.py 的 struct.pack('>Q', ctr)
         *    （be64，[20..23]=0、[24..27]=blk）【块内一致、跨块错位】。
         *    单块（≤32B，cmdline/maps/哨兵）侥幸全对；**跨块（anddata 33B）
         *    第 2 块密钥流不同 → 尾字节解成 0x90（应为 '/'）** → 拼出非法
         *    目录 → mkdir/fopen 全部静默失败 → 报告黑洞（真机首验暴露）。
         *    修后与 gen-paths.py 逐字节一致（36 字节明文对拍验证）。 */
        msg[16] = 0;
        msg[17] = 0;
        msg[18] = 0;
        msg[19] = msg_id;
        msg[20] = 0;
        msg[21] = 0;
        msg[22] = 0;
        msg[23] = 0;
        msg[24] = (uint8_t)(blk >> 24);
        msg[25] = (uint8_t)(blk >> 16);
        msg[26] = (uint8_t)(blk >> 8);
        msg[27] = (uint8_t)blk;
        ksha256(msg, sizeof(msg), ks);

        for (; off < 32 && i < n; off++, i++)
            out[i] = (char)(blob[i] ^ ks[off]);
    }

    /* 密钥材料用完即毁（与 ncg_wipe 同样的动机：避免栈上残留）。
     * 这里用 volatile 写，防止 -Oz 把"死存储"优化掉。 */
    {
        volatile uint8_t *p = ks;
        size_t k;
        for (k = 0; k < sizeof(ks); k++) p[k] = 0;
        p = msg;
        for (k = 0; k < sizeof(msg); k++) p[k] = 0;
    }
}

/* ── 对外接口（语义与 lsg_s 一致，便于原地替换调用点）─────────────── */
const char *ncg_path_s(int id, char *buf, size_t cap) {
    uint8_t n;

    if (!buf || cap == 0) return NULL;
    if (id < 0 || id >= NCG_PATH_COUNT) return NULL;

    n = ncg_path_tab[id].len;
    /* 需要 n+1 空间放结尾 NUL；不足则不写，避免截断出一个假路径
     * （截断的路径会被 open() 当成合法但不存在的文件，问题更难查）。 */
    if ((size_t)n + 1 > cap) return NULL;

    ncg_path_ctr_xor(ncg_path_tab[id].blob, (uint8_t)id, n, buf);
    buf[n] = '\0';
    return buf;
}

/* ── APK 路径可读性检查（2026-11-24，从 nc_guard_crypto.c 移来）────────
 *
 * ⚠️⚠️ 为什么必须放在本文件、而不是 nc_guard_crypto.c：
 *   后者是【整文件 VMP】的目标（make-zip-lib.sh 的 _vmp=1 名单）。
 *   第一版把本函数写在那里 → 被 Amice 虚拟化进 .ncq 字节码 → 实测
 *   .ncq 从 95,397 涨到 108,693 B，而内联 svc 在 VM 转换后语义不可靠
 *   （svc 被当作普通操作码处理），于是修复【静默失效】：
 *   真机上 ncg_find_apk_path 仍返回 -1，锁箱 U12 仍 -12，照样 SIGILL。
 *   教训：**内联汇编/系统调用必须放在不被 VMP 的编译单元**。
 *   本文件不在 VMP 名单 → 明文 .text，且被 ncg_boot_key 的 CRC 覆盖
 *   （改这里会让 k_stub 变，属额外收益）。
 *
 * 为什么不直接用 access()：去签名校验类工具（本项目的 libusign.so）把
 * 17 个路径类 libc 函数 inline hook 到诱饵包。锁箱用 access() 验证候选
 * 路径时会被重定向，"检查通过"但读的是 origin.apk。
 * 契约（与 artifact-pipeline 的 sig_check.c 同纪律）：任何新增的
 * "读自身 APK" 路径都必须走内联 svc。
 *
 * ⚠️ armv7 的 r7 是保留寄存器（Thumb frame pointer），必须 push/pop。
 * ⚠️ 返回 0 = 可读；非 0 = 不可读（-ENOENT / -EACCES / -ENOSYS 等）。 */
#if defined(__aarch64__) || defined(__arm__)
static long ncg_svc4(long n, long a0, long a1, long a2, long a3) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return x0;
#else
    register long r0 __asm__("r0") = a0;
    __asm__ volatile(
        "push {r7}\n\t"
        "mov  r7, %[nr]\n\t"
        "svc  #0\n\t"
        "pop  {r7}"
        : "+r"(r0)
        : [nr] "r"(n), "r"(a1), "r"(a2), "r"(a3)
        : "memory");
    return r0;
#endif
}

__attribute__((noinline, used))
int ncg_apk_readable(const char *path) {
    if (!path || !*path) return -1;
    /* faccessat(AT_FDCWD, path, R_OK, 0) */
    return (int)ncg_svc4(__NR_faccessat, (long)AT_FDCWD, (long)path,
                         (long)R_OK, 0L);
}
#else
/* 非 ARM 平台（宿主测试）：没有 svc，退回 libc。
 * ⚠️ 宿主测试不模拟 hook 场景，此处行为与真机不同是已知且可接受的
 *    （真机路径由本条注释上方那个分支负责）。 */
__attribute__((noinline, used))
int ncg_apk_readable(const char *path) {
    if (!path || !*path) return -1;
    return access(path, R_OK);
}
#endif

/* ── APK 读取：内联 svc 的 open/close/pread/fstat（2026-11-25）─────────
 *
 * ⚠️⚠️ 为什么连 open/fstat/pread 都要自己走 svc：
 *   真机事故（Nivii，加固+去校验组合）：
 *     ① 构建期用最终签名证书 d82e48da 派生 k_so；
 *     ② 运行期 SigFix 的 libusign 把 open(base.apk) 重定向到 origin.apk
 *        （内含原开发者证书 3c81b429）——这是去校验的**本职工作**；
 *     ③ 锁箱的 ncg_apk_first_cert_der 也走 open → 被一并重定向 →
 *        读到 3c81b429 ≠ d82e48da → k_so 不匹配 → -13 → 密文 SIGILL。
 *   两个模块**都在 hook 同一批函数**，锁箱被"误伤"。
 *
 * 契约（AGENTS §2）：任何读自身 APK 的路径都必须内联 svc。
 * 本组函数把 open/fstat/pread 也包起来，与 ncg_apk_readable 同一纪律。
 *
 * 返回语义与 libc 一致（失败返回负 errno）。 */
#if defined(__aarch64__) || defined(__arm__)
__attribute__((noinline, used))
int ncg_apk_open_ro(const char *path) {
    /* openat(AT_FDCWD, path, O_RDONLY, 0) */
    return (int)ncg_svc4(__NR_openat, (long)AT_FDCWD, (long)path,
                         (long)O_RDONLY, 0L);
}

__attribute__((noinline, used))
long ncg_apk_pread(int fd, void *buf, size_t n, long off) {
    /* pread64(fd, buf, n, off)：4 个参数，用 ncg_svc4（双 ABI 已处理）。
     * ⚠️ armv7 不支持 64 位偏移的 pread64 一次传参（ABI 差异）；
     *    这里按 32 位截断使用 —— 本设施只用 32 位以内的包（>4GB 的 APK
     *    不存在），并加断言防越界。 */
    if (off < 0 || off > 0x7FFFFFFFL) return -1;
    return (long)ncg_svc4(__NR_pread64, (long)fd, (long)buf, (long)n, off);
}

__attribute__((noinline, used))
long ncg_apk_fsize(int fd) {
    /* lseek(fd, 0, SEEK_END) */
    return (long)ncg_svc4(__NR_lseek, (long)fd, 0L, 2L /* SEEK_END */, 0L);
}

__attribute__((noinline, used))
int ncg_apk_close(int fd) {
    /* close(fd) */
    return (int)ncg_svc4(__NR_close, (long)fd, 0L, 0L, 0L);
}
#else
/* 宿主测试：退回 libc（不模拟 hook 场景） */
__attribute__((noinline, used))
int ncg_apk_open_ro(const char *path) { return open(path, O_RDONLY); }
__attribute__((noinline, used))
long ncg_apk_pread(int fd, void *buf, size_t n, long off) {
    return (long)pread(fd, buf, n, (off_t)off);
}
__attribute__((noinline, used))
long ncg_apk_fsize(int fd) { return (long)lseek(fd, 0, SEEK_END); }
__attribute__((noinline, used))
int ncg_apk_close(int fd) { return close(fd); }
#endif
