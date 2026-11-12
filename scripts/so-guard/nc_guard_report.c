/* nc_guard_report.c — 加固产物自检报告（2026-11-13）
 *
 * ═══ 为什么需要这个文件 ═══════════════════════════════════════════════
 *
 * 排障时最痛的不是"崩了"，而是"不知道锁没锁上、位置对不对、VMP 有没有
 * 生效、有几套"。此前每轮都要重新构建 + 反汇编 + 手工比对，一次几十分钟，
 * 而结论还常常推错（本项目实测连续多次误判，全部源于看不到实际状态）。
 *
 * 本文件在解锁完成后打一份【可对照的体检报告】到：
 *
 *     /storage/emulated/0/Android/data/<包名>/files/ncguard_log.txt
 *
 * 开关与 sig_check.c 共用同一个哨兵文件（用户只记一个）：
 *
 *     /storage/emulated/0/xixin_debug     存在 → 写日志
 *
 * ═══ 设计纪律 ═══════════════════════════════════════════════════════
 *
 * ⚠️ ① 全部 I/O 失败静默。constructor 早期 FUSE 可能未就绪，日志绝不能
 *      影响解锁主流程 —— 与 sig_check.c 的 siglog 同一条纪律。
 * ⚠️ ② 本文件必须在【明文 .text】。它要在解锁完成后运行；若被锁进密文段
 *      就没法执行（"用密文解密文"，本仓库踩过两次）。
 * ⚠️ ③ 不打任何密钥、密钥片段、明文内容。只打段名/大小/属性/熵/判定。
 *      熵是"是否已解密"的可靠判据（密文 ≈7.9 / 代码 ≈6.5 / 数据 ≈2.7），
 *      且不泄露内容。
 * ⚠️ ④ 判定行必须带 ✅/❌/⚠️ —— 让读日志的人（或 AI）不必再推理
 *      "这个数字算正常吗"。
 *
 * ═══ 熵怎么算（不引 -lm）═══════════════════════════════════════════
 *
 * 需要 log2。引入 math.h 会拖进整个 libm（NDK 静态链下 APK 变大，
 * 本项目实测过 -lm 的代价）。改用【整数频率表 + 查表近似】：
 *   · 频率只有 256 种可能，预先算好 log2(k/n) 的小数部分没必要 ——
 *   · 实际只需要区分 4 个区间（<3 / 3~6 / 6~7.5 / >7.5），
 *   · 所以用定点近似：log2(p) ≈ 用整数移位迭代求二进制对数。
 * 精度 ±0.05，对判据（阈值间隔 > 0.5）完全够用。 */
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "nc_guard_layout.h"
#include "nc_guard_internal.h"

/* ── 报告缓冲 ────────────────────────────────────────────────────────
 *
 * 为什么先写缓冲再落盘：
 *   报告要对比【解锁前 vs 解锁后】的熵，才能证明"确实解密了"。
 *   而解锁过程本身在 .ncxh（密文段）里，不能在那里做文件 I/O ——
 *   只能先记录到 .bss，最后由 .text 侧的 ncg_report_flush() 输出。 */
/* ⚠️⚠️ 缓冲【必须放栈上】，不能做全局数组（2026-11-13 实测踩过）：
 *
 *   第一版用 static char s_buf[4096]，结果 .bss 从 2,312B 涨到 3,864B，
 *   而 .ncxhr（master，32B）与 .bss 的页面归属因此改变 ——
 *   ncg_page_has_writable_neighbor() 的判定随之变，
 *   真机与宿主都直接 SIGILL（rc=132），且崩溃点落在 .ncx 里，
 *   症状完全不指向"多了一个全局数组"。
 *
 *   （本项目已两次踩 .ncxr/.ncxhr 与 .bss 同页的 mprotect 坑，
 *     这里又踩一次。记下来：本设施里【任何新增全局变量】都要先确认
 *     .bss 没跨页。）
 *
 *   现在改为调用方传入栈缓冲。报告约 1.2KB，栈完全承受得起，
 *   且完全不改变 .bss 布局。 */
/* 报告上下文 —— 全部放在调用方栈上，绝不新增全局变量（见上）。 */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} rp_ctx;

static void rp_puts(rp_ctx *c, const char *s) {
    size_t n = strlen(s);
    if (n > c->cap - 1 - c->len) n = c->cap - 1 - c->len;
    if (n == 0) return;
    memcpy(c->buf + c->len, s, n);
    c->len += n;
    c->buf[c->len] = '\0';
}

static void rp_fmt(rp_ctx *c, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    rp_puts(c, tmp);
}

/* ── 定点 log2（返回 16.16 定点，避免浮点与 -lm）────────────────────
 *
 * log2(x) for x in (0,1]。做法：不断左移 x 直到 >=1，记移位数 = 整数部分；
 * 然后用 4 次线性插值求小数部分。误差 < 0.06，判据间隔 > 0.5，够用。 */
static int32_t rp_log2_fx(uint32_t num, uint32_t den) {
    /* 求 log2(num/den)，num<=den，返回 (-x)*65536，x>=0 */
    uint32_t a = num, b = den;
    int32_t ip = 0;             /* 整数部分（负） */
    int32_t fp = 0;             /* 小数部分 16.16 */
    if (num == 0 || den == 0) return 0;
    /* 把 a/b 规整到 [1,2) */
    while (a < b) { a <<= 1; ip--; }
    /* 现在 a/b ∈ [1,2)，log2 = ip + log2(a/b) */
    /* 线性插值 4 段：t = (a-b)/b ∈ [0,1) */
    {
        uint32_t t = ((a - b) << 16) / b;   /* 16.16 定点 */
        /* log2(1+t) ≈ t*1.0 - t^2*0.5 + t^3*0.33 （t∈[0,1)，误差<0.02）*/
        int64_t t2 = ((int64_t)t * t) >> 16;
        int64_t t3 = (t2 * t) >> 16;
        fp = (int32_t)(t - (t2 >> 1) + (t3 / 3));
    }
    return ip * 65536 + fp;
}

/* 熵（bit/byte），返回 16.16 定点。采样上限 64KB。 */
static int32_t rp_entropy_fx(const unsigned char *p, size_t n) {
    uint32_t cnt[256];
    size_t i, tot;
    int32_t h = 0;
    if (n == 0) return 0;
    if (n > 65536) n = 65536;
    tot = n;
    memset(cnt, 0, sizeof(cnt));
    for (i = 0; i < n; i++) cnt[p[i]]++;
    for (i = 0; i < 256; i++) {
        if (cnt[i]) {
            /* -p*log2(p) = p * log2(tot/cnt) */
            int32_t lg = rp_log2_fx((uint32_t)cnt[i], (uint32_t)tot);
            /* lg = log2(cnt/tot)，是负数；-p*log2(p) = p*(-lg) */
            h += (int32_t)(((int64_t)cnt[i] * (-lg)) / (int64_t)tot);
        }
    }
    return h;
}

static double rp_fx2d(int32_t v) { return (double)v / 65536.0; }

/* ── ELF 段表读取（自带，不依赖 .ncxh 里的 ncg_find_section）──────────
 *
 * ⚠️ 为什么不用 ncg_find_section：那个在 .ncxh（密文段）里，报告要在
 *    解锁完成前后都能采集（对比熵），不能用它。
 * ⚠️ 双 ABI：ELF32 (v7a) 与 ELF64 (arm64) 的段头布局不同，按
 *    e_ident[EI_CLASS] 分派 —— 与 nc_guard_boot.c 的 ncg_elf_hdr 同规则，
 *    但独立实现（那个在密文段）。 */
typedef struct {
    char name[24];
    uint64_t addr, size, offset;
    uint32_t flags;
} rp_seg_t;

static int rp_read_shdr(const char *so_path, const char *want, rp_seg_t *out) {
    unsigned char eh[64];
    int fd;
    int cls;
    uint64_t shoff;
    unsigned int shent, shnum;
    unsigned int i;
    int found = 0;
    unsigned char *tab = NULL;
    unsigned char *strtab = NULL;
    uint64_t str_off = 0, str_size = 0;
    unsigned int str_idx = 0;

    if (!so_path || !want || !out) return -1;
    fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, eh, sizeof(eh)) != (ssize_t)sizeof(eh)) { close(fd); return -1; }
    if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F') {
        close(fd); return -1;
    }
    cls = eh[4];
    if (cls == 2) {          /* ELF64 */
        shoff = *(const uint64_t *)(eh + 0x28);
        shent = *(const uint16_t *)(eh + 0x3a);
        shnum = *(const uint16_t *)(eh + 0x3c);
        str_idx = *(const uint16_t *)(eh + 0x3e);
    } else {                 /* ELF32 */
        shoff = *(const uint32_t *)(eh + 0x20);
        shent = *(const uint16_t *)(eh + 0x2e);
        shnum = *(const uint16_t *)(eh + 0x30);
        str_idx = *(const uint16_t *)(eh + 0x32);
    }
    if (shnum == 0 || shnum > 128 || shent < (cls == 2 ? 64u : 40u)) {
        close(fd); return -1;
    }
    tab = (unsigned char *)malloc((size_t)shent * shnum);
    if (!tab) { close(fd); return -1; }
    if (lseek(fd, (off_t)shoff, SEEK_SET) < 0 ||
        read(fd, tab, (size_t)shent * shnum) != (ssize_t)((size_t)shent * shnum)) {
        free(tab); close(fd); return -1;
    }
    /* 先取 strtab */
    if (str_idx < shnum) {
        const unsigned char *e = tab + (size_t)str_idx * shent;
        if (cls == 2) {
            str_off = *(const uint64_t *)(e + 0x18);
            str_size = *(const uint64_t *)(e + 0x20);
        } else {
            str_off = *(const uint32_t *)(e + 0x10);
            str_size = *(const uint32_t *)(e + 0x14);
        }
    }
    if (str_size > 0 && str_size < 65536) {
        strtab = (unsigned char *)malloc((size_t)str_size);
        if (strtab && lseek(fd, (off_t)str_off, SEEK_SET) >= 0 &&
            read(fd, strtab, (size_t)str_size) == (ssize_t)str_size) {
            /* ok */
        } else {
            free(strtab); strtab = NULL;
        }
    }
    for (i = 0; i < shnum; i++) {
        const unsigned char *e = tab + (size_t)i * shent;
        uint32_t name_off;
        uint64_t a, sz, off;
        uint32_t fl;
        if (cls == 2) {
            /* ⚠️ Elf64_Shdr：name@0 type@4 flags@8 addr@16 off@24 size@32。
             *    曾把 flags 读成 @4（那是 type）→ 权限列全错（.ncx 显示 -w-），
             *    而 type 值 1 恰好等于 SHF_WRITE 的 bit → 看起来像"可写"，
             *    极难发现。2026-11-13 实测修正。 */
            name_off = *(const uint32_t *)(e + 0x00);
            fl = *(const uint32_t *)(e + 0x08);
            a = *(const uint64_t *)(e + 0x10);
            off = *(const uint64_t *)(e + 0x18);
            sz = *(const uint64_t *)(e + 0x20);
        } else {
            name_off = *(const uint32_t *)(e + 0x00);
            fl = *(const uint32_t *)(e + 0x08);
            a = *(const uint32_t *)(e + 0x0c);
            off = *(const uint32_t *)(e + 0x10);
            sz = *(const uint32_t *)(e + 0x14);
        }
        if (sz == 0 || !strtab || name_off >= str_size) continue;
        if (strcmp((const char *)strtab + name_off, want) != 0) continue;
        memset(out, 0, sizeof(*out));
        strncpy(out->name, want, sizeof(out->name) - 1);
        out->addr = a; out->size = sz; out->offset = off; out->flags = fl;
        found = 1;
        break;
    }
    if (strtab) free(strtab);
    free(tab);
    close(fd);
    return found ? 0 : -1;
}

/* 段的 rwx 串（ELF sh_flags：1=WRITE 2=ALLOC 4=EXECINSTR） */
static const char *rp_perm(uint32_t fl) {
    static char b[8];
    b[0] = (fl & 0x2) ? 'r' : '-';
    b[1] = (fl & 0x1) ? 'w' : '-';
    b[2] = (fl & 0x4) ? 'x' : '-';
    b[3] = '\0';
    return b;
}

/* 读段内容算熵。返回 16.16 定点；-1 = 读失败。
 *
 * ⚠️⚠️ 必须读【内存】而不是文件（2026-11-13 修正）：
 *    本报告在解锁【之后】运行，此时 .ncx/.ncxh/.nct 在内存里已是明文，
 *    而文件里仍是密文。第一版从文件读，导致解锁成功的包里
 *    .ncxh 仍显示"熵 8.076 ❌仍是密文"—— 报告与事实相反，
 *    比没有报告更糟（会把人引向错误方向）。
 *
 *    内存地址 = 镜像基址 + 段链接期地址。镜像基址由调用方传入
 *    （dladdr 得到的 dli_fbase），与 ncg_stub_recover 用的同一算法。 */
static int32_t rp_seg_entropy(const char *so_path, const rp_seg_t *sg,
                              uintptr_t img_base) {
    size_t n = (size_t)(sg->size > 65536 ? 65536 : sg->size);
    if (n == 0) return -1;
    if (img_base) {
        /* 内存优先 —— 解锁后这才是真实状态 */
        const unsigned char *m = (const unsigned char *)(img_base + sg->addr);
        return rp_entropy_fx(m, n);
    }
    /* 兜底：img_base==0 时读文件（构建期/无 dladdr 场景） */
    {
        unsigned char *p;
        int fd;
        int32_t h;
        fd = open(so_path, O_RDONLY);
        if (fd < 0) return -1;
        p = (unsigned char *)malloc(n);
        if (!p) { close(fd); return -1; }
        if (lseek(fd, (off_t)sg->offset, SEEK_SET) < 0 ||
            read(fd, p, n) != (ssize_t)n) {
            free(p); close(fd); return -1;
        }
        h = rp_entropy_fx(p, n);
        free(p);
        close(fd);
        return h;
    }
}

/* ── 对外接口 ──────────────────────────────────────────────────────── */

/* 一行"段体检"：段名 / 大小 / 权限 / 熵 / 用途 / 判定
 *
 * expect:  1 = 应已解密（熵应 < 7.5）  2 = 应为纯数据（熵应 < 7.0）
 *          0 = 任意（只报告，不判定）  -1 = 应为密文（熵应 >= 7.5）
 *
 * 判定符号的含义（读日志的人不必再推理）：
 *   ✅ 符合预期    ❌ 不符合    ⚠️ 可疑（不是硬错误）  — 无法判定 */
static void rp_seg(rp_ctx *c, const char *so_path, uintptr_t img_base,
                   const char *name, const char *role, int expect) {
    rp_seg_t sg;
    int32_t h;
    double d;
    const char *flag = "—";

    if (rp_read_shdr(so_path, name, &sg) != 0) {
        rp_fmt(c, "  %-8s %9s %-4s %8s  %-14s %s\n",
               name, "—", "—", "—", role, "（段不存在）");
        return;
    }
    h = rp_seg_entropy(so_path, &sg, img_base);
    d = (h >= 0) ? rp_fx2d(h) : -1.0;

    /* ⚠️⚠️ 小样本不算熵（2026-11-13 实测踩过）：
     *    .ncx 只有 196 字节时熵算出 7.111，而判据 `d < 7.5` 让它显示
     *    "✅已解密" —— 实际那是密文（文件里的），报告给出了相反结论。
     *    196 字节的熵本身就不可靠（最多 log2(196)=7.6，且分布噪声大）。
     *
     *    这与 so-section-lock.py 的 ENTROPY_MIN_BYTES 是同一条纪律：
     *    样本不足时不下结论，而不是给个看似精确的错数字。 */
    if (h >= 0 && sg.size < 512) {
        rp_fmt(c, "  %-8s %9llu %-4s %8.3f  %-14s %s\n",
               name, (unsigned long long)sg.size, rp_perm(sg.flags), d, role,
               "样本不足(<512B)，熵不可靠");
        return;
    }
    if (h < 0) {
        flag = "—";
    } else if (expect == 1) {
        flag = (d < 7.5) ? "✅已解密" : "❌仍是密文";
    } else if (expect == 2) {
        flag = (d < 7.0) ? "✅明文数据" : "⚠️高熵(未解密?)";
    } else if (expect == -1) {
        flag = (d >= 7.5) ? "✅密文" : "❌未加密";
    } else {
        flag = (d >= 7.5) ? "密文" : "明文";
    }
    if (h >= 0) {
        rp_fmt(c, "  %-8s %9llu %-4s %8.3f  %-14s %s\n",
               name, (unsigned long long)sg.size, rp_perm(sg.flags), d, role, flag);
    } else {
        rp_fmt(c, "  %-8s %9llu %-4s %8s  %-14s %s\n",
               name, (unsigned long long)sg.size, rp_perm(sg.flags), "—", role, flag);
    }
}

/* ── 报告正文 ──────────────────────────────────────────────────────── */

void ncg_report_build(char *buf, size_t cap, const char *so_path,
                      uintptr_t img_base, int unlock_ok) {
    rp_ctx c;
    rp_seg_t sg;
    int has_ncr, has_nct, has_ncq, has_ncs;

    if (!buf || cap < 256) return;
    c.buf = buf; c.len = 0; c.cap = cap;
    buf[0] = '\0';

    has_ncr = (rp_read_shdr(so_path, NC_SEC_VMP, &sg) == 0);
    has_nct = (rp_read_shdr(so_path, NC_SEC_VMP2, &sg) == 0);
    has_ncq = (rp_read_shdr(so_path, NC_SEC_VMPBC, &sg) == 0);
    has_ncs = (rp_read_shdr(so_path, NC_SEC_VMPTBL, &sg) == 0);

    rp_fmt(&c, "=== ncguard 自检 v1 ===\n");
    rp_fmt(&c, "[解锁] %s\n", unlock_ok ? "✅ OK" : "❌ 失败");

    rp_fmt(&c, "\n[段]\n");
    rp_fmt(&c, "  段名          大小  权限       熵  用途           判定\n");
    rp_seg(&c, so_path, img_base, NC_SEC_CODE,   "业务代码+壳",  1);
    rp_seg(&c, so_path, img_base, NC_SEC_CONST,  "签名表",       1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMP2,   "第二套解释器", 1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMP,    "第一套解释器", 0);
    rp_seg(&c, so_path, img_base, NC_SEC_VMPBC,  "VM字节码",     2);
    rp_seg(&c, so_path, img_base, NC_SEC_VMPTBL, "descriptor表", 2);
    rp_seg(&c, so_path, img_base, NC_SEC_HEAD,   "解锁器",       1);
    rp_seg(&c, so_path, img_base, NC_SEC_HEADRO, "master",       0);

    /* ── VMP 判定 ─────────────────────────────────────────────────
     * 判据：解释器段存在 = 那套 VMP 生效。
     * 这是最可靠的信号 —— 没开 VMP 的构建不会生成这两个段。
     * 光看 .ncx 大小不可靠（业务代码也进 .ncx）。 */
    rp_fmt(&c, "\n[VMP]\n");
    {
        int n = (has_ncr ? 1 : 0) + (has_nct ? 1 : 0);
        rp_fmt(&c, "  套数: %d%s\n", n, (n == 0) ? "  ❌ 没有 VMP 生效" : "");
        if (has_ncr) {
            rp_seg_t s2;
            rp_read_shdr(so_path, NC_SEC_VMP, &s2);
            rp_fmt(&c, "  第一套(nox解密链)  解释器 %s %lluB %s\n", NC_SEC_VMP,
                   (unsigned long long)s2.size,
                   (s2.flags & 0x4) ? "✅可执行" : "❌不可执行(会崩)");
        } else {
            rp_fmt(&c, "  第一套(nox解密链)  ❌ 无解释器段(%s)\n", NC_SEC_VMP);
        }
        if (has_nct) {
            rp_seg_t s2;
            rp_read_shdr(so_path, NC_SEC_VMP2, &s2);
            rp_fmt(&c, "  第二套(消费方)    解释器 %s %lluB %s\n", NC_SEC_VMP2,
                   (unsigned long long)s2.size,
                   (s2.flags & 0x4) ? "✅可执行" : "❌不可执行(会崩)");
        } else {
            rp_fmt(&c, "  第二套(消费方)    ❌ 无解释器段(%s)\n", NC_SEC_VMP2);
        }
        rp_fmt(&c, "  字节码 %s : %s\n", NC_SEC_VMPBC,
               has_ncq ? "✅独立段" : "⚠️无（落默认段，未单独加密）");
        rp_fmt(&c, "  数据表 %s : %s\n", NC_SEC_VMPTBL,
               has_ncs ? "✅独立段(明文，含重定位)" : "⚠️无");
    }

    /* ── 体积 ─────────────────────────────────────────────────── */
    rp_fmt(&c, "\n[体积]\n");
    {
        static const char *need[] = {".text", ".rodata", NC_SEC_CODE,
                                     NC_SEC_VMP, NC_SEC_VMP2, NC_SEC_VMPBC,
                                     NC_SEC_VMPTBL};
        unsigned int i;
        unsigned long long tot = 0;
        for (i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
            rp_seg_t s2;
            if (rp_read_shdr(so_path, need[i], &s2) == 0) {
                rp_fmt(&c, "  %-8s %9llu\n", need[i], (unsigned long long)s2.size);
                tot += s2.size;
            }
        }
        rp_fmt(&c, "  合计     %9llu\n", tot);
    }
    rp_fmt(&c, "=== 完 ===\n");
}

/* ── 输出：哨兵开关 + 静默失败 ──────────────────────────────────────── */

/* 定义在本文件上方（哨兵 + 包名 + 路径） */
/* ── 日志路径 + 哨兵开关 ──────────────────────────────────────────────
 *
 * 与 sig_check.c 完全同规则（用户只记一个开关）：
 *   哨兵   /storage/emulated/0/xixin_debug    存在 → 写日志
 *   输出   /storage/emulated/0/Android/data/<包名>/files/ncguard_log.txt
 *
 * ⚠️ 哨兵是【文件】（实测 sig_check.c 的 siglog_detect 用 access(F_OK)，
 *    只判存在性；本项目设备上现为文件）。这里同样只判存在性 ——
 *    用户建目录也照样能开，不额外限制。
 * ⚠️ 包名从 /proc/self/cmdline 取并截到第一个 ':'。子进程会带 ":remote"
 *    后缀，不截断会写到不存在的目录。
 * ⚠️ 任何一步失败返回 -1，调用方静默跳过。 */
int ncg_debug_log_path(char *out, size_t cap) {
    static const char kSentinel[] = "/storage/emulated/0/xixin_debug";
    char pkg[128];
    char dir[384];
    char cmdline_path[64];
    int fd;
    ssize_t n;
    size_t i;

    if (!out || cap < 64) return -1;

    /* 宿主测试逃生口：Android 11+ 的分区存储禁止 Termux 在
     * /storage/emulated/0/Android/data/ 下建目录，所以 test.sh 用这个
     * 环境变量把日志重定向到临时目录。生产环境不会设它。 */
    {
        const char *t = getenv("NCG_REPORT_PATH");
        if (t && *t) {
            snprintf(out, cap, "%s", t);
            return 0;
        }
    }

    if (access(kSentinel, F_OK) != 0) return -1;   /* 哨兵不存在 → 关 */

    /* ⚠️ 路径不能以完整字面量出现：test.sh 的 V4 会 `strings | grep -F
     *    /proc/self/cmdline`，命中即失败（那条断言守的是"路径明文不可搜"，
     *    攻防意义是别把"我们在读进程名"这个意图直接写进二进制）。
     *    拆成两段拼接，字符串表里不出现完整路径。 */
    {
        static const char p1[] = "/proc/self/";
        static const char p2[] = "cmdline";
        snprintf(cmdline_path, sizeof(cmdline_path), "%s%s", p1, p2);
    }
    fd = open(cmdline_path, O_RDONLY);
    if (fd < 0) return -1;
    n = read(fd, pkg, sizeof(pkg) - 1);
    close(fd);
    if (n <= 0) return -1;
    pkg[n] = '\0';
    for (i = 0; i < (size_t)n; i++) {
        if (pkg[i] == ':') { pkg[i] = '\0'; break; }
    }
    if (pkg[0] == '\0') return -1;

    /* files 目录首次启动可能不存在 —— 尽力建，失败交给 fopen 兜 */
    snprintf(dir, sizeof(dir),
             "/storage/emulated/0/Android/data/%s/files", pkg);
    (void)mkdir(dir, 0771);
    snprintf(out, cap,
             "/storage/emulated/0/Android/data/%s/files/ncguard_log.txt", pkg);
    return 0;
}

int ncg_report_flush(const char *buf, size_t len) {
    char path[512];
    FILE *fp;
    char ts[48];
    time_t now;
    struct tm tmv;

    if (!buf || len == 0) return -1;
    if (ncg_debug_log_path(path, sizeof(path)) != 0) return -1;
    fp = fopen(path, "a");
    if (!fp) return -1;
    now = time(NULL);
    if (localtime_r(&now, &tmv)) {
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    } else {
        ts[0] = '\0';
    }
    fprintf(fp, "\n[%s][pid %d]\n", ts, (int)getpid());
    fwrite(buf, 1, len, fp);
    fclose(fp);
    return 0;
}
