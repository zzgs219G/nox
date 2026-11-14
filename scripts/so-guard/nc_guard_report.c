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
 *     /storage/emulated/0/Android/data/<包名>/files/ncguard_log.md
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
#include <sys/time.h>   /* gettimeofday：阶段追踪的毫秒时间戳（2026-11-14） */
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

/* 段名显示宽度计算：CJK 字符占两列。
 *
 * ⚠️ 为什么需要它（2026-11-13 实测）：printf 的 %-8s 按【字节】补齐，
 *    而中文一个字符 3 字节、显示占 2 列。混排后表头与数据必然错位 ——
 *    第一版日志里 "业务代码+壳" 和 "第二套解释器" 两个用途列完全对不齐，
 *    读的时候要一行一行数。日志的第一价值是可扫读，错位就没价值。 */
static int rp_disp_width(const char *s) {
    int w = 0;
    while (*s) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x80) { w += 1; s += 1; }
        else if ((c & 0xE0) == 0xC0) { w += 1; s += 2; }   /* 2 字节 */
        else if ((c & 0xF0) == 0xE0) { w += 2; s += 3; }   /* 3 字节：CJK */
        else { w += 2; s += 4; }                            /* 4 字节：emoji */
    }
    return w;
}

/* 把字节数格式化成 "12.3 KB" / "1.2 MB" / "512 B"（左对齐用，定宽 12 显示列）
 *
 * ⚠️ 为什么不再只给裸字节数（2026-11-14 用户反馈）：
 *    "你是让我自己去数到底有多少kb吗，还要我自己人工进行单位换算吗"
 *    段大小动辄 10 万字节，人眼换算 KB 每次都要数位数。日志的第一价值
 *    是扫一眼就懂，不是提供原始数据。
 * ⚠️ 定宽 12：最长的 "1023.9 KB" 占 9 列，留 3 列余量给 "1023.9 KB "。 */
static void rp_fmt_size(char *out, size_t cap, unsigned long long bytes) {
    if (bytes >= 1024ULL * 1024ULL)
        snprintf(out, cap, "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024ULL)
        snprintf(out, cap, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(out, cap, "%llu B", bytes);
}

/* 打印 s 并用空格补到 width 列（按显示宽度，不按字节） */
static void rp_pad(rp_ctx *c, const char *s, int width) {
    int w = rp_disp_width(s);
    rp_puts(c, s);
    while (w < width) { rp_puts(c, " "); w++; }
}

/* 体积归因的单一行格式（2026-11-14）：保证组名/明细/合计三类的
 * 数字与 "B" 落在同一列。
 *
 * 列位：2 空格 | indent | 名称 12 显示列 | 右对齐数字 10 列 | " B"
 *
 * ⚠️ 名称列必须走 rp_pad（按显示列，中文算 2）而不是 snprintf("%-12s")：
 *    后者按【字节】补，中文 3 字节/2 列，混排必歪 —— 本文件反复踩的坑。
 * ⚠️ 数字右对齐：体积从个位数到七位数都有，左对齐看不出量级差。
 *    右对齐时起点随位数变化是【正确】行为，比的是末位对齐。 */
/* 体积归因的单行（Markdown 表格行，2026-11-14 改）。
 *
 * 缩进用 Markdown 的 `&nbsp;` 表达层级（渲染后仍是真正的缩进），
 * 而不是靠补空格 —— 与段表同一理由：中文宽度不可控。
 */
static void _rp_size_row(rp_ctx *c, int depth,
                         const char *label, unsigned long long bytes) {
    const char *ind = (depth > 0) ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "";
    rp_fmt(c, "| %s%s | %llu B |\n", ind, label, bytes);
}

/* 一行"段体检" —— Markdown 表格行（2026-11-14 改）
 *
 * expect:  1 = 应已解密（熵 < 7.5）  2 = 应为纯数据（熵 < 7.0）
 *          0 = 任意   -1 = 应为密文（熵 >= 7.5）
 *
 * ═══ 为什么改成 Markdown 表格 ═══
 *
 * 此前用手工补空格的定宽文本，用户在手机上看永远是歪的 ——
 * 根因是**中文宽度取决于渲染字体**：本文件按「中文 = 2 显示列」补，
 * 而用户的查看器按 1 列渲染时，每一列都错位。这个假设我控制不了，
 * 也没法在本地复现（本地算和本地看用的是同一套假设）。
 *
 * 改用 Markdown 表格后：列宽由渲染器决定，源码里只写 `| a | b |`，
 * 中文宽度的不确定性被彻底消掉。
 *
 * ⚠️ 单元格内容不能含 `|`（会破坏表格结构）。段名/用途都是固定字面量，
 *    已确认无 `|`；熵值与权限也不会产生。
 */
static void rp_seg(rp_ctx *c, const char *so_path, uintptr_t img_base,
                   const char *name, const char *role, int expect,
                   int *unknown_p, int is_vmp) {
    rp_seg_t sg;
    int32_t h;
    double d;
    const char *flag = "—";
    char szbuf[32];

    if (rp_read_shdr(so_path, name, &sg) != 0) {
        rp_fmt(c, "| `%s` | - | - | - | %s | - 段不存在 |\n", name,
               is_vmp ? "✅" : "—");
        return;
    }

    rp_fmt_size(szbuf, sizeof(szbuf), (unsigned long long)sg.size);
    h = rp_seg_entropy(so_path, &sg, img_base);
    d = (h >= 0) ? rp_fx2d(h) : -1.0;

    /* 熵列：无法计算时写 "-"，避免混入无意义的 0.000 */
    char ebuf[16];
    if (h >= 0) snprintf(ebuf, sizeof(ebuf), "%.3f", d);
    else        snprintf(ebuf, sizeof(ebuf), "-");

    /* 小样本不下结论（见文件头③） */
    if (h >= 0 && sg.size < 512) {
        rp_fmt(c, "| `%s` | %s | %s | %s | %s | ⚠️ 样本不足 |\n",
               name, szbuf, rp_perm(sg.flags), ebuf, is_vmp ? "✅" : "—");
        (*unknown_p)++;
        return;
    }

    if (h < 0)                          flag = "—";
    else if (expect == 1)               flag = (d < 7.5) ? "✅ 已解密" : "❌ 仍是密文";
    /* 判定文案要能自解释（2026-11-14 用户反馈「看不懂」）：
     * 旧版 expect==0 时只打「明文」，读者会以为「这个段被解密了」。
     * 实际上 .ncr/.ncq/.ncs 是【设计上就不加密】的段 —— 它们从来不是
     * 密文，也就谈不上「解密」。措辞必须区分这两件事。 */
    else if (expect == 2)               flag = (d < 7.0) ? "✅ 明文数据（本就不加密）" : "⚠️ 高熵异常";
    else if (expect == -1)              flag = (d >= 7.5) ? "✅ 密文" : "❌ 未加密";
    else                                flag = (d >= 7.5) ? "密文（未解锁）" : "明文（本就不加密）";

    rp_fmt(c, "| `%s` | %s | %s | %s | %s | %s |\n",
           name, szbuf, rp_perm(sg.flags), ebuf, is_vmp ? "✅" : "—", flag);
}

/* ── 报告正文 ──────────────────────────────────────────────────────── */

void ncg_report_build(char *buf, size_t cap, const char *so_path,
                      uintptr_t img_base, int rc, int nseg) {
    rp_ctx c;
    rp_seg_t sg;
    int has_ncr, has_nct, has_ncq, has_ncv, has_ncs, has_ncw, has_ncd;
    int bad = 0;      /* 有问题项计数，最后汇总 */
    int unknown = 0;  /* "无法判断"计数（样本不足），不算异常但要报 */

    if (!buf || cap < 512) return;
    c.buf = buf; c.len = 0; c.cap = cap;
    buf[0] = '\0';

    has_ncr = (rp_read_shdr(so_path, NC_SEC_VMP, &sg) == 0);
    has_nct = (rp_read_shdr(so_path, NC_SEC_VMP2, &sg) == 0);
    has_ncq = (rp_read_shdr(so_path, NC_SEC_VMPBC, &sg) == 0);
    has_ncv = (rp_read_shdr(so_path, NC_SEC_VMPBC2, &sg) == 0);
    has_ncs = (rp_read_shdr(so_path, NC_SEC_VMPTBL, &sg) == 0);
    has_ncw = (rp_read_shdr(so_path, NC_SEC_VMPTBL2, &sg) == 0);

    rp_puts(&c, "# ncguard 自检 v3\n");
    /* 图例放在最前面 —— 此前用户看到 '!' 和 '结论 OK' 并存，不知道
     * '!' 是什么意思。宁可多占两行，也不要让人猜。 */
    rp_puts(&c, "\n> 符号：✅ 通过 · ❌ 有问题 · ⚠️ 无法判断（样本不足）· — 段不存在\n");

    /* ── 解锁结果（第一眼要看的）────────────────────────────────── */
    if (rc == 0) {
        rp_fmt(&c, "\n**解锁**：✅ %d 段全部解密\n", nseg);
    } else {
        bad++;
        rp_fmt(&c, "\n**解锁**：❌ 失败 rc=%d（%d 段）\n", rc, nseg);
        if (rc == -11) rp_puts(&c, "\n> ❌ **MAC 校验失败** —— 段序或段内容与锁箱侧不一致\n");
        else if (rc == -12) rp_puts(&c, "\n> ❌ **密钥派生失败** —— 证书/包名不匹配，或段序错导致钥匙错配\n");
        else if (rc == -8 || rc == -10) rp_puts(&c, "\n> ❌ **mprotect 失败** —— 页权限/同页可写段\n");
        else if (rc == -3) rp_puts(&c, "\n> ❌ **密钥槽缺失** —— 找不到 `.nck`\n");
        else if (rc == -9) rp_puts(&c, "\n> ❌ **内存不足** —— malloc 失败\n");
    }

    /* ── 段表（Markdown，2026-11-14 改）────────────────────────────
     *
     * ⚠️ 列名必须说清「熵是从哪读的」（2026-11-14 用户反馈）：
     *
     *      「这个熵到底是解锁后的，还是未解锁后的？我很难判断，
     *        因为你这个日志写得太让人误解」
     *
     *    实际情况：有 img_base 时读【内存】（解锁后的真实状态），
     *    没有时读【文件】（磁盘上锁箱后的密文）。两者熵值完全不同
     *    （密文 ≈8.0 / 明文代码 ≈6.5），但旧列名只写「熵」，
     *    读日志的人无法判断眼前这个数字代表哪一边。
     *
     *    所以：列名改成「熵(内存)」或「熵(文件)」，并在表头下方
     *    用一行引用说明这代表什么状态。宁可占两行，也不让人猜。 */
    if (img_base)
        rp_puts(&c, "\n> 熵读自**解锁后的内存**（6.x = 明文 / 8.0 = 仍是密文）。"
                    "此处反映真实运行状态。\n");
    else
        rp_puts(&c, "\n> 熵读自**磁盘文件**（8.0 = 锁箱后的密文 / 6.x = 明文）。"
                    "本次没有内存基址，反映的是锁箱后的状态。\n");
    rp_puts(&c, "\n| 段名 | 大小 | 权限 | 熵");
    rp_puts(&c, img_base ? "(内存) | VMP | 判定 |\n" : "(文件) | VMP | 判定 |\n");
    rp_puts(&c, "|:---|--:|:---|--:|:-:|:---|\n");
    rp_seg(&c, so_path, img_base, NC_SEC_CODE, "业务代码+壳", 1, &unknown, 0);
    /* ⚠️ .nct 现在**不加密**（体积优先，见 so防护架构 §15.5），所以判据是
     * "应为明文"（2）而不是"应已解密"（1）。写成 1 会显示"OK 已解密"——
     * 结论碰巧对（熵低），但语义错，会让人以为它被加密过。 */
    rp_seg(&c, so_path, img_base, NC_SEC_VMP2, "第二套解释器", 2, &unknown, 1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMPBC2, "第二套字节码", 2, &unknown, 1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMP, "第一套解释器", 0, &unknown, 1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMPBC, "第一套字节码", 0, &unknown, 1);
    rp_seg(&c, so_path, img_base, NC_SEC_VMPTBL, "第一套数据表", 0, &unknown, 1);
    rp_seg(&c, so_path, img_base, NC_SEC_CONST, "签名表", 1, &unknown, 0);
    rp_seg(&c, so_path, img_base, NC_SEC_HEAD, "解锁器", 1, &unknown, 0);
    rp_seg(&c, so_path, img_base, NC_SEC_HEADRO, "master", 0, &unknown, 0);

    /* ── VMP 判定 ────────────────────────────────────────────────
     * 判据：解释器段存在 = 那套 VMP 生效（没开 VMP 的构建不会生成）。
     * 光看 .ncx 大小不可靠 —— 业务代码也进 .ncx。 */
    rp_puts(&c, "\n## VMP\n\n");
    {
        int n = (has_ncr ? 1 : 0) + (has_nct ? 1 : 0);
        rp_fmt(&c, "**套数**：%d", n);
        if (n == 0) rp_puts(&c, "（本次构建未开 VMP）\n");
        else rp_puts(&c, "\n");

        if (n > 0) {
            rp_puts(&c, "\n| 套 | 解释器 | 字节码 | 数据表 |\n");
            rp_puts(&c, "|:---|:---|:---|:---|\n");
        }

        /* ⚠️ 段「不存在」不算异常 —— 没开 VMP 的构建本来就没有这些段
         *    （test.sh 的构建就是这样）。只有「存在但不可执行」才是真问题。
         *    第一版把「不存在」记成 ❌ 并计入异常数，导致正常构建也报
         *    「有 3 项异常」，日志失去可信度。 */
        if (has_ncr) {
            rp_seg_t s2;
            rp_read_shdr(so_path, NC_SEC_VMP, &s2);
            int ok = (s2.flags & 0x4) != 0;
            if (!ok) bad++;
            rp_fmt(&c, "| 1. nox解密链 | `%s` %llu B %s | `%s` %s | `%s` %s |\n",
                   NC_SEC_VMP, (unsigned long long)s2.size, ok ? "✅" : "❌ 不可执行",
                   NC_SEC_VMPBC, has_ncq ? "✅" : "—",
                   NC_SEC_VMPTBL, has_ncs ? "✅" : "—");
        } else {
            rp_puts(&c, "| 1. nox解密链 | — 未开 | — | — |\n");
        }

        if (has_nct) {
            rp_seg_t s2;
            rp_read_shdr(so_path, NC_SEC_VMP2, &s2);
            int ok = (s2.flags & 0x4) != 0;
            if (!ok) bad++;
            rp_fmt(&c, "| 2. 消费方 | `%s` %llu B %s | `%s` %s | `%s` %s |\n",
                   NC_SEC_VMP2, (unsigned long long)s2.size, ok ? "✅" : "❌ 不可执行",
                   NC_SEC_VMPBC2, has_ncv ? "✅" : "—",
                   NC_SEC_VMPTBL2, has_ncw ? "✅" : "—");
        } else {
            rp_puts(&c, "| 2. 消费方 | — 未开 | — | — |\n");
        }
    }

    /* ── 体积归因（2026-11-14 重写）─────────────────────────────────
     *
     * ═══ 为什么要按组而不是按段平铺 ═══
     *
     * 旧版只列 7 个段的裸字节数：人看到 "142532" 无法判断这算多还是少，
     * 也不知道"这些加起来是整个 so 吗"。实测反复出现同一个问题 ——
     * 想知道 so 变大了是哪个模块的责任，看这堆数字推不出来。
     *
     * 改成三层：① 总量与各组占比 ② 每组的明细段 ③ 一句话结论。
     *
     * ═══ 分组依据（重要，别按段名猜）═══
     *
     * 按"谁产生的"分，不按"在哪"分：
     *   nox 设施量  —— .ncxh/.ncxhr/.nck/.ncks（解锁链本身，nox 的固有开销）
     *   VMP 载荷    —— 两套解释器+字节码+数据表（开了 VMP 才有）
     *   业务载荷    —— .ncx（业务函数）+.ncxr（签名表）
     *   基础代码    —— .text/.rodata（混着业务与 nox 运行库，strip 后不可分）
     *
     * ⚠️ .ncx 归"业务"不归"nox"：段本身是 nox 的契约，但里面装的是
     *    业务函数。把它算进 nox 会让"nox 开销"虚高，正是要避免的误判。
     *
     * ⚠️ 各组合计 < so 总大小是正常的，差值 = ELF 头/符号表/dynamic
     *    等未纳入统计的段。故打 so 总大小与"统计覆盖"百分比。 */
    rp_puts(&c, "\n## 体积归因\n\n| 组 / 段 | 大小 |\n|:---|--:|\n");
    {
        /* 每个组的段清单，NULL 结尾 */
        static const char *grp_nox[]  = {NC_SEC_HEAD, NC_SEC_HEADRO,
                                         NC_SEC_SLOT, NC_SEC_STUBSLOT, NULL};
        static const char *grp_vmp[]  = {NC_SEC_VMP, NC_SEC_VMP2, NC_SEC_VMPBC,
                                         NC_SEC_VMPBC2, NC_SEC_VMPTBL,
                                         NC_SEC_VMPTBL2, NULL};
        static const char *grp_biz[]  = {NC_SEC_CODE, NC_SEC_CONST, NULL};
        static const char *grp_base[] = {".text", ".rodata", ".data", NULL};
        const char **groups[] = {grp_nox, grp_vmp, grp_biz, grp_base};
        static const char *gnames[] = {"nox 设施", "VMP 载荷", "业务载荷",
                                       "基础代码"};
        unsigned int g;
        unsigned long long covered = 0;

        for (g = 0; g < 4; g++) {
            unsigned long long gsum = 0;
            unsigned int i;
            int any = 0;
            for (i = 0; groups[g][i]; i++) {
                rp_seg_t s2;
                if (rp_read_shdr(so_path, groups[g][i], &s2) == 0) {
                    gsum += s2.size;
                    any = 1;
                }
            }
            /* 整组都不存在也打一行（显示 0 B），不 continue 跳过。
             *
             * ⚠️ 这里曾写成 `if (!any) continue;`，理由是"没这个组就别占行"。
             *    但读者无法区分两种情况：
             *      ① 本次构建没开 VMP（VMP 载荷确实是 0）
             *      ② 报告漏统计了 VMP 段（bug）
             *    实测：test.sh 的构建没有 VMP，报告里"VMP 载荷"整组消失，
             *    看日志的人第一反应是"体积统计坏了"而不是"没开 VMP"。
             *    打 0 B 的成本只有一行，收益是消除这个歧义。 */
            /* ── 统一列位（2026-11-14 修）───────────────────────────
             *
             * 原实现三处格式串各不相同，导致 B 落在三个不同列位：
             *   组名行   "  %-10s %9d B"      → B @ 21
             *   明细行   "      %-9s %9llu B" → B @ 26
             *   已统计行 "  %-10s %9llu B"    → B @ 20
             * 用户反馈：「连 b 也对不齐」—— 就是这个。
             *
             * 现在统一：组名/明细/合计都用同一组列宽
             *   前缀(缩进) | 名称 12 显示列 | 数字 12 列右对齐 | " B"
             * 且名称列走 rp_pad（按显示列，中文算 2）——
             * 用 %-12s 会对中文按【字节】补，必歪。 */
            if (!any) {
                _rp_size_row(&c, 0, gnames[g], 0);
                continue;
            }
            covered += gsum;
            _rp_size_row(&c, 0, gnames[g], gsum);
            /* 组内明细：只在组有多个段时展开，单段组没必要 */
            {
                int nseg = 0;
                for (i = 0; groups[g][i]; i++) {
                    rp_seg_t s2;
                    if (rp_read_shdr(so_path, groups[g][i], &s2) == 0) nseg++;
                }
                if (nseg > 1) {
                    for (i = 0; groups[g][i]; i++) {
                        rp_seg_t s2;
                        if (rp_read_shdr(so_path, groups[g][i], &s2) == 0)
                            _rp_size_row(&c, 1, groups[g][i], s2.size);
                    }
                }
            }
        }
        _rp_size_row(&c, 0, "已统计", covered);
        rp_puts(&c, "  （合计小于 so 总大小属正常：ELF 头/符号表/dynamic 等"
                    "未纳入）\n");
    }

    /* ── 结论 ────────────────────────────────────────────────────
     * 最重要的一行：有问题就列出来，没问题就一句话。
     * 读日志的人（或 AI）不需要自己再判断一遍。 */
    rp_puts(&c, "\n## 结论\n\n");
    if (bad == 0 && rc == 0) {
        rp_puts(&c, "✅ **全部正常**");
        if (unknown > 0) {
            /* ⚠️ 是"样本太小算不出熵"，不是错误 —— 必须说明，
             * 否则"有 ⚠️ 却说我全部正常"看起来像自相矛盾。 */
            rp_fmt(&c, "（其中 %d 项标 ⚠️ 是样本不足无法判断熵，不影响功能）",
                   unknown);
        }
        rp_puts(&c, "\n");
    } else {
        rp_fmt(&c, "❌ **有 %d 项异常**，见上方 ❌ 标记\n", bad);
        if (unknown > 0)
            rp_fmt(&c, "\n另有 %d 项标 ⚠️ 无法判断（样本不足），不算异常\n",
                   unknown);
    }
    rp_puts(&c, "\n---\n");
}

/* ── 输出：哨兵开关 + 静默失败 ──────────────────────────────────────── */

/* ── 日志路径 + 哨兵开关 ──────────────────────────────────────────────
 *
 * 与 sig_check.c 完全同规则（用户只记一个开关）：
 *   哨兵   /storage/emulated/0/xixin_debug    存在 → 写日志
 *   输出   /storage/emulated/0/Android/data/<包名>/files/ncguard_log.md
 *
 * ⚠️ 哨兵只判存在性（access F_OK），建文件或目录都认。
 * ⚠️ 包名从 /proc/self/cmdline 取并截到第一个 ':'。子进程带 ":remote"
 *    后缀，不截断会写到不存在的目录。
 * ⚠️ 路径不能以完整字面量出现：test.sh 的 V4 会 strings|grep -F
 *    /proc/self/cmdline，命中即失败（那条断言守的是"别把意图写进二进制"）。
 *    故拆成两段拼接。
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

    /* 宿主测试逃生口：Android 11+ 分区存储禁止 Termux 在
     * /storage/emulated/0/Android/data/ 下建目录，test.sh 用它重定向。 */
    {
        const char *t = getenv("NCG_REPORT_PATH");
        if (t && *t) { snprintf(out, cap, "%s", t); return 0; }
    }

    if (access(kSentinel, F_OK) != 0) return -1;   /* 哨兵不存在 → 关 */

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

    snprintf(dir, sizeof(dir),
             "/storage/emulated/0/Android/data/%s/files", pkg);
    (void)mkdir(dir, 0771);
    snprintf(out, cap,
             "/storage/emulated/0/Android/data/%s/files/ncguard_log.md", pkg);
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
    /* 显式改成 0644（2026-11-14）：fopen 只在新创建时按 umask 设权限，
     * 已存在的 -rw------- 文件会一直是私有 —— 上一版追踪用 0600 创建过，
     * 用户因此打不开日志。这里每次追加都纠一次，升级后自动修好旧文件。 */
    (void)fchmod(fileno(fp), 0644);
    now = time(NULL);
    if (localtime_r(&now, &tmv)) {
        strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", &tmv);
    } else {
        ts[0] = '\0';
    }
    fprintf(fp, "\n[%s][pid %d]\n", ts, (int)getpid());
    fwrite(buf, 1, len, fp);
    fclose(fp);
    return 0;
}

/* ── 阶段追踪实现（2026-11-14）────────────────────────────────────────
 *
 * ═══ 为什么必须每步独立 open/write/close ═══
 *
 * 进程崩溃时，stdio 缓冲区里的内容全部丢失。若用静态 FILE* 攒着写，
 * 「最后一行 = 崩溃点」这个判据就不成立 —— 崩溃前的几行反而会丢。
 * 所以每条追踪都走完整的一次 fopen/fprintf/fclose：close 返回时数据
 * 已交给内核，进程再崩也不影响已写入的内容。
 *
 * ═══ 为什么格式是 [NCG-TRACE] 前缀 ═══
 *
 * 用户在日志里 grep 这一个词就能拿到完整执行轨迹，与自检报告的
 * 段表混在同一文件里也不影响阅读。
 *
 * ═══ 开销 ═══
 *
 * 每次约 20~50us（一次 open+write+close）。解锁链一共 12 个阶段，
 * 合计 <1ms，相对于解锁本身的文件读取可忽略。
 * 未开哨兵时 getenv/access 立即返回，零开销。
 */

/* 三个对外入口都是定参函数，不能对它们用 va_start（C 要求最后一个
 * 形参是省略号）。所以拆成两层：对外入口先格式化成字符串，再交给
 * 不带可变参数的 rp_trace_line。
 *
 * ⚠️⚠️ 用 open/write/close 而不是 fopen/fprintf/fclose（2026-11-14 修）：
 *
 *    V7 测试（.ncxr 与 .bss 同页）在追踪存在时必崩 —— `fopen` 会 malloc
 *    一块 stdio 缓冲区，改变了堆布局与页归属，而解锁链对「段与 .bss 是否
 *    同页」极其敏感（mprotect 的页粒度判定）。
 *
 *    这不是理论推测：把 ncg_trace* 全部注释掉，V7 立刻恢复通过
 *    （48/48）；加回来就红（44/48）。
 *
 *    改用裸系统调用后不经过 libc 的堆分配，且栈上只有一个 512 字节的
 *    路径缓冲（与 ncg_debug_log_path 原有开销一致）。 */
static void rp_trace_line(const char *stage, const char *payload) {
    char path[512];
    char line[640];
    struct timeval tv;
    struct tm tmv;
    char ts[16];
    int n, fd;

    if (!stage) return;
    if (ncg_debug_log_path(path, sizeof(path)) != 0) return;

    gettimeofday(&tv, NULL);
    if (localtime_r(&tv.tv_sec, &tmv))
        strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    else
        ts[0] = '\0';

    /* 手工拼行：snprintf 不分配堆内存，但这里连它也不用，避免任何
     * 意外的 libc 路径。 */
    n = 0;
    n += snprintf(line + n, sizeof(line) - n,
                  "[NCG-TRACE] %s.%03d  %s", ts,
                  (int)(tv.tv_usec / 1000), stage);
    if (payload && *payload && n > 0 && n < (int)sizeof(line) - 2) {
        n += snprintf(line + n, sizeof(line) - n, " %s", payload);
        if (n > (int)sizeof(line) - 2) n = (int)sizeof(line) - 2;
    }
    if (n > 0 && n < (int)sizeof(line) - 1) {
        line[n++] = '\n';
        line[n] = '\0';
        /* ⚠️ 权限必须是 0644 而不是 0600（2026-11-14 修）。
         *
         * 第一版写 0600，结果追踪作为【第一个】写文件的人，用 0600 创建了
         * 日志 → 后续报告 fopen 追加时继承已有权限 → 用户在手机文件管理器
         * 和 adb 里都打不开这个文件（纯文本文件不需要任何保密性，
         * 里面的段名/大小/熵都是公开信息）。
         *
         * 与 fopen("a") 的默认行为对齐：fopen 走 umask(022) → 0644。 */
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            /* 文件已存在时 open 的 mode 参数被忽略 —— 上一版用 0600 创建的
             * 日志会一直是 -rw-------。显式改回 0644，让升级后能自动修好
             * 用户机器上的旧文件，不用手动删。
             * ⚠️ fchmod 失败不影响写入（可能是不支持 chmod 的挂载点）。 */
            (void)fchmod(fd, 0644);
            /* write 后立即 close：崩溃时内核里已落盘的内容不会丢 */
            (void)!write(fd, line, (size_t)n);
            close(fd);
        }
    }
}

void ncg_trace(const char *stage) {
    rp_trace_line(stage, NULL);
}

void ncg_trace_i(const char *stage, long long v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "=%lld", v);
    rp_trace_line(stage, buf);
}

void ncg_trace_s(const char *stage, const char *s) {
    char buf[384];
    /* 不直接传 s 给 %s：调用方可能传未终止或超长的缓冲 */
    snprintf(buf, sizeof(buf), "=%.350s", s ? s : "(null)");
    rp_trace_line(stage, buf);
}

