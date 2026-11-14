/* nc_guard_internal.h — so-guard 内部跨编译单元的声明
 *
 * 只在本设施的 .c 之间用，不构成对外契约（改它不影响历史产物）。
 * 与 nc_guard_layout.h 分工：那边是【产物格式契约】（零 include 零逻辑），
 * 这边是【内部函数声明】。
 *
 * ⚠️ 这里的函数签名是 boot.c 与 crypto.c 共享的，改签名编译器会拦。
 * ⚠️ 全部无 visibility("default")，生产构建下不进 .dynsym（test.sh V2）。 */
#ifndef _NC_GUARD_INTERNAL_H_
#define _NC_GUARD_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>

/* 统一的段头表示（ELF32/ELF64 抹平后的产物）。
 * 定义原在 nc_guard_boot.c，2026-11-06 随 ncg_boot_key 拆文件上移到此处。
 * 字段含义与 Elf32_Shdr/Elf64_Shdr 对应，宽度统一到 64 位以免调用方
 * 关心 ELF class。 */
typedef struct {
    uint64_t addr;      /* 运行期/链接期虚拟地址 */
    uint64_t offset;    /* 文件偏移 */
    uint64_t size;
    uint32_t name_off;
    uint32_t flags;     /* sh_flags 在两种 ELF 里都是 32 位 */
} ncg_shdr_t;

/* ── 定义仍在 nc_guard_boot.c（.text 明文段）─────────────────────────
 * ⚠️ 这三个必须留在 .text：ncg_boot_key 在 .ncxh 尚未解密时就要跑，
 *    它调用的函数不能在任何加密段里，否则"用密文解密文"。
 *    （本文件已踩过两次：head 段锁箱、master 解密的 RC4） */

/* 在 ELF 文件里按名字找 ".text" 段，填 out。返回 0 成功。 */
int ncg_stub_find_text(const char *so_path, ncg_shdr_t *out);

/* CRC32（IEEE 802.3，多项式 0xEDB88320）。与 ncg_crc32 同算法但独立
 * 实现 —— 后者用于解密后的完整性基线，前者用于 boot_key 派生，
 * 两者调用时机不同（前者早于 .ncxh 解密）。不要合并成一个。 */
uint32_t ncg_boot_crc32(const uint8_t *p, size_t n);

/* 不可优化的清零（见定义处说明：memset 会被 -Oz 当死存储删掉）。 */
void ncg_wipe(void *p, size_t n);

/* ── 定义在 nc_guard_crypto.c（同样必须在 .text）────────────────────
 * 计算 boot_key（16 字节）。调用方用完必须 ncg_wipe。
 * 返回 0 成功；-1 = .text 定位失败或 CRC 区间过小（fail-closed）。
 * 与 so-section-lock.py 的 _derive_boot_key() 逐字节同规则。 */
int ncg_boot_key(const char *so_path, uintptr_t base, uint8_t out[16]);


/* ── 以下为 ncg_stub_recover 的依赖，定义仍在 nc_guard_boot.c ────────
 * 2026-11-06 拆 ncg_stub_recover 到 crypto.c 时上移到此处。
 * ⚠️ 全部必须在 .text（明文）：它们要在 .ncxh 尚未解密时就能用。 */

/* 二级密钥槽本体（.ncks 段）。crypto.c 用它反推镜像基址：
 *     img_base = (uintptr_t)&ncg_stub_slot - stub_sh_addr
 * ⚠️ 改外部符号后该引用从 PC 相对变成 GOT 间接（实测 4 对
 *    ADR_GOT_PAGE/LD64_GOT_LO12_NC），但 GOT 里存的就是段表 sh_addr，
 *    两者实测相等 → 反推结果不变。详见 docs/so防护架构.md §3.2。 */
extern const volatile unsigned char ncg_stub_slot[];

/* 小端读 32 位（slot 字段解析）。 */
uint32_t ncg_rd32(const volatile unsigned char *p);

/* SHA-256-CTR 加解密（head 与 master 两段，用 dom 分域）。
 * 与 so-section-lock.py 的 ctr_xor() 逐字节一致。 */
void ncg_ctr_xor(const uint8_t k[16], uint8_t dom, uint8_t *buf, uint32_t len);

/* 自身代码 CRC（由 ncguard_unlock 在调用 stub 前算好，stub 折进 k_stub）。 */
extern uint32_t ncg_self_crc;

/* 用后即毁交接区：stub 解出 .ncxh 明文后写这里，ncguard_unlock 消费。 */
extern volatile uint8_t  *ncg_head_live;
extern volatile uint32_t  ncg_head_live_len;

/* ── 定义在 nc_guard_crypto.c ─────────────────────────────────────────
 * 把 .ncxh 还原成明文。签名带 so_path/base 参数【而不是自己 dladdr】——
 * 取自身地址会被 VMP 判为 non-call use 并跳过（见 nc_guard_crypto.c 头）。
 * 返回 void；失败一律 fail-closed（段保持密文 → 调用即 SIGILL）。 */
void ncguard_stub_recover(const char *so_path, uintptr_t base);


/* 读 .ncks 并解出槽明文（stub 阶段唯一持有 boot_key 的地方）。
 * 返回 0 成功；-1 = fail-closed（调用方必须放弃解密）。 */
int ncg_slot_read(const char *so_path, uintptr_t base,
                  uint8_t out[]);

/* XOR_KEY 重组（定义在 nc_guard_xor.c）。从已解密的槽拼回 8 字节，
 * 调用方用完必须 ncg_wipe。 */
void ncg_xor_key(const volatile uint8_t *slot, uint8_t out[8]);

/* 还原 HKDF 的 boot label（定义在 nc_guard_key.c）。
 * 2026-11-06 P0：不再暴露 NC_BOOT_INFO 宏，避免明文字符串进 .rodata。
 * out 至少 10 字节；返回长度（不含 NUL），0 = 参数错误。 */
size_t ncg_label_boot(uint8_t *out, size_t cap);


/* ── 迁入 nc_guard_crypto.c 的解密链基础函数（2026-11-06）────────────
 * 报告 §5.2 点名的"明文函数"，逆向者靠它们读懂架构。迁入后随 crypto.c
 * 一起被 VMP 覆盖。⚠️ 仍必须在 .text（明文）：stub 阶段就要调用。 */

/* 魔数比对（报告 0x3f858）。返回 1 = 匹配（已锁箱）。 */
int ncg_magic_ok(const volatile unsigned char *got, const uint8_t seed[8]);

/* 小端读 32 位（报告 0x3fc80）。 */
uint32_t ncg_rd32(const volatile unsigned char *p);


/* ── 迁入 nc_guard_crypto.c 的包名/路径解析（2026-11-06）────────────
 * 报告 §5.2 点名 0x3ff9c（so→apk 路径）为明文。迁入前已把大栈数组
 * 缩小（256→128、8192→512），否则 VMP 会跳过。 */

/* 从 /proc/self/cmdline 取进程名（截到首个 ':'）。返回 0 成功。 */
int ncg_self_pkg(char *out, size_t cap);

/* 定位自身 APK 路径：先查 /proc/self/maps，再按 so 路径反推。 */
int ncg_find_apk_path(const char *so_path, char *out, size_t cap);

/* 包名指纹偏差（全 0 = 匹配）。刻意返回偏差而非 bool，避免可 patch 的判定点。 */
void ncg_pkg_fault(const uint8_t *slotdata, const char *pkg, uint8_t fault[8]);

/* 扫 /proc/self/maps 找 base.apk 路径（定义在 nc_guard_boot.c）。
 * ⚠️ 刻意放在【非 VMP 文件】：它有 13 个基本块 / 6 个 phi，
 *    在 VMP 文件里会因寄存器预算超限被跳过并刷告警日志。 */
int ncg_scan_maps_for_base_apk(const char *maps_path, char *out, size_t cap);



/* ── 自检报告（2026-11-13，nc_guard_report.c）─────────────────────────
 *
 * ⚠️ 全部在 .text 明文：解锁完成后才调用，需要读段表算熵。
 * ⚠️ 缓冲由调用方提供（栈上）—— 绝不能用全局数组，那会撑大 .bss，
 *    改变 .ncxhr 与 .bss 的页面归属 → ncg_page_has_writable_neighbor
 *    判定变化 → SIGILL（2026-11-13 实测，rc=132）。 */
#define NCG_REPORT_CAP 2560

/* 生成报告正文到 buf（NUL 结尾）。so_path = 自身路径。 */
/* img_base = dladdr 得到的 dli_fbase（镜像基址）。
 * ⚠️ 必须传：报告在解锁【之后】跑，段在内存里已解密而文件里仍是密文，
 *    只读文件会把"已解密的段"误报成密文。img_base==0 时退回读文件。 */
/* rc    = ncg_head_unlock 的返回码（0 成功；负数是失败原因，见 boot.c）
 * nseg  = 实际参与解锁的段数（与锁箱侧 --section 段数不一致 = MAC 必失败） */
void ncg_report_build(char *buf, size_t cap, const char *so_path,
                      uintptr_t img_base, int rc, int nseg);

/* 追加写入日志文件。哨兵不存在 / 任何 I/O 失败 → 返回 -1，调用方忽略。 */
int ncg_report_flush(const char *buf, size_t len);

/* ── 阶段追踪（2026-11-14）────────────────────────────────────────────
 *
 * 解决什么问题：崩溃时看不到任何日志。
 *
 * 此前报告只在 ncg_head_unlock 返回后生成一次 —— 如果解锁过程本身崩了
 * （SIGSEGV/SIGILL/SIGABRT），那个函数永远不返回，报告永远不写，用户
 * 只看到"App 闪退"三个字，不知道炸在哪一步。
 *
 * 做法：每个关键阶段【一进入就写一行到磁盘并 close】——
 * 不能攒着，攒着就等于没写（进程崩了缓冲区全丢）。崩在 N 步，
 * 磁盘上就有前 N-1 步的记录，最后一行就是崩溃点。
 *
 * ⚠️⚠️ 参数是【文案 ID】不是字符串（2026-11-14 改）：
 *
 *    旧签名 ncg_trace("U9 OK boot_key") 会把中文写进 .rodata，
 *    `strings` 一条命令就能拿到完整解锁流程（U1→U2→U3→U6→U7→U9→
 *    U11→U12→U14→U15）—— 等于送出一份解锁说明书。
 *
 *    现在只传 ID，文案在构建期被 gen-trace.py 加密成密文数组
 *    （与 nc_guard_paths.c 同一套机制），运行期解码后再写日志。
 *    买到的是「strings 扫不到路标词」，不是「不可还原」——
 *    key 与算法都在源码里，反汇编就能解。如实标注。
 *
 * ⚠️ 每条都独立 open/write/close，不用静态 FILE*：崩溃时静态指针的
 *    缓冲区内容会丢，而独立开关文件是原子的（write 后 close 即落盘）。
 * ⚠️ 所有失败静默。追踪本身绝不能成为新的崩溃源。
 * ⚠️ 只在哨兵文件存在时才写（与报告同一开关）。
 *
 * ⚠️ ID 顺序必须与 gen-trace.py 的 STAGES 严格一致。
 *    改动任何一条都要重跑生成器并同步下方枚举。 */
/* 枚举定义在 nc_guard_report.c 顶部的生成区块（由 gen-trace.py 产出），
 * 这里不重复定义 —— 两处定义会立刻撞名。 */

/* NCG_TR 文案 ID（顺序与 ncg_trace_tab 表一致，同一列表生成）*/
typedef enum {
    NCG_TR_U1_ENTER = 0,
    NCG_TR_U1_OK_PATH,
    NCG_TR_U1_FAIL,
    NCG_TR_U2_ENTER,
    NCG_TR_U2_OK_SIZE,
    NCG_TR_U2_FAIL,
    NCG_TR_U3_ENTER,
    NCG_TR_U3_OK_SIZE,
    NCG_TR_U3_FAIL,
    NCG_TR_U4_ENTER,
    NCG_TR_U4_OK,
    NCG_TR_U4_FAIL,
    NCG_TR_U5_ENTER,
    NCG_TR_U5_OK,
    NCG_TR_U5_FAIL,
    NCG_TR_U6_ENTER,
    NCG_TR_U6_OK_FD,
    NCG_TR_U6_FAIL,
    NCG_TR_U7_ENTER,
    NCG_TR_U7_OK_BYTES,
    NCG_TR_U7_FAIL,
    NCG_TR_U8_ENTER,
    NCG_TR_U8_STATE,
    NCG_TR_U9_ENTER,
    NCG_TR_U9_OK_BK,
    NCG_TR_U9_FAIL,
    NCG_TR_U10_UNLOCKED,
    NCG_TR_U10_LOCKED,
    NCG_TR_U11_ZERO,
    NCG_TR_U11_NONZERO,
    NCG_TR_U12_ENTER,
    NCG_TR_U12_OK_KSO,
    NCG_TR_U12_FAIL,
    NCG_TR_U13_NSEG,
    NCG_TR_U14_OK,
    NCG_TR_U14_FAIL,
    NCG_TR_U15_ENTER,
    NCG_TR_U15_OK,
    NCG_TR_U15_FAIL,
    NCG_TR_U16_DONE,
} ncg_tr;

/* RPT 文案 ID（顺序与 ncg_report_tab 表一致，同一列表生成）*/
typedef enum {
    RPT_TITLE = 0,
    RPT_LEGEND,
    RPT_UNLOCK_OK,
    RPT_UNLOCK_FAIL,
    RPT_FAIL_MAC,
    RPT_FAIL_KSO,
    RPT_FAIL_MPROT,
    RPT_FAIL_SLOT,
    RPT_FAIL_NOMEM,
    RPT_ENT_HDR,
    RPT_ENT_HINT,
    RPT_SEG_HDR,
    RPT_SEG_SEP,
    RPT_SEG_ABSENT,
    RPT_SEG_TINY,
    RPT_SEG_ROW,
    RPT_VMP_HDR,
    RPT_VMP_N,
    RPT_VMP_OFF,
    RPT_VMP_TBL,
    RPT_VMP_SEP,
    RPT_VMP1,
    RPT_VMP1_OFF,
    RPT_VMP2,
    RPT_VMP2_OFF,
    RPT_VMP_NOEXEC,
    RPT_SZ_HDR,
    RPT_SZ_NOX,
    RPT_SZ_VMP,
    RPT_SZ_BIZ,
    RPT_SZ_BASE,
    RPT_SZ_TOTAL,
    RPT_SZ_NOTE,
    RPT_CONCL_HDR,
    RPT_CONCL_OK,
    RPT_CONCL_UNK,
    RPT_CONCL_BAD,
    RPT_CONCL_BAD2,
    RPT_END,
    RPT_V_READFAIL,
    RPT_V_DECRYPTED,
    RPT_V_STILL_ENC,
    RPT_V_PLAIN_DATA,
    RPT_V_HIGH_ENT,
    RPT_V_CIPHER,
    RPT_V_NOT_ENC,
    RPT_V_ENC_LOCKED,
    RPT_V_PLAIN_INHERENT,
    RPT_V_DISK_PLAIN,
    RPT_T_EMPTY,
    RPT_T_UNREADABLE,
    RPT_T_PLAIN,
    RPT_T_CIPHER,
    RPT_ROLE_CODE,
    RPT_ROLE_VMP2,
    RPT_ROLE_BC2,
    RPT_ROLE_VMP1,
    RPT_ROLE_BC1,
    RPT_ROLE_TBL1,
    RPT_ROLE_CONST,
    RPT_ROLE_HEAD,
    RPT_ROLE_MASTER,
} rpt;


void ncg_trace(int id);

/* 带一个整数值的阶段（记录 rc、大小、偏移等），用于排障 */
void ncg_trace_i(int id, long long v);

/* 带字符串的阶段（记录路径、段名、错误描述） */
void ncg_trace_s(int id, const char *s);

/* 计算日志文件路径（哨兵 /storage/emulated/0/xixin_debug 存在才算开）。 */
int ncg_debug_log_path(char *out, size_t cap);

#endif /* _NC_GUARD_INTERNAL_H_ */
