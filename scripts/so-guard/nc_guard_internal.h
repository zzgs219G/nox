/* nc_guard_internal.h — so-guard 内部跨编译单元的声明（2026-11-06）
 *
 * 存在的唯一理由：`ncg_boot_key` 为提高 VMP 保护强度被拆到
 * `nc_guard_crypto.c`（VMP 与 annotate 互斥，只能走文件级开关，
 * 详见 nc_guard_xor.c 的文件头说明）。它需要 3 个仍留在
 * `nc_guard_boot.c` 里的辅助函数，故在此统一声明。
 *
 * ⚠️ 与 nc_guard_layout.h 的分工（不要混）：
 *   nc_guard_layout.h   契约常量 —— 零 include 零逻辑，会被拷进各种
 *                       NDK 工程。它描述的是【产物格式】。
 *   nc_guard_internal.h 内部函数声明 —— 只在本设施的几个 .c 之间用，
 *                       不构成对外契约，改它不影响任何历史产物。
 *   把声明塞进 layout.h 会破坏它"零依赖"的刻意约束。
 *
 * ⚠️ 本文件不参与"格式契约"，但仍有一条纪律：这里的函数签名是
 *    boot.c 与 crypto.c 共享的，改签名必须同时改两侧 —— 编译器会拦，
 *    不会静默。这正是把它抽成头文件的目的（此前是各写一份前向声明）。
 *
 * ⚠️ 符号可见性：这些函数都没有加 visibility("default")，生产构建
 *    （-fvisibility=hidden）下不会进 .dynsym。实测见 test.sh V2。
 */
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
 *    两者实测相等 → 反推结果不变。详见 docs/混淆计划.md §3.2。 */
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

#endif /* _NC_GUARD_INTERNAL_H_ */

