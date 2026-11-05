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

#endif /* _NC_GUARD_INTERNAL_H_ */
