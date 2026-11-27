/* nc_guard_decoy.c — 诱饵段定义（零逻辑，只有占位）
 *
 * ═══ 这是什么，为什么存在 ═══════════════════════════════════════════
 *
 * 零信息静态逆向的固定流程是：readelf 看段表 → 认出哪组数据是真的 →
 * 逆那条链。段表把「哪个是真的」直接告诉了攻击者，这条路是免费的。
 *
 * 本文件提供 N 组【与真段逐项同构】的诱饵段，锁箱时由
 * so-section-lock.py --bait 填入自洽内容：
 *
 *   readelf -SW 里出现 N+1 组平行的 (head, slot, master) 三元组，
 *   权限（AXR/AR/WAR）、对齐、大小量级、命名风格全部一致。
 *   攻击者无法靠段表判断真假，必须逐组跑完整条派生链。
 *
 * ═══ 为什么诱饵必须「最后一步才失败」═══════════════════════════════
 *
 * 若诱饵解出来是垃圾，攻击者 5 秒就排除它 —— 诱饵等于没做。
 * 所以 --bait 保证：
 *   ① 诱饵槽的 expect_mac_head 用【诱饵自己的】k_mac_head 正确计算
 *      → 攻击者的 HMAC 校验会【通过】，他确信「走对了」
 *   ② 诱饵 head 里是从 .text 抄的【真实 ARM64 代码】
 *      → 解出来能反汇编，序言合法（sub sp / stp x29,x30），他确信「解开了」
 *   ③ 只有用诱饵 master 派生 k_so 去解 .ncx 时才失败
 *      → 此时他怀疑【自己实现错了】，回头反复调试那条错误路径
 *
 * 核心价值不是「挡住」，是「把时间转移到错误路径上」。
 *
 * ═══ 约束 ═══════════════════════════════════════════════════════════
 *
 * ⚠️ 只提供占位，不含代码、不参与解锁链路。真路径完全不引用这些符号。
 * ⚠️ head 诱饵用【函数 + .space】而不是数组：AXR（可执行）标志只能由
 *    函数产生，数组是 AR。属性不一致 = 段表直接暴露它是假的。
 * ⚠️ used + retain 不可省：--gc-sections 会回收无引用的段。
 * ⚠️ 段名必须与真段平行（.ncxh/.ncks/.ncxhr ↔ .ncxh0/.ncks0/.ncxhr0）。
 *    用 .decoy/.bait 这类名字等于在段表上写「我是假的」。
 * ⚠️ 组数用 NCG_BAIT_N 控制（默认 2）。每增一组约 +4.2KB 产物。
 */
#include "nc_guard_layout.h"

/* 诱饵组数。0 = 完全关闭（产物里不出现任何诱饵段）。
 * 测试用 -DNCG_BAIT_N=0 做「关掉后零诱饵段」的反向断言。 */
#ifndef NCG_BAIT_N
#  define NCG_BAIT_N 2
#endif

/* 诱饵 head 的填充字节数（不含函数序言本身，约 32 字节）。
 *
 * ⚠️ 必须【大于等于】真 .ncxh 的最大尺寸 —— 段只能缩小不能放大。
 *    实测真 .ncxh：
 *      arm64 无 VMP（example）      = 4048 B
 *      arm64 云端真包（含 Amice）   = 4052 B（2026-11-27 实测）
 *      v7a（32 位指令更密）          = 4444 B
 *    VMP 把解锁器逻辑抽到 .ncq 字节码里，.ncxh 本身【没有显著变大】——
 *    这点与直觉相反，所以余量取 16 KB 已足够（约 4 倍实测值）。
 *
 * ⚠️ 不要为了"保险"把它设成几十 KB：head 诱饵在【链接期】占这个体积，
 *    2 组就是 2×16KB，会让构建期 .so 虚胖（虽不影响最终产物，但拖慢
 *    链接、误导体积排查）。真正的边界由 fail-fast 守住 ——
 *    真段超了会明确报「需调大 NCG_BAIT_HEAD_PAD」，不会静默出错。 */
#define NCG_BAIT_HEAD_PAD  16352

/* 诱饵业务代码段（.ncxN）。必须也是 AXR（可执行）——真 .ncx 是代码段，
 * 用数组会变 AR，属性不同就等于在段表上标了「这条是假的」。
 *
 * ⚠️⚠️ 容量必须【覆盖真段的实际大小】，因为裁只能缩小不能放大。
 *    实测真 .ncx 大小差异极大：
 *      example 的 mycode.c      →   184 B
 *      云端真包（sigcheck+dex2c）→ 11344 B（2026-11-27 实测，当时设 8192
 *                                   → 锁箱 fail-fast 拒产，报
 *                                   「诱饵 .ncx0 无法裁到 11344B」）
 *    真实业务包的 .ncx 是「dex2c 产物 + VMP 壳」，几十 KB 很常见。
 *
 *    取 96 KB：够覆盖绝大多数单模块产物，且代价可接受 ——
 *      诱饵段本身在【链接期】占这个大小，但锁箱时会被裁到与真段同尺寸，
 *      所以【最终产物】只多出 N × 真段大小，不是 N × 96KB。
 *      唯一代价是编译期内存与 .so 的 file size（锁箱前），不影响分发体积。
 *
 * ⚠️ 若真 .ncx 超过本值，锁箱会 fail-fast 并明说「需调大
 *    NCG_BAIT_CODE_MAX」——不会静默产出残次品。这是刻意的：
 *    宁可变红，也不要「有诱饵段却没内容」（那本身是真段路标）。 */
#define NCG_BAIT_CODE_MAX 98304

#if NCG_BAIT_N >= 1
__attribute__((section(".ncxh0"), used, retain, noinline))
static void ncg_bait_head_0(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_HEAD_PAD));
}
__attribute__((section(".ncks0"), used, retain, aligned(1)))
const volatile unsigned char ncg_bait_slot_0[NC_STUB_SIZE] = {0};
__attribute__((section(".ncxhr0"), used, retain, aligned(16)))
volatile unsigned char ncg_bait_ro_0[32] = {0};
__attribute__((section(".ncx0"), used, retain, noinline))
static void ncg_bait_code_0(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_CODE_MAX));
}
#endif

#if NCG_BAIT_N >= 2
__attribute__((section(".ncxh1"), used, retain, noinline))
static void ncg_bait_head_1(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_HEAD_PAD));
}
__attribute__((section(".ncks1"), used, retain, aligned(1)))
const volatile unsigned char ncg_bait_slot_1[NC_STUB_SIZE] = {0};
__attribute__((section(".ncxhr1"), used, retain, aligned(16)))
volatile unsigned char ncg_bait_ro_1[32] = {0};
__attribute__((section(".ncx1"), used, retain, noinline))
static void ncg_bait_code_1(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_CODE_MAX));
}
#endif

#if NCG_BAIT_N >= 3
__attribute__((section(".ncxh2"), used, retain, noinline))
static void ncg_bait_head_2(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_HEAD_PAD));
}
__attribute__((section(".ncks2"), used, retain, aligned(1)))
const volatile unsigned char ncg_bait_slot_2[NC_STUB_SIZE] = {0};
__attribute__((section(".ncxhr2"), used, retain, aligned(16)))
volatile unsigned char ncg_bait_ro_2[32] = {0};
__attribute__((section(".ncx2"), used, retain, noinline))
static void ncg_bait_code_2(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_CODE_MAX));
}
#endif

#if NCG_BAIT_N >= 4
__attribute__((section(".ncxh3"), used, retain, noinline))
static void ncg_bait_head_3(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_HEAD_PAD));
}
__attribute__((section(".ncks3"), used, retain, aligned(1)))
const volatile unsigned char ncg_bait_slot_3[NC_STUB_SIZE] = {0};
__attribute__((section(".ncxhr3"), used, retain, aligned(16)))
volatile unsigned char ncg_bait_ro_3[32] = {0};
__attribute__((section(".ncx3"), used, retain, noinline))
static void ncg_bait_code_3(void) {
    __asm__ __volatile__(".space %c0, 0" :: "i"(NCG_BAIT_CODE_MAX));
}
#endif

/* 编译期自检。超界要在此补分支，否则 NCG_BAIT_N=5 会静默只生成 4 组 ——
 * 「以为加了一组其实没有」比编译失败危险。 */
_Static_assert(NCG_BAIT_N >= 0, "NCG_BAIT_N 不能为负");
_Static_assert(NCG_BAIT_N <= 4, "NCG_BAIT_N>4 需在本文件补分支");
_Static_assert(NCG_BAIT_HEAD_PAD % 32 == 0,
               "诱饵填充长度必须是 SHA-256 块长整数倍（CTR 加密要求）");
