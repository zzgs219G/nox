/* nc_guard_xor.c — XOR_KEY 重组（2026-11-06 从 nc_guard_boot.c 拆出）
 *
 * ── 为什么单独一个文件 ──────────────────────────────────────────────
 * VMP 与 annotate 属性互斥。
 *
 *   annotate 会把函数地址写进 @llvm.global.annotations 表，Amice 的
 *   vm_virtualize 因此判定该函数 "has non-call address uses" 并安全跳过。
 *   实测 CI 42075245237 的 debug 日志原文：
 *     skip function "ncg_xor_key": function has non-call address uses
 *
 *   Amice 只提供两种启用方式：
 *     ① annotate("+vm_virtualize")  → 逐函数，但有上面的地址引用冲突
 *     ② AMICE_VM_VIRTUALIZE=true    → 整个编译单元
 *   没有"按函数名指定"的第三方途径。
 *
 *   所以把需要 VMP 的函数拆到独立文件，对该文件用文件级全局开关：
 *   既不经过 annotate（无地址引用冲突），又不会波及 nc_guard_boot.c 里
 *   那一百多个无关函数（上次全局开关导致 .text 涨 92% 的教训）。
 *
 * ── 为什么拆这一个函数不牵动调用方 ──────────────────────────────────
 *   它只依赖 NC_OFF_FRAGS（来自 nc_guard_layout.h）与 NCG_XOR_FRAG（本文件），
 *   无 libc 调用、无其他内部函数依赖。三个调用点都是普通函数调用
 *   （ncguard_unlock / ncg_stub_recover），改成外部符号即可。
 */
#include <stdint.h>
#include <stddef.h>

#include "nc_guard_layout.h"

/* XOR 碎片的查表规则。表本身不构成独立泄露：没有 slot 里的真碎片，
 * 表只是排列规则（见 nc_guard_boot.c 的 XOR_KEY 碎片化说明）。 */
static const uint8_t NCG_XOR_FRAG[8] = NC_XOR_FRAG_INIT;

/* 从【调用方提供的已解密槽】里拼回 8 字节 XOR_KEY。
 *
 * ⚠️ 原实现直接读全局 ncg_slot_live（.bss 常驻明文）。现在改为由调用方
 *    传槽指针，调用方用完立刻擦 —— 不在任何地方留副本。
 * ⚠️ 不缓存结果（缓存=又一处常驻明文），每次重算，调用方用完必须 ncg_wipe。
 *
 * ⚠️ 非 static（2026-11-06 拆分）：跨编译单元调用。
 *    符号面由 -fvisibility=hidden 收敛，不会进 .dynsym。 */
void ncg_xor_key(const uint8_t *slot, uint8_t out[8]) {
    const uint8_t *fr = slot + NC_OFF_FRAGS;
    for (int i = 0; i < 8; i++) {
        uint16_t v = (uint16_t)(fr[NCG_XOR_FRAG[i] * 2]
                               | (fr[NCG_XOR_FRAG[i] * 2 + 1] << 8));
        out[i] = (i < 4) ? (uint8_t)(v & 0xFF) : (uint8_t)((v >> 8) & 0xFF);
    }
}
