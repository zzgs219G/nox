/* nc_guard_xor.c — XOR_KEY 重组（2026-11-06 从 boot.c 拆出）
 *
 * 为什么拆到独立文件：VMP 与 annotate 互斥，只有【文件级】
 * AMICE_VM_VIRTUALIZE 才能覆盖它，而 boot.c 不能整文件开 VMP。
 *
 * 碎片来源与诱饵的关系见 踩坑记录 K-02（两种藏法都实测无效）。 */
#include <stdint.h>
#include <stddef.h>

#include "nc_guard_layout.h"

/* XOR 碎片的查表规则。表本身不构成独立泄露：没有 slot 里的真碎片，
 * 表只是排列规则（见 nc_guard_boot.c 的 XOR_KEY 碎片化说明）。 */
static const uint8_t NCG_XOR_FRAG[8] = NC_XOR_FRAG_INIT;

/* 从调用方提供的已解密槽拼回 8 字节 XOR_KEY。
 * 碎片在 slot[104:112) 的 4 个 uint16 里，按 NC_XOR_FRAG 查表重组。
 * 写完必须由调用方 ncg_wipe。与 so-section-lock.py 逐字节同规则（T20 对拍）。 */
void ncg_xor_key(const volatile uint8_t *slot, uint8_t out[8]) {
    const volatile uint8_t *fr = slot + NC_OFF_FRAGS;
    for (int i = 0; i < 8; i++) {
        uint16_t v = (uint16_t)(fr[NCG_XOR_FRAG[i] * 2]
                               | (fr[NCG_XOR_FRAG[i] * 2 + 1] << 8));
        out[i] = (i < 4) ? (uint8_t)(v & 0xFF) : (uint8_t)((v >> 8) & 0xFF);
    }
}
