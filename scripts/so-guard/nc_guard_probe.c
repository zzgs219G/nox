/* nc_guard_probe.c — 密钥槽定义 + 样例消费者
 *
 * ⚠️ ncg_key_slot[96] 就是 .nck 段的全部内容。删掉它 = .nck 段消失 →
 *    ncguard_unlock() 返回 -3 → 段保持密文 → 探针踩密文 → SIGILL。
 *    （文件头曾写"验证通过后可整体删除"，那句是错的。）
 *
 * ncguard_probe() 是样例消费者，对拍契约 probe(0) == 59。
 * 新增消费者不需要改本文件，用 so_section_mark.py 按规则注入 attribute。 */

#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */

/* .nck 段的全部内容（布局见 nc_guard_layout.h）。
 * const volatile：writable 对象在 SHF_EXECINSTR 段里会让 LLD 生成 W+X 的
 *   PT_LOAD，Android 10+ 拒绝。const 让它进 .rodata（只读），运行时 mprotect 改写。
 * ⚠️ retain 不可省：lib-ldk.sh 含 --gc-sections，无引用的段会被连段回收。
 * ⚠️ 长度必须 == NC_SLOT_SIZE，否则锁箱侧 assert 炸。 */
__attribute__((section(NC_SEC_SLOT), used, aligned(1), retain))
static const volatile unsigned char ncg_key_slot[96] = {0};

/* 样例消费者：只有解锁后才能调用（解密前调用 = 执行密文 = SIGILL）。
 * retain 同密钥槽：防 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), used, retain))
int ncguard_probe(int token) {
    int acc = token;
    acc = (acc ^ 0x5A) + 0x0F;
    acc = (acc * 3) & 0xFF;
    return acc;
}

/* 查询"本 so 是否支持段加密机制"——只探测符号存在性，不碰 .ncx 内容。 */
int ncguard_available(void) {
    return 1;
}
