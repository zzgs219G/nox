/* nc_guard_crypto.c — boot_key 派生（2026-11-06 从 nc_guard_boot.c 拆出）
 *
 * ── 为什么单独一个文件 ──────────────────────────────────────────────
 * 要给 ncg_boot_key 上【指令级 VMP】，而 VMP 与 annotate 属性互斥。
 *
 *   annotate 会把函数地址写进 @llvm.global.annotations 表，Amice 的
 *   vm_virtualize 因此判定该函数 "has non-call address uses" 并安全跳过。
 *   实测日志原文（CI 42075245237）：
 *     skip function "ncg_xor_key": function has non-call address uses
 *
 *   Amice 只提供两种启用方式：
 *     ① annotate("+vm_virtualize")  → 逐函数，但有上面的地址引用冲突
 *     ② AMICE_VM_VIRTUALIZE=true    → 整个编译单元
 *   没有"按函数名指定"的第三方途径。
 *
 *   所以把需要 VMP 的函数拆到独立文件，对该文件用文件级全局开关：
 *   既不经过 annotate（无地址引用冲突），又不会波及 nc_guard_boot.c 里
 *   那一百多个无关函数。
 *
 * ── 为什么只搬 ncg_boot_key，不连带搬它的依赖 ──────────────────────
 *   ncg_boot_key 依赖两个辅助函数（都在 nc_guard_boot.c 的 .text 里）：
 *     ncg_stub_find_text   内嵌 open/pread/close/strcmp —— 重型 I/O
 *     ncg_boot_crc32       纯计算
 *   若一并搬进本文件并开 VMP，它们也会被虚拟化：体积暴涨、强度零收益
 *   （通用的 ELF 读取逻辑没有"配方"价值）。所以它们留在原地，
 *   只去掉 static 由 nc_guard_internal.h 提供声明。
 *
 * ── 搬走为什么安全（实测过，不是推断）──────────────────────────────
 *   ncg_boot_key 不碰 ncg_stub_slot，不靠 PC 相对寻址反推镜像基址 ——
 *   基址由调用方以 base 参数传入。跨编译单元调用只影响寻址方式，
 *   不影响它拿到的值。
 *
 *   （对照：ncg_slot_read 靠 &ncg_stub_slot 反推基址，改外部符号会让它
 *    从 PC 相对变成 GOT 间接寻址。那条风险在 docs/混淆计划.md §3.2，
 *    已实测验证反推结果仍正确，留给 P2。）
 *
 * ── ⚠️ 必须留在 .text（明文段）────────────────────────────────────
 *   本函数在 .ncxh 尚未解密时就要运行（stub 阶段要它算 boot_key 才能
 *   解 .ncks）。所以本文件【不加 section 属性】—— 加了就是"用密文解密文"，
 *   本仓库已踩过两次（head 段锁箱、master 解密的 RC4）。
 *
 *   代价：本函数体在静态视角下可读。这就是必须上 VMP 的原因 ——
 *   攻击者读懂它就等于拿到 boot_key 的配方。
 *
 * ── 与构建期的契约 ────────────────────────────────────────────────
 *   本函数与 so-section-lock.py 的 _derive_boot_key() 必须逐字节同规则：
 *     ikm  = CRC32(区间)(4B 大端) || 区间首 16B || 区间末 16B
 *     salt = NC_BOOT_SALT_INIT
 *     info = NC_BOOT_INFO ("nc-boot-v1")
 *   区间 = .text 起始连续 min(NC_BOOT_SPAN, .text 实际长度) 字节。
 *   改任一侧必须同步另一侧，否则产物在真机上解不开槽（症状是 SIGILL，
 *   不指向派生逻辑）。
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "nc_guard_layout.h"
#include "nc_guard_internal.h"
#include "nc_guard_key.h"        /* khkdf_sha256 */

/* 计算 boot_key（16 字节）。调用方用完必须 ncg_wipe。
 * 参数：so_path（由调用方用 dladdr 取得）、base（镜像基址）。
 * 返回 0 成功；-1 表示 .text 定位失败或区间配置错误（fail-closed）。
 *
 * ⚠️ 不加 NC_OBF（annotate）：本文件的 VMP 由 make-zip-lib.sh 用
 *    AMICE_VM_VIRTUALIZE=true 文件级开关控制，两者互斥（见文件头）。 */
int ncg_boot_key(const char *so_path, uintptr_t base, uint8_t out[16]) {
    ncg_shdr_t text;
    if (ncg_stub_find_text(so_path, &text) != 0) return -1;

    /* 区间长度自适应：取 min(上限, .text 实际长度)。
     * ⚠️ 2026-10-28 CI 踩坑：原先把 BACK+FWD 写成常量相加，
     *    armeabi-v7a 的 .text 只有 12000 字节 < 16384 → 锁箱 fail-fast。
     *    改成自适应后两个 ABI 都能工作，且与 Python 侧 take min 同规则。 */
    size_t span = (size_t)NC_BOOT_SPAN;
    if (span > (size_t)text.size) span = (size_t)text.size;
    if (span < (size_t)NC_BOOT_SPAN_MIN) return -1;   /* 区间过小，强度不足 */

    const uint8_t *lo = (const uint8_t *)base + text.addr;
    uint32_t crc = ncg_boot_crc32(lo, span);

    /* ikm = CRC(4B 大端) || 区间首 16B || 区间末 16B
     * 补首尾原始字节：4 字节 CRC 碰撞空间只有 2^32，补入原始字节
     * 可让敏感度接近全区间。 */
    uint8_t ikm[36];
    ikm[0] = (uint8_t)(crc >> 24); ikm[1] = (uint8_t)(crc >> 16);
    ikm[2] = (uint8_t)(crc >> 8);  ikm[3] = (uint8_t)crc;
    memcpy(ikm + 4, lo, 16);
    memcpy(ikm + 20, lo + span - 16, 16);

    static const uint8_t salt[16] = NC_BOOT_SALT_INIT;
    khkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                 (const uint8_t *)NC_BOOT_INFO, strlen(NC_BOOT_INFO),
                 out, 16);
    ncg_wipe(ikm, sizeof(ikm));
    return 0;
}
