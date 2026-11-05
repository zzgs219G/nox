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
#include <sys/mman.h>            /* mprotect：ncguard_stub_recover 用 */
#include <dlfcn.h>               /* Dl_info：本文件已不直接用，保留以免
                                  * 调用方头文件顺序变化时踩空 */

#include "nc_guard_layout.h"
#include "nc_guard_internal.h"
#include "nc_guard_key.h"        /* khkdf_sha256 / khmac_sha256 */

/* CTR 域分隔（2026-11-06 随 ncguard_stub_recover 上移到本文件）。
 * head 与 master 共用同一把 k_stub_eff，若都从 counter=0 起算即构成
 * two-time pad（密文 XOR 可还原明文 XOR）。dom 区分两段。
 * ⚠️ 与 so-section-lock.py 的 CTR_DOM_HEAD / CTR_DOM_HEADRO 必须逐一相等。 */
#define NC_CTR_DOM_HEAD    0x01
#define NC_CTR_DOM_HEADRO  0x02

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

/* ═══════════════════════════════════════════════════════════════════
 * 第二部分：二级锁箱的开箱本体（2026-11-06 从 boot.c 拆出）
 * ═══════════════════════════════════════════════════════════════════ */

/* 前向声明：ncguard_head_decrypt 调用它，但它的定义在文件靠后。 */
static void ncguard_headro_unlock(const uint8_t k[16],
                                  const volatile unsigned char *slot,
                                  uintptr_t img_base);

/* 改权限 → 解密 .ncxh → 交接明文区间 → 解 master（2026-11-06 第三次拆分）。
 * 与 ncguard_stub_recover / ncguard_head_mac_ok 同因：降寄存器压力。
 *
 * ⚠️ 时序与拆分前逐字对应，不可改：
 *    1. mprotect 成 RWX（失败 → return，段保持密文 → 调用即 SIGILL）
 *    2. ncg_ctr_xor 解 head（dom=0x01）
 *    3. clear_cache + 交接明文区间给 ncg_head_live
 *    4. 解 master 段（dom=0x02）
 *
 * ⚠️ mprotect 失败必须【立即 return】，不能继续解密 —— 那是 fail-closed
 *    与 fail-open 的分界（历史上这里曾漏查返回值，导致往只读页写 → SIGSEGV，
 *    且症状与"段被篡改"的 SIGILL 混淆，排查方向完全错）。
 * ⚠️ noinline 不可省（-Oz 会内联回去，拆分失效）。
 */
__attribute__((noinline))
static void ncguard_head_decrypt(const uint8_t k[16],
                                 const volatile unsigned char *slot,
                                 uintptr_t img_base,
                                 uint8_t *start, uint32_t head_size) {
    uintptr_t ps = getpagesize();
    uintptr_t s = (uintptr_t) start & ~(ps - 1);
    uintptr_t e = ((uintptr_t) start + head_size - 1 & ~(ps - 1)) + ps;
    if (mprotect((void *) s, e - s, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return;   /* 权限没改成功 → 不解密，段保持密文 → 调用即 SIGILL */
    }

    /* dom=0x01 与 master 段（0x02）分域，避免 two-time pad。 */
    ncg_ctr_xor(k, NC_CTR_DOM_HEAD, start, head_size);

    __builtin___clear_cache((char *) start, (char *)(start + head_size));

    /* 用后即毁的交接：把明文区间交给 .text 全局（head 自毁时读）。
     * volatile 写：该值跨"函数返回"被另一个 TU 段的代码读取，且时机在
     * 攻击者可见的窗口内，编译器不得缓存/重排。 */
    ncg_head_live = start;
    ncg_head_live_len = head_size;

    /* 解 master 段。失败不阻断 —— master 保持全零时 ncg_head_unlock
     * 会判定"未锁"返回 0（fail-safe：未锁状态下 .ncx 本就是明文）。 */
    ncguard_headro_unlock(k, slot, img_base);
}

/* 校验 .ncxh 密文的 HMAC（P0-b）。
 * 2026-11-06 从 ncguard_stub_recover 拆出 —— 与 ncguard_headro_unlock 同因：
 * 降低单函数寄存器压力，好让 VMP 能接受（原因见 ncguard_headro_unlock 注释）。
 *
 * ⚠️ 对【密文】算，不对明文算：密文在解密前就可读，所以可以"先验后解"；
 *    若对明文算就必须先解密再验，篡改的明文已经落盘生效，晚一步。
 *
 * ⚠️ k_mac_head 的恢复与 k_stub 同源（都是 wrapped ^ XOR_KEY）。
 *    调 khmac_sha256 不破坏"stub 无智力"约束 —— 它只是复用 .text 里
 *    现成的密码学原语，本函数仍没有 ELF 解析、RC4 S 盒、密钥派生。
 *
 * 返回 1 = 通过；0 = 不通过（或参数异常）。
 * 内部用完即擦 k_mac / got_mac，不给调用方留密钥材料。
 *
 * ⚠️ noinline 不可省：实测 -Oz 会内联回去，拆分即失效。
 */
__attribute__((noinline))
static int ncguard_head_mac_ok(const volatile unsigned char *slot,
                               const uint8_t *cipher, uint32_t cipher_len) {
    if (!slot || !cipher || cipher_len == 0) return 0;

    uint8_t k_mac[16], got_mac[32];
    {
        uint8_t xk[8];
        ncg_xor_key(slot, xk);
        for (int i = 0; i < 16; i++)
            k_mac[i] = (uint8_t)(slot[NC_OFF_K_MAC_HEAD + i] ^ xk[i & 7]);
        ncg_wipe(xk, sizeof(xk));
    }
    khmac_sha256(k_mac, 16, cipher, cipher_len, got_mac);

    const volatile unsigned char *want = slot + NC_OFF_EXPMAC_HEAD;
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (uint8_t)(got_mac[i] ^ want[i]);

    ncg_wipe(k_mac, sizeof(k_mac));
    ncg_wipe(got_mac, sizeof(got_mac));
    return diff == 0;
}

/* 解开 master 数据段（.ncxhr，32 字节）。
 * 2026-11-06 从 ncguard_stub_recover 拆出 —— 目的是降低单函数寄存器压力，
 * 好让 VMP 能接受它（原因见调用处的注释）。
 *
 * ⚠️ 必须与 ncguard_stub_recover 同在 .text（明文）：
 *    调用点仍在 .ncxh 尚未解密的时刻之前/之后紧邻，不能进加密段。
 * ⚠️ 调用纪律：只能用 .text 里的函数（ncg_ctr_xor 满足）。
 *    绝不能调 ncg_rc4 —— 它在 .ncxh 段里，此刻还是密文。
 *
 * 参数：
 *   k         已恢复的 k_stub（16 字节，调用方在用完后负责 wipe）
 *   slot      已解密的 .ncks 槽副本（只读，不解密它自己）
 *   img_base  镜像基址（调用方已算出）
 *
 * 失败处理（与拆分前一致）：段缺失 / 大小异常 / mprotect 失败 → 什么都不做，
 * master 保持全零 → ncg_head_unlock 检测到全零即判定"未锁"返回 0。
 * 这是 fail-safe 而非 fail-open：未锁状态下 .ncx 本就是明文。
 *
 * ⚠️⚠️ noinline 不可省：实测 -Oz 会把它整个内联回 ncguard_stub_recover，
 *    那样寄存器压力一点没降、拆分等于没做（拆完第一版就是这样，IR 里
 *    根本找不到这个函数的 define）。加 noinline 后才是两个独立的函数，
 *    各自过 VM 寄存器预算。
 */
__attribute__((noinline))
static void ncguard_headro_unlock(const uint8_t k[16],
                                  const volatile unsigned char *slot,
                                  uintptr_t img_base) {
    uint32_t ro_addr = ncg_rd32(slot + NC_OFF_HEADRO_ADDR);
    uint32_t ro_size = ncg_rd32(slot + NC_OFF_HEADRO_SIZE);
    if (ro_addr == 0 || ro_size == 0 || ro_size > (1u << 16)) return;

    uint8_t *ro = (uint8_t *)(img_base + ro_addr);
    uintptr_t ps = getpagesize();
    uintptr_t rs = (uintptr_t) ro & ~(ps - 1);
    uintptr_t re = ((uintptr_t) ro + ro_size - 1 & ~(ps - 1)) + ps;
    if (mprotect((void *) rs, re - rs, PROT_READ | PROT_WRITE) != 0) return;

    /* dom=0x02 与 head 段（0x01）分域，避免 two-time pad。 */
    ncg_ctr_xor(k, NC_CTR_DOM_HEADRO, ro, ro_size);

    /* ⚠️ 恢复成 RW 而不是 R —— 实测踩过：.ncxhr 与 .data/.bss 同页
     * （arm64：.data 0x13ca8、head_ro 0x13cd0、.bss 0x13cf0，同在页 0x13000）。
     * mprotect 粒度是页，设成 READ 会把 .bss 也变只读 → 之后任何 .bss
     * 写入即 SIGSEGV。这页本就是 RW，恢复 RW 才是还原原状；
     * 密文段的保护靠"内容是密文"，不靠页权限。 */
    (void) mprotect((void *) rs, re - rs, PROT_READ | PROT_WRITE);
}

/* 明文 stub：把 .ncxh 还原成明文。
 * 全程无循环展开以外的分支、无 libc 调用、无磁盘 I/O。
 * 未锁（slot magic 不匹配）时直接返回——段本就是明文。
 *
 * ⚠️ 2026-11-06：本函数已拆到 nc_guard_crypto.c 上 VMP。
 *    拆走的直接原因是【本函数原先取了自己的地址】：
 *        dladdr((const void *)&ncg_stub_recover, &info)
 *    Amice 的 vm_virtualize 会检查函数的所有 use，除"直接调用"和
 *    "@llvm.global.annotations" 之外一律判为 "has non-call address uses"
 *    并【静默跳过】该函数（crates/amice/src/aotu/vm_virtualize/mod.rs:128）。
 *    取自身地址传给 dladdr 正是这种 use，所以原样搬过去必然被跳过。
 *
 *    改法：把"取地址"移到调用方 ncguard_unlock（.text，不虚拟化）——
 *    它本来就已经为自绑定 CRC 算好了 so_path / base（见其定义处），
 *    这里改成参数传入，零额外成本、零新增依赖。
 *
 * ⚠️ 参数语义：
 *    so_path  自身的 .so 路径（由调用方 dladdr 取得，非 NULL）
 *    base     镜像基址（同上）
 *    两者都由调用方保证非空；本函数不再自己取。
 *
 * ⚠️ 时序约束（与拆分前完全一致，未变）：
 *    先验 MAC 再 mprotect 再解密；用后即毁。
 *    VMP 引入的 VM 帧（sub sp,sp,#0xc0）不影响这个顺序 —— 它只是把
 *    函数体编译成字节码，控制流语义不变。
 */
void ncguard_stub_recover(const char *so_path, uintptr_t base) {
    /* ── T4（2026-10-28 / 2026-10-29 修正）：解密槽到【本函数栈缓冲】───
     * 修正理由见 ncg_slot_read 上方注释：不再有 .bss 常驻明文副本。
     * 本函数用完即 wipe，全进程不留第二份。 */
    static int recovered = 0;
    if (recovered) return;                         /* 本进程已解过 */

    /* ⚠️ 2026-11-06：原先这里自己 dladdr(&ncg_stub_recover) 取路径与基址。
     * 那是一次"取自身地址"的 non-call use → VMP 判定跳过本函数。
     * 现在两个值由调用方 ncguard_unlock 传入（它本来就算好了）。 */
    if (!so_path || !base) return;                  /* fail-closed */

    uint8_t slot[NC_STUB_SIZE];
    if (ncg_slot_read(so_path, base, slot) != 0) {
        ncg_wipe(slot, sizeof(slot));
        return;                                    /* fail-closed */
    }

    /* 恢复 k_stub：slot[8:24] ^ XOR_KEY，再混入自身代码 CRC（阶段3 自绑定）。
     *
     * 混入方式刻意选【异或进密钥】而不是"算 CRC 后比较、不等就 return"：
     *   - 比较式：攻击者 patch 掉那条比较分支即可绕过（只多 1 处 patch）
     *   - 混入式：CRC 错了密钥就错，head 解出乱码 → 后续所有校验都失效，
     *     没有单点可以 patch 掉。这是"链式依赖"对"独立 patch"的本质差别。
     * 代码改一位 → CRC 变 → k_stub 变 → head 段解出乱码 → SIGILL。 */
    uint8_t k[16];
    {
        uint8_t xk[8];
        ncg_xor_key(slot, xk);
        for (int i = 0; i < 16; i++) k[i] = (uint8_t)(slot[8 + i] ^ xk[i & 7]);
        ncg_wipe(xk, sizeof(xk));
        /* 把 4 字节 CRC 折叠进 16 字节密钥（每 4 字节异或一次同一 CRC，
         * 保证 16 字节全部参与，且不引入额外依赖） */
        uint32_t crc = ncg_self_crc;
        for (int i = 0; i < 16; i++)
            k[i] ^= (uint8_t)((crc >> ((i & 3) * 8)) & 0xFF);
        crc = 0;
    }

    uint32_t stub_sh_addr = ncg_rd32(slot + 24);
    uint32_t head_sh_addr = ncg_rd32(slot + 28);
    uint32_t head_size    = ncg_rd32(slot + 32);

    /* 合理性守卫：任一为 0 或段大小荒谬 → 视为未锁/损坏，直接放弃 */
    if (head_size == 0 || head_size > (64u << 20)
        || stub_sh_addr == 0 || head_sh_addr == 0) return;

    /* 镜像基址 = slot 自身运行期地址 − slot 链接期地址。
     * &ncg_stub_slot 由编译器生成 PC 相对引用（adr/add），运行期天然正确，
     * 且该符号是 static —— strip .symtab 不影响它的可链接性（本地编译产物
     * 里 nm 看不到它，但代码照常引用）。这是绕开"符号表被 strip"的关键。 */
    uintptr_t img_base = (uintptr_t) &ncg_stub_slot - stub_sh_addr;

    /* head 段起始 = 基址 + head 段链接期虚拟地址 */
    uint8_t *start = (uint8_t *)(img_base + head_sh_addr);

    /* ── P0-b：先验 MAC 再解密（2026-10-18）──────────────────────
     * 2026-11-06 抽成独立函数 ncguard_head_mac_ok（降寄存器压力）。
     * ⚠️ 位置不变，仍在 mprotect / 解密【之前】：
     *    一旦 MAC 不符，head 一个字都不改 → 段保持密文 →
     *    后续调用踩密文 = SIGILL（fail-closed，与 .ncx 的 -11 语义对等）。
     * ⚠️ 返回值语义：1 = 通过；0 = 不通过或参数异常。
     *    不通过时必须【立即返回】且不解密，保持与拆分前完全一致的时序。 */
    if (!ncguard_head_mac_ok(slot, start, head_size)) {
        ncg_wipe(k, sizeof(k));
        ncg_wipe(slot, sizeof(slot));
        return;
    }


    /* ── mprotect + 解 head + 交接（2026-11-06 第三次拆分）──────────
     * 前两轮把峰值存活从 18 降到 14/13，仍超 32 的预算
     * （CI：values=14 Some(Xor) / values=13 Some(GetElementPtr)，
     *   spilled=1 used_spill_slots=1 —— 溢出槽也用到了极限）。
     * 剩余压力是算法本质：slot[112] + k[16] + start + head_size + img_base
     * 必须同时活到末尾，收窄作用域压不下去。所以把收尾整段移出去，
     * 本函数只做「准备 → 校验 → 委派」。 */
    ncguard_head_decrypt(k, slot, img_base, start, head_size);
    ncg_wipe(k, sizeof(k));
    /* ⚠️ 槽副本用完必须立刻擦（本函数是它唯一的生命周期边界）。
     *    这样 .bss / 栈上都不留密钥材料。 */
    ncg_wipe(slot, sizeof(slot));
    recovered = 1;
}
