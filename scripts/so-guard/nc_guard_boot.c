/* nc_guard_boot.c — 自解谜引导（明文 stub + 密文 unlock 本体）
 *
 * 三级结构（攻击面从外到内）：
 *   ① 明文 stub（.text）—— 攻击者唯一能直接读的部分
 *      只做：算 CRC → 读 slot → 验 magic → 恢复 k_stub → mprotect → XOR → 跳转
 *      无 ELF 解析 / 无 HMAC / 无 RC4 S 盒 / 无 slot 布局解释。
 *      ⚠️ -O2 会把 ncg_stub_recover 整个内联进 ncguard_unlock（无独立符号），
 *         实测 225 行反汇编 —— 比预期大，但仍"无智力"。
 *   ② 密文 unlock 本体（.ncxh，构建期锁箱）
 *      完整能力：ELF 段表解析、HMAC 校验、RC4 解密、页权限管理、证书派生
 *   ③ 密文业务段（.ncx / .ncxr，由 ② 负责解）
 *      dex2c 转译产物 + env_check 探针 + 判决核心
 *
 * ⚠️ 三条调用纪律（违反即死锁/崩溃，均有真机实测依据）：
 *   ① stub 只能调【.text 里】的函数。调 .ncxh 里的（如 ncg_rc4）会执行
 *      密文 → 卡死/SIGILL。
 *   ② ncg_head_unlock 及其私有函数绝不能标进 .ncx —— 开锁器锁进箱子。
 *   ③ ncVerify / heartbeat（nc_link.c）绝不能标段 —— 它们是 unlock 的
 *      调用方，标了即死锁。
 *
 * 未锁状态（锁箱器没跑过）也必须正常：slot magic 不匹配 → stub 直接返回，
 *   段是明文 → 本体照常执行 → 本体发现 .nck 无 magic → 返回 0。开发期可跑。
 *
 * 历史：本文件取代 nc_guard_unlock.c（后者已移入 archive/，逐条过期，
 *   不参与任何构建）。
 */
/* ⚠️ 跨平台：Linux（glibc）下 Dl_info / dladdr 是 GNU 扩展，必须先定义
 *    _GNU_SOURCE 才可见；Android 的 bionic 默认暴露它们，所以本文件
 *    在 Termux / NDK 上一直编译通过，到 Ubuntu CI 才炸：
 *        error: use of undeclared identifier 'Dl_info'
 *    这是典型的"本地永远绿的"盲区，靠 CI 在别的环境跑一次才暴露。
 *    必须写在【任何头文件之前】——glibc 的 feature_test_macros 只认
 *    第一次 include 时的定义。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
/* 提交二（2026-10-30）：自包含周期检测线程需要 pthread + nanosleep。
 * 本文件原先不依赖 pthread —— 新增这两个头是必要成本（见
 * ncg_code_watchdog_start 的注释：跨文件复用 env_check 的线程会让
 * 某些组合链接失败，故自带一份）。 */
#include <pthread.h>
#include <time.h>

#include "nc_guard_key.h"   /* khmac_sha256 */

/* 路径字面量走自带的密文表（2026-10-30 独立化）。
 *
 * 历史：此前复用 env_check.c 定义的 LSGS_PATH_CMDLINE / LSGS_PATH_MAPS
 *   宏，由主项目的 make-sig-log.py 统一生成 sig_log_data.h。那个做法省体积，
 *   但让本设施在编译期依赖 sigcheck 模块的产物 —— 单独拿设施编译会失败。
 *   现在改为 nc_guard_paths.c 自带两条路径的密文（只这两条，成本极低）。
 *
 * ⚠️ 为什么必须加密：这两个字面量所在函数虽标进 .ncxh，
 *    但 **C 的字符串字面量永远进 .rodata，不会跟着函数进自定义段**。
 *    实测确认：锁箱后 /proc/self/cmdline 仍在 .rodata 明文可搜。 */
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/slot尺寸/偏移/magic seed */
#include "nc_guard_internal.h" /* 跨 .c 的内部声明（ncg_shdr_t 等，2026-11-06）*/
/* ⚠️ 2026-10-30 独立化：原先 include "sig_log_data.h"（主项目 sigcheck 模块
 *    生成的表），那让本设施脱离主项目就编译不过。现改为自带的路径密文表。
 *    只有两条路径需要隐藏（cmdline / maps），自包含成本极低。
 *    强度边界见 nc_guard_paths.h 的文件头（混淆，非加密）。 */
#include "nc_guard_paths.h"
#include "nc_guard_internal.h" /* 跨 .c 内部声明（ncg_shdr_t / ncg_boot_key 等，2026-11-06）*/

/* ncg_xor_key 已拆到 nc_guard_xor.c（2026-11-06）：VMP 与 annotate 互斥
 * —— annotate 会把函数地址写进 @llvm.global.annotations，VMP 因此判定
 * "has non-call address uses" 并跳过（实测 CI 42075245237 的 debug 日志）。
 * 拆到独立文件后可用文件级 AMICE_VM_VIRTUALIZE，不经 annotate。 */
/* 声明已移至 nc_guard_internal.h（2026-11-06），此处不再重复 */

/* ── Amice 混淆标注（2026-11-05，可选）──────────────────────────────
 *
 * 组合 5 项，全部逐函数生效（不设全局 AMICE_* 环境变量 —— 那会波及
 * 同编译单元的所有函数，实测让 .text 涨 92%）。
 *
 *   +flatten            控制流平坦化 —— 唯一改变控制流结构的
 *   +mba                混合布尔算术 —— 算术等价替换，风险最低
 *   +shuffle_blocks     基本块乱序
 *   +split_basic_block  基本块拆分（默认 num=1，体积随 num 线性涨）
 *   +indirect_call      间接调用 —— 打断调用链
 *
 * 不选 VMP/BCF 的理由：VMP 体积 +300~500% 且崩溃后 pc 落在解释器里
 * 无法排查；BCF 让体积翻几倍且关键路径上有实打实的执行开销。
 * （ncg_xor_key 的 VMP 试验见 nc_guard_xor.c）
 *
 * ⚠️ flatten 会重排控制流，而这两个函数都在 constructor(50) 里。
 *    一旦有边界错误就是随机崩溃，且混淆后的反汇编我们自己也不好查。
 *    唯一有效验证是真机 selftest==59（CI x86_64 跑不了 ARM64）。 */
#if defined(NC_AMICE_ANNOTATE)
#  define NC_OBF \
     __attribute__((noinline, \
       annotate("+flatten"), \
       annotate("+mba"), \
       annotate("+shuffle_blocks"), \
       annotate("+split_basic_block"), \
       annotate("+indirect_call")))
#else
#  define NC_OBF
#endif

/* ── NC_VMP_FUNC（2026-11-12）：给 .ncxh 里的解锁器逐函数上 VMP ────────
 *
 * 背景：nc_guard_boot.c 不能整文件开 VMP（25+ 个无关函数含重型 I/O，
 * 体积会暴涨，见 make-zip-lib.sh 的清单注释）。但 .ncxh 里这 5 个函数
 * 是攻击者解开 .ncxh 之后直接读到的**全部内容**：
 *
 *   ncg_head_unlock      解 .ncx 的主流程
 *   ncg_rc4              RC4
 *   ncg_resolve_self     dladdr 取基址
 *   ncg_find_section     ELF 段查找
 *   ncg_apk_path_fault   APK 路径污染
 *
 * 实测依据（本轮零信息逆向）：它能走到 .ncx 门口，靠的正是读这些函数的
 * 明文反汇编 —— 具体是把 ncg_stub_descramble 的 16 次 XOR 循环误当成
 * .ncx 解密，算法判断错后停手。**VMP 这一层，它连误判的机会都没有。**
 *
 * ⚠️ 依赖本 fork 的 @llvm.used 豁免补丁（amice 040ce6c）。
 *    .ncxh 的函数带 used/retain，上游 Amice 会判 "non-call address use"
 *    并跳过。换回上游 bundle 时这 5 个会被**静默跳过**（构建仍绿），
 *    所以换 bundle 后必须跑 check-obf.sh 确认 VM 子段数。
 *
 * ⚠️ 与 NC_OBF 互斥使用：同一函数不能既 annotate "+flatten" 又
 *    "+vm_virtualize"（实测两者叠加会让 vm_virtualize 跳过该函数）。
 *    本宏只含 vm_virtualize，不要和其它 annotate 宏叠加。
 *
 * ⚠️ 不开时（无 NC_AMICE_ANNOTATE）宏为空 —— 与 NC_OBF 同款，
 *    保证不用 Amice 的构建路径行为不变。 */
#if defined(NC_AMICE_ANNOTATE)
#  define NC_VMP_FUNC \
     __attribute__((noinline, annotate("+vm_virtualize")))
#else
#  define NC_VMP_FUNC
#endif

/* ── 契约常量：与 so-section-lock.py 共享，改一处必须同步另一侧 ── */
/* 常量表专用段（2026-10-19）：签名表的 salt/期望值放这里。
 * 为什么不能放 .ncx：那是 AXR（可执行）段，clang 拒绝让 const 数据
 * 进去（'causes a section type conflict'）。本段是 AWR，不可执行。
 * 与 .ncx 共用同一把 k_so 和同一个 MAC —— 逻辑上是同一份资产。 */
/* ⚠️ 2026-10-19：magic 不再以明文字面量出现在 .rodata。
 *
 * 原实现是字符串常量 "NCKEYLOCK"/"NCSTUBLK"，`strings -n 6` 直接扫出
 * （实测旧产物可见 3 条，含半边 "NCSTUBLKEM"）。现在锁箱器往 slot 写
 * 8 字节【随机种子】，运行期逐字节比较（ncg_magic_ok）。
 *
 * ⚠️ 别高估这层（2026-10-20 修正过一处夸大表述）：
 *   碎片密钥【不参与】magic 比较（ncg_magic_ok 只做 got[i]^seed[i] 累或）。
 *   攻击者 dump 到 slot 前 8 字节即可与代码里的种子直接比对，零额外成本。
 *   本机制的真实收益只有一条：strings 搜不到 "NCKEYLOCK"/"NCSTUBLK" 字面量
 *   —— 买的是"自动扫描失效"，不是"人工逆向成本"。
 *
 * 两侧契约：本文件的 NC_SEED_*（来自 nc_guard_layout.h）与
 *   so-section-lock.py 的 SLOT_MAGIC_SEED / STUB_MAGIC_SEED 必须逐字节一致。
 *   该 py 文件有 assert seed ^ XOR_KEY == b'NCKEYLOC' 自校验，但那只验
 *   Python 自我一致、不校验 C 侧 —— 跨语言对拍由 test-so-lock.sh T20 负责。
 *
 * ⚠️ 数组名保留 NCG_ 前缀：它是本文件私有符号，不属于跨语言契约
 *   （契约是"值"，不是"C 变量叫什么"）。改符号名会改变 .rodata 布局，
 *   使 T22 的二进制等价性验证失效。 */
static const uint8_t NCG_MAGIC_SEED_SLOT[8] = NC_SEED_SLOT_INIT;
static const uint8_t NCG_MAGIC_SEED_STUB[8] = NC_SEED_STUB_INIT;
int ncg_magic_ok(const volatile unsigned char *got, const uint8_t seed[8]);

/* 不可优化的清零（实现在第二部分 .text）。前向声明：密钥清零调用点
 * 在 .ncxh 段的 ncg_head_unlock 里，而本函数在 .text —— 两侧都必须能
 * 相互引用，靠 PC 相对寻址天然正确。详见定义处的说明。 */
void ncg_wipe(void *p, size_t n);

/* 提交二（2026-10-30）：完整性基线采集。定义在第二部分 .text，
 * 调用点在 .ncxh 段的 ncg_head_unlock —— 同 ncg_wipe 的理由需前置声明。
 * NC_CODE_SEG_MAX 必须在此可见（ncg_head_unlock 里用它开栈数组），
 * 故与声明一并前置；定义处有同名 #define 会冲突，故只保留此处一份。 */
#define NC_CODE_SEG_MAX 4   /* 最多跟踪 4 段（当前用 2：.ncx + .ncxr）*/

__attribute__((noinline))
static void ncg_baseline_init(uint8_t *const *addrs, const uint32_t *sizes,
                              int nseg);

/* ── slot 布局与尺寸：唯一真相源在 nc_guard_layout.h ──────────────
 * 本文件不再画布局图。2026-10-20 删除的原因：此处原有【三份】slot 布局图
 * （88 字节版 / 96 字节版 / 104 字节版），与 nc_guard_layout.h 的 NC_OFF_*
 * 构成多权威——扩容时改宏不改图，图就变成错的，而"权威的错图"比没有图
 * 更坏（AI/人会照着它改代码）。
 * 现行：段名看 NC_SEC_*，.nck 尺寸看 NC_SLOT_SIZE，.ncks 尺寸看
 * NC_STUB_SIZE，字段偏移看 NC_OFF_*。该头文件带 _Static_assert 挡偏移重叠，
 * 且 so-section-lock.py 从中抽取、test-so-lock.sh T20/T21/T22 对拍。
 *
 * 保留两条 layout.h 里没有的历史信息（防止"当初为什么这么设计"失传）：
 *   · .nck[80:88] 存 SHA256(包名) 前 8 字节而非明文包名：k_so 派生需要
 *     构建期那个包名，但明文会暴露"密钥与包名有关"这条线索。
 *   · .ncks 扩到 104 而非复用 [44:48) reserved：那里只有 4 字节，装不下
 *     addr+size 两个 u32；硬塞会与 expect_mac_head 重叠——那种重叠是
 *     【静默】破坏 MAC 校验的，编译期不报。 */

/* 为什么 head 段也要算 MAC（P0-b，2026-10-18；安全设计理由，勿删）：
 *   在此之前 head 段只有简单 XOR。攻击者可以改 head 密文中对应"unlock 本体
 *   的 MAC 校验函数"的那几位 → 解密后 unlock 本体还在，但它对 .ncx 的校验
 *   被改成恒真 → .ncx 的 HMAC 保护被绕过。这是具体路径，不是理论风险。
 *   加 MAC 后：改任何一位 → HMAC 不符 → 不解密 → head 保持密文 →
 *   调用即 SIGILL（与 .ncx 的 -11 语义完全对等）。
 *   MAC 对【密文】算，与 .ncx 一致：解密前就能验，验不过就不装明文。
 *
 * （原此处还有一份 88 字节旧版布局图作"历史存档"，2026-10-20 删除——
 *  它构成了第二份布局描述，与 nc_guard_layout.h 形成双权威。） */


/* ── XOR_KEY 碎片化（与 so-section-lock.py 的 XOR_KEY 逐字节对应）────────
 *
 * 完整 8 字节密钥从不在 .rodata 里连续出现。原实现是一整串常量，
 * HEX 搜索直接命中（实测 7e31a50dc8924bf6 在 so 里明文出现 2 次）。
 *
 * 现行机制（2026-10-21 起）：
 *   · 真碎片在【slot 碎片区】NC_OFF_FRAGS([104:112))，锁箱器每次构建随机生成；
 *   · 本文件的 ncg_frag_a/b/c/d 是【诱饵】——随机初值、参与假运算、
 *     防 gc-sections 回收；攻击者读 .data 拼出的是随机值，与真 XOR_KEY 无关。
 *     保留它们还兼作 diff 掩护（每次构建都在，看起来仍像老机制）。
 *   · NCG_XOR_FRAG 查表仍在 .rodata（编译期常量）。表本身不构成独立泄露：
 *     没有 slot 里的真碎片，表只是排列规则。
 *
 * 演进教训（别退回旧做法）：
 *   ① 4 个 uint16 各放一个 noinline static 函数 —— 不管用。LLVM 做函数间
 *      常量传播，把完整 8 字节密钥写回 .rodata（实测 boot.o 0x5b0/0x5b8）。
 *      只有 volatile 这类标准级屏障才真阻止折叠。
 *   ② 碎片放 .data 常量也不行 —— 破解复盘实测"objdump 读 .data + 反汇编
 *      5 分钟重组出 XOR_KEY"。真碎片必须来自构建期随机（即 slot 碎片区）。
 *
 * ⚠️ 2026-10-22 删除一条【从未成立】的"反向纪律"（原第 128-132 行）。
 *   原文宣称："key16 中间值经栈偏移 [sp+0x40] 在函数间隐式传递，IDA/r2
 *   追不到源，这层白捡的防御是 -Oz 栈分配的副产品"。
 *
 *   核实后该表述有两处问题，故删除：
 *   ① 【归因错】。破解复盘报告说的 [sp+0x40] 是 ncg_head_unlock 里
 *      pread(fd, slotdata, 96, slot.sh_offset) 的 offset 参数 —— 那是
 *      Elf64_Shdr 结构体跨函数传递落在栈上的字段，属正常编译产物，
 *      不是"刻意设计的隐式传参"。报告作者把它误读成混淆手法。
 *   ② 【现象已不存在】。实测当前产物（-Oz）：ncg_xor_key 是【孤立函数】
 *      （nm 可见独立符号，ncguard_unlock 内对它的 bl 调用 = 0 次，
 *      所有调用点都被内联），不存在"跨帧栈槽传递密钥"。
 *
 *   为什么不试图恢复它：它依赖 -Oz 的栈分配决策，编译器一升级就可能变；
 *   而源码注释一旦宣称"我们有这层防御"，后续所有加固判断都会建立在
 *   错误前提上（正是本条注释过去几轮造成的问题）。不可维护的防御
 *   不该写进注释当保障。冻结靠 T22（二进制等价）仍然有效，但 T22 只能
 *   验证"改动前后一致"，验证不了"某个编译器副产品还在"。
 *
 *   真正强的防线是 CRC 自绑定（见 ncg_self_crc）：改 .text 任一字节 →
 *   CRC 变 → k_stub 变 → .ncxh 解出垃圾 → SIGILL。破解复盘 v2 做了
 *   对照实验证实（改一条正常运行 100% 不可达的指令仍 SIGILL），
 *   且它试图绕过（重加密 .ncxh）仍失败 —— 因为它漏了 .ncxhr 也依赖
 *   k_stub。那条靠的是链式依赖，不是误导。
 *
 * 存放约定：逻辑字节 i<4 取第 NCG_XOR_FRAG[i] 个 uint16 的低 8 位；
 *   i>=4 取高 8 位。 */

static volatile uint16_t ncg_frag_a = 0x51a3u;
static volatile uint16_t ncg_frag_b = 0xe27bu;
static volatile uint16_t ncg_frag_c = 0x9c47u;
static volatile uint16_t ncg_frag_d = 0x30d9u;

/* 诱饵消费点：让 ncg_frag_* 有"可观测的使用"（防 --gc-sections 回收，
 * 历史上真实踩过），结果丢弃。noinline 防 -O2 把假运算折叠成常量。 */
__attribute__((noinline, used))
static uint32_t ncg_decoy_sink(void) {
    uint32_t acc = (uint32_t)ncg_frag_a << 16 | ncg_frag_b;
    acc ^= (uint32_t)ncg_frag_c << 8;
    acc += ncg_frag_d;
    return acc;
}

/* 运行期从 slot 碎片区拼回 8 字节密钥。每次调用重算、不缓存
 * （缓存就是又把密钥写进内存某处）。调用方用完必须 memset 擦除。
 * 前向声明：ncg_stub_slot 定义在第二部分，与本函数同在 .text，
 * PC 相对引用不受定义顺序影响。 */
extern const volatile unsigned char ncg_stub_slot[NC_STUB_SIZE];

/* ── T4：解密后的槽副本（2026-10-28）──────────────────────────────
 * 为什么需要它：.ncks 段在文件里已是密文，运行期只读且与邻段同页，
 * 不能原地解密（详见 ncg_stub_recover 里的说明）。
 * 所以解密结果放在这里，所有字段读取一律走这个副本。
 *
 * ⚠️ 必须在 ncg_stub_recover() 解密后才有有效内容。
 * ⚠️ 未锁箱（开发期）时由 ncg_stub_recover 直接 memcpy 原段，
 *    所以本缓冲在两种状态下都有效。
 * ⚠️ 这是一份密钥材料的明文副本，用完不擦（ncguard_unlock 还要读）；
 *    全进程只存在一次，与既有 threat model 一致（原本明文就在段里）。 */
/* ── T4 安全审计与修正（2026-10-29）───────────────────────────────────
 *
 * 审计发现（自查，非外部提出）：
 *   把解密结果放进 .bss 全局变量 ncg_slot_live，等于让【112 字节全部
 *   密钥材料在进程生命周期内常驻明文内存】。这比 T4 之前更糟：
 *   以前攻击者还要算 XOR_KEY，现在有内存读能力者（frida/ptrace）
 *   直接 read(.bss) 就拿到全部材料。
 *
 * 修正：改为【按需解密到调用方栈缓冲 + 用完即毁】。
 *   · 不再有全局明文副本
 *   · 每个调用点在栈上开自己需要的那块，读完后立刻 ncg_wipe
 *   · 代价：boot_key 需重算（已缓存，见下方 g_boot_key_cache 的取舍）
 *
 * ⚠️ 关于是否缓存 boot_key：
 *   缓存 = 又一处常驻明文。但每次重算要跑 CRC(16KB) + HKDF ≈ 十几微秒，
 *   三个调用点共约 50 μs，只在 constructor 跑一次 —— 不缓存更安全。
 *   → 决定：不缓存。
 */

/* 解密 .ncks 到调用方提供的缓冲。返回 0 成功。
 *
 * 为什么不直接返回指针：返回指针必然指向某块长期存活的内存（要么全局
 * 要么堆），都违背"用完即毁"。强制调用方给栈缓冲，用完必须 ncg_wipe。
 *
 * ⚠️ 未锁箱（开发期）：直接把原段明文拷过来，行为与改动前一致。 */
/* ncg_boot_key 的前向声明已移到 nc_guard_internal.h（2026-11-06 拆文件）。
 * 定义现在 nc_guard_crypto.c —— ncg_slot_read 仍在本文件调用它。 */

__attribute__((noinline))
int ncg_slot_read(const char *so_path, uintptr_t base,
                         uint8_t out[NC_STUB_SIZE]) {
    /* 先看 magic（明文区）判断是否已锁。
     * ⚠️ 必须经 volatile 读：ncg_stub_slot 是 const 且初值 {0}，
     *    -Oz 会把普通读折叠成常量 0（实测踩过）。 */
    {
        const volatile unsigned char *src = ncg_stub_slot;
        for (int i = 0; i < NC_OFF_FRAGS_ENC; i++)
            out[i] = (uint8_t)src[i];
    }
    if (!ncg_magic_ok(ncg_stub_slot, NCG_MAGIC_SEED_STUB)) {
        /* 未锁：原段就是明文，直接拷（同样要避 const 传播） */
        const volatile unsigned char *src = ncg_stub_slot;
        for (int i = 0; i < NC_STUB_SIZE; i++)
            out[i] = (uint8_t)src[i];
        return 0;
    }
    if (!so_path || !base) return -1;

    uint8_t bk[16];
    if (ncg_boot_key(so_path, base, bk) != 0) return -1;

    /* ⚠️ RC4 就地内联，不调独立函数（见下条审计项）：
     *    独立的 ncg_boot_rc4 是可 hook 的单一切入点，
     *    hook 它的入参即可同时拿到 boot_key 与明文槽。 */
    {
        uint8_t S[256];
        const uint8_t *key = bk;
        int i, j;
        for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
        for (i = 0, j = 0; i < 256; i++) {
            j = (j + S[i] + key[i % 16]) & 0xFF;
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        }
        i = j = 0;
        for (size_t n = 0; n < (NC_STUB_SIZE - NC_OFF_FRAGS_ENC); n++) {
            uint8_t c;
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
            c = S[(S[i] + S[j]) & 0xFF];
            out[NC_OFF_FRAGS_ENC + n] =
                (uint8_t)(((const volatile unsigned char *)ncg_stub_slot)
                              [NC_OFF_FRAGS_ENC + n] ^ c);
        }
        ncg_wipe(S, sizeof(S));
    }
    ncg_wipe(bk, sizeof(bk));
    return 0;
}




/* ── T4：boot_key 派生（2026-10-28）─────────────────────────────────
 *
 * 作用：用 .text 的内容派生一把钥匙，加密 .ncks/.nck 两个槽段。
 * 攻击者拿到 so 后，两个槽不再是"读 8 字节就有"的明文表，而必须先
 * 反汇编 stub、复现本函数的运算链。
 *
 * ⚠️ 关于"是否循环依赖"（此处曾误判，记录以免后人再绕）：
 *    boot_key 要算 CRC32(.text)，而 .text 的地址似乎"存在 .ncks 里"。
 *    但实测：段表【从来没有被加密】，ncg_find_section() 直接 open 自身
 *    读 ELF 头就能拿到 .text 的 addr/size，与 .ncks 无任何关系。
 *    → 无循环依赖。用 find_section 即可，不需要 PC 相对锚点那套。
 *
 * 前提（必须成立）：.text 区间内无重定位，否则"锁箱期按文件算的 CRC"
 * ≠ "运行期按内存算的 CRC" → 正常包也解不开。test-so-lock.sh T31 断言。
 * 实测本产物 .text 内重定位数 = 0（readelf -r 全部落在 .text 之外）。
 *
 * 本函数与 Python 侧 _derive_boot_key() 必须逐字节同规则。 */

/* 前向声明：ncg_find_section 定义在第一部分（.ncxh 内），但 T4 的
 * ncg_boot_key 需要在 stub 阶段用它定位 .text —— 那时 .ncxh 尚未解开，
 * 所以不能调它！
 *
 * ⚠️⚠️ 这里必须用【独立的、不依赖 .ncxh 的实现】：
 *     ncg_find_section 在 .ncxh 段里，stub 调它会执行密文 → SIGILL。
 *     所以下面另写一个最小实现，只读 ELF 头 + 段表，与它逻辑相同但
 *     编译进 .text。这是"stub 只能调 .text 函数"纪律的直接后果。 */
/* ── ELF32/ELF64 统一抽象（2026-11-02）────────────────────────────────
 *
 * 为什么必须有它：`APP_ABI := armeabi-v7a arm64-v8a`，v7a 产物是
 * **ELF32**（实测 `Class: ELF32 / Machine: ARM / shentsize 40`），
 * 而本文件原先所有解析都硬编码 `Elf64_Ehdr` / `Elf64_Shdr`。用 ELF64
 * 结构读 ELF32 文件会得到：
 *     e_shoff  = 0x28000900200034   （真实 0x335a8，把 e_phoff+e_shoff
 *                                    两个 32 位字段拼成一个 64 位读）
 *     e_shstrndx = 0
 *     → pread(shstrtab) 读回 0 字节 → find_text 返回 -1
 *     → ncg_boot_key 返回 -1 → ncg_slot_read 失败
 *     → .ncks/.nck 保持密文 → ncg_head_unlock() 执行密文 → SIGILL
 * 即 **32 位设备上加固包启动即崩**，且症状（SIGILL 在 .ncxh）完全不
 * 指向"ELF 解析读错字段"。已用最小复现钉死。
 *
 * 设计选择：本文件【不放逻辑进 nc_guard_layout.h】——那是常量契约文件，
 * 零 include 零逻辑是刻意约束（它会被拷进各种 NDK 工程）。所以这层
 * 抽象留在 boot.c 的 .text 段。
 *
 * ⚠️ 必须放在 .text（明文）：T4 的 ncg_boot_key 要在 .ncxh 尚未解密时
 *    就算出来，而 .ncxh 里的 ncg_find_section 也消费同一套读段函数。
 *    两边都调它，它自己不能在任何加密段里，否则"用密文解密文"。
 *
 * ⚠️ 2026-11-06：`ncg_shdr_t` 的定义已上移到 nc_guard_internal.h ——
 *    ncg_boot_key 拆到 nc_guard_crypto.c 后两侧都要用这个类型。
 *    此处只保留说明，不再重复定义（重复定义会编译报错，好事）。 */

int ncg_stub_find_text(const char *so_path, ncg_shdr_t *out);

/* CRC32（IEEE 802.3）—— 与第二部分 ncg_crc32 同算法，此处前置实现，
 * 因为 stub 阶段的调用顺序早于第二部分定义。
 * ⚠️ 2026-11-06 去掉 static：ncg_boot_key 已拆到 nc_guard_crypto.c，
 *    跨编译单元调用。符号面由 -fvisibility=hidden 收敛，不进 .dynsym。 */
uint32_t ncg_boot_crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

/* 读 ELF 头，把差异抹平。返回 0 成功。 */
static int ncg_elf_hdr(int fd, uint8_t *cls_out, uint64_t *shoff,
                       uint16_t *shnum, uint16_t *shstrndx,
                       uint16_t *shentsize) {
    unsigned char id[EI_NIDENT];
    if (pread(fd, id, sizeof(id), 0) != (ssize_t)sizeof(id)) return -1;
    if (memcmp(id, ELFMAG, SELFMAG) != 0) return -1;
    /* EI_DATA=2 是大端，本设施只支持小端（Android 全 ABI 都是小端） */
    if (id[EI_DATA] != ELFDATA2LSB) return -1;

    if (id[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr eh;
        if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) return -1;
        *cls_out = 64;
        *shoff = eh.e_shoff;
        *shnum = eh.e_shnum;
        *shstrndx = eh.e_shstrndx;
        *shentsize = eh.e_shentsize;
        if (*shentsize != sizeof(Elf64_Shdr)) return -1;
    } else if (id[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr eh;
        if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) return -1;
        *cls_out = 32;
        *shoff = eh.e_shoff;
        *shnum = eh.e_shnum;
        *shstrndx = eh.e_shstrndx;
        *shentsize = eh.e_shentsize;
        if (*shentsize != sizeof(Elf32_Shdr)) return -1;
    } else {
        return -1;
    }
    if (*shoff == 0 || *shnum == 0 || *shstrndx >= *shnum) return -1;
    return 0;
}

/* 读第 i 个段头（统一成 ncg_shdr_t）。返回 0 成功。 */
static int ncg_elf_shdr(int fd, uint8_t cls, uint64_t shoff,
                        uint16_t shentsize, int i, ncg_shdr_t *out) {
    off_t at = (off_t)shoff + (off_t)i * (off_t)shentsize;
    if (cls == 64) {
        Elf64_Shdr sh;
        if (pread(fd, &sh, sizeof(sh), at) != (ssize_t)sizeof(sh)) return -1;
        out->addr = sh.sh_addr;
        out->offset = sh.sh_offset;
        out->size = sh.sh_size;
        out->name_off = sh.sh_name;
        out->flags = (uint32_t)sh.sh_flags;
    } else {
        Elf32_Shdr sh;
        if (pread(fd, &sh, sizeof(sh), at) != (ssize_t)sizeof(sh)) return -1;
        out->addr = sh.sh_addr;
        out->offset = sh.sh_offset;
        out->size = sh.sh_size;
        out->name_off = sh.sh_name;
        out->flags = sh.sh_flags;
    }
    return 0;
}

/* ── T4 专用：在 stub 阶段查 .text 段 ────────────────────────────────
 *
 * 为什么不复用 ncg_find_section：那函数编译进 .ncxh 段（密文），
 * 而 T4 的 boot_key 必须在【stub 阶段、.ncxh 尚未解开时】就能算出来。
 * 按本文件开头的调用纪律"stub 只能调 .text 里的函数"，这里另写一份
 * 最小实现，编进 .text。
 *
 * 只取 .text 一项，不做通用遍历（省体积，也减少 stub 的攻击面）。
 * ELF32/64 双支持见上方的 ncg_elf_hdr / ncg_elf_shdr。 */
__attribute__((noinline))
int ncg_stub_find_text(const char *so_path, ncg_shdr_t *out) {
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t cls;
    uint64_t shoff;
    uint16_t shnum, shstrndx, shentsize;
    if (ncg_elf_hdr(fd, &cls, &shoff, &shnum, &shstrndx, &shentsize) != 0) {
        close(fd); return -1;
    }
    ncg_shdr_t shstr;
    if (ncg_elf_shdr(fd, cls, shoff, shentsize, shstrndx, &shstr) != 0) {
        close(fd); return -1;
    }

    char name[16];
    /* 段名只可能是 ".text"，逐项比对前 16 字节即可 */
    for (int i = 0; i < shnum; i++) {
        ncg_shdr_t sh;
        if (ncg_elf_shdr(fd, cls, shoff, shentsize, i, &sh) != 0) break;
        if (sh.name_off >= shstr.size) continue;
        ssize_t n = pread(fd, name, sizeof(name) - 1,
                          (off_t)shstr.offset + sh.name_off);
        if (n <= 0) continue;
        name[n] = 0;
        if (strcmp(name, ".text") == 0) { *out = sh; close(fd); return 0; }
    }
    close(fd);
    return -1;
}

/* ── ncg_boot_key 已拆到 nc_guard_crypto.c（2026-11-06）────────────
 *
 * 为什么拆：要给本函数上【指令级 VMP】，而 VMP 与 annotate 互斥 ——
 * annotate 会把函数地址写进 @llvm.global.annotations，Amice 的
 * vm_virtualize 因此判定 "has non-call address uses" 并静默跳过。
 * Amice 只提供文件级开关 AMICE_VM_VIRTUALIZE，没有"按函数名指定"的途径，
 * 所以必须把目标函数单独放一个 .c（与 nc_guard_xor.c 同样的手法）。
 *
 * 为什么只搬这一个、不连带搬它的依赖：
 *   ncg_boot_crc32 / ncg_stub_find_text 若一起搬并开文件级 VMP，
 *   它们也会被虚拟化 —— 但它们是通用工具函数（内嵌 open/pread/close），
 *   VMP 之后体积暴涨且强度无收益。所以它们留在本文件，只去掉 static，
 *   由 nc_guard_internal.h 提供声明。
 *
 * 为什么搬走是安全的（实测，非推断）：ncg_boot_key 不碰 ncg_stub_slot，
 *   不依赖 PC 相对寻址反推基址。基址由调用方以 base 参数传入。
 *   （对照：ncg_slot_read 靠 &ncg_stub_slot 反推基址，改外部符号会让它
 *    从 PC 相对变成 GOT 间接寻址 —— 那条风险留给 P2，且已单独验证过
 *    反推结果仍正确，见 docs/混淆计划.md §3.2。）
 *
 * ⚠️ 拆走后本文件对 NC_OBF 的使用只剩 ncg_stub_recover（见下方）。
 *    混淆开关由 scripts/make-zip-lib.sh 按文件粒度控制。
 */

/* ═══════════════════════════════════════════════════════════════════
 * 第一部分：密文 unlock 本体（进 .ncxh，构建期被锁）
 * ═══════════════════════════════════════════════════════════════════ */

/* ── master：HKDF 的 ikm，构建期随机化后藏进 head 密文段 ──────────────
 *
 * 原为 `static const` 全 0x11 占位符躺在 .rodata —— `od` 一条命令读出，
 * 配合 APK 里的证书即可离线算出 k_so（8 分钟解开 .ncx）。这条链完全
 * 不需要运行、不需要真机、不需要证书私钥。
 *
 * ⚠️ 关键设计判断：只换成随机数【不够】。随机数若仍是 .rodata 裸常量，
 *   `od` 一样读出来，成本不变。必须同时做到"值随机"+"藏在读不到的地方"
 *   —— 所以放进 .ncxh 段，随整段锁成密文。
 *
 * 运行期链路（解 head 之前拿不到 master）：
 *   碎片 → XOR_KEY → wrapped_k_stub → k_stub → 解 head → master → k_so
 *
 * ⚠️ 为什么用 .ncxhr 而不是 .ncxh：后者是 AXR（可执行），clang 拒绝让
 *   数据进去（'ncg_rc4' causes a section type conflict with 'ncg_master'）。
 *   签名表用 .ncxr 也是同一原因。
 *
 * ⚠️ 为什么必须与 head 用同一把 k_stub、在同一次 lock_head 里锁：
 *   若改用 k_so 加密，就成"k_so 的派生需要先解开 k_so 加密的东西"——
 *   循环依赖。用 k_stub 则链路单向：
 *     碎片 → XOR_KEY → k_stub → {解 head, 解 head_ro → master} → k_so
 *   而 stub 只需碎片、零 I/O，能独立完成这一步。
 *
 * ⚠️ 未锁箱时（开发期）：master 保持全零，运行期检测到全零即视为未锁、
 *   不参与派生（与 magic 判"未锁"同语义）。锁箱器强制写入随机值并断言
 *   非全零，故全零不可能是合法 master。 */
__attribute__((section(NC_SEC_HEADRO), used, retain, aligned(16)))
static uint8_t ncg_master[32] = {0};

/* RC4 —— 与 so-section-lock.py 的 rc4() 逐字节同算法 */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static void ncg_rc4(const uint8_t *key, size_t keylen,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t S[256];
    int i, j;
    for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (i = 0, j = 0; len-- > 0; ) {
        uint8_t c;
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        c = S[(S[i] + S[j]) & 0xFF];
        *out++ = *in++ ^ c;
    }
}

/* 判断 [addr, addr+len) 覆盖的任何一个页范围内，是否存在
 * 原始权限为可写（SHF_WRITE）的其它段。
 *
 * 为什么需要它：mprotect 的粒度是【页】。给某个段设只读时，若该页上
 * 还住着 .data / .bss 这类本来可写的段，它们会一起变只读 →
 * 后续写入即 SIGSEGV。
 *
 * 实测踩过两次：
 *   ① .ncxhr（master，32B）与 .data/.bss 同页 —— 已在 ncg_stub_recover
 *      里用"恢复 RW"修掉
 *   ② .ncxr（常量表，17B）与 .bss 同页 —— 2026-10-30 实测 dlopen 即
 *      SIGSEGV。主项目没暴露是因为它的 .ncxr 有 96 字节、恰好与 .data
 *      同页而不是 .bss。
 *
 * 返回 1 = 有可写邻居（调用方应保持 RW），0 = 无（可安全设只读）。
 * 出错时返回 1（保守：宁可权限宽一点，也不要误伤正常段）。 */
/* ⚠️ 2026-11-12：参数宽度统一成 uint64_t。
 * 原因：Amice 把它算成 [64, 32, 32, 32]，而调用点传的是 [64, 64, 64, 64]
 * → "argument 1 width mismatch"。uintptr_t/size_t 在 LLVM IR 里虽然是 i64，
 * 但 Amice 的 native call 参数宽度推断在某些路径上按 32 处理——
 * 显式用 uint64_t 让两侧都无歧义。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_page_has_writable_neighbor(const char *so_path, uint64_t addr,
                                          uint64_t len, uint64_t page) {
    /* 思路：镜像基址必定页对齐，所以「运行期地址所在页」减去基址后，
     * 与「链接期地址所在页」是同一页。因此只要把所有段的 sh_addr 按页
     * 分组，找出 addr 落在哪一组，再看该组里有没有 SHF_WRITE 的段即可。
     *
     * 但 addr 是运行期地址、sh_addr 是链接期地址，两者的页号可能差一个
     * 常数（基址页号）。为回避这个未知量，改用【相对位置】判断：
     *   对每个候选段 X（非当前段），若 X 与本段的链接期距离
     *   |X.sh_addr - 本段.sh_addr| 使得两者覆盖的页区间相交，则同页。
     * 这只需要段表，不需要基址。 */
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return 1;                    /* 保守：放宽权限，不误伤 */
    uint8_t cls;
    uint64_t shoff;
    uint16_t shnum, shstrndx, shentsize;
    if (ncg_elf_hdr(fd, &cls, &shoff, &shnum, &shstrndx, &shentsize) != 0
        || shnum > 4096) {
        close(fd); return 1;
    }
    ncg_shdr_t *shs = (ncg_shdr_t *)calloc(shnum, sizeof(ncg_shdr_t));
    if (!shs) { close(fd); return 1; }
    for (int i = 0; i < shnum; i++) {
        if (ncg_elf_shdr(fd, cls, shoff, shentsize, i, &shs[i]) != 0) {
            free(shs); close(fd); return 1;
        }
    }
    close(fd);

    /* 找出当前段：运行期地址与 sh_addr 的差就是基址，同一镜像里所有段
     * 共用同一个基址。故 base = addr - 当前段.sh_addr，但我们不知道
     * 当前段是哪个。改为：对每个段假设它是当前段，算出 base，再验证
     * 该 base 是否让 addr 落在它的范围内。只有一个段会验证通过。 */
    const ncg_shdr_t *cur = NULL;
    for (int i = 0; i < shnum; i++) {
        if ((shs[i].flags & SHF_ALLOC) == 0) continue;
        if ((shs[i].flags & SHF_WRITE) != 0) continue;   /* 当前段是只读的 */
        if (shs[i].addr == 0 || shs[i].size == 0) continue;
        uintptr_t base = addr - (uintptr_t)shs[i].addr;
        if (addr >= base + shs[i].addr
            && addr + len <= base + shs[i].addr + shs[i].size
            && base % page == 0) {
            cur = &shs[i];
            break;
        }
    }
    if (!cur) { free(shs); return 1; }

    /* 与当前段页区间相交的其它段里，有可写的吗 */
    uintptr_t clo = (uintptr_t)cur->addr & ~(page - 1);
    uintptr_t chi = (((uintptr_t)cur->addr + cur->size - 1) & ~(page - 1)) + page;
    int found = 0;
    for (int i = 0; i < shnum; i++) {
        if (&shs[i] == cur) continue;
        if ((shs[i].flags & SHF_ALLOC) == 0) continue;
        if ((shs[i].flags & SHF_WRITE) == 0) continue;
        if (shs[i].size == 0) continue;
        uintptr_t wlo = (uintptr_t)shs[i].addr & ~(page - 1);
        uintptr_t whi = (((uintptr_t)shs[i].addr + shs[i].size - 1) & ~(page - 1)) + page;
        if (wlo < chi && clo < whi) { found = 1; break; }
    }
    free(shs);
    return found;
}

/* 在 ELF 文件里按名字找段（ELF32 + ELF64 双支持，2026-11-02）。
 *
 * 原先只支持 ELF64 且注释写"ELF32 是既有缺口，本轮不扩范围"——但
 * `APP_ABI := armeabi-v7a arm64-v8a`，v7a 产物就是 ELF32，缺口等于
 * 32 位设备上加固包必然 SIGILL。复用 ncg_elf_hdr / ncg_elf_shdr。 */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_find_section(const char *so_path, const char *name,
                            ncg_shdr_t *out) {
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t cls;
    uint64_t shoff;
    uint16_t shnum, shstrndx, shentsize;
    if (ncg_elf_hdr(fd, &cls, &shoff, &shnum, &shstrndx, &shentsize) != 0) {
        close(fd); return -1;
    }

    ncg_shdr_t *shs = (ncg_shdr_t *)calloc(shnum, sizeof(ncg_shdr_t));
    if (!shs) { close(fd); return -1; }
    for (int i = 0; i < shnum; i++) {
        if (ncg_elf_shdr(fd, cls, shoff, shentsize, i, &shs[i]) != 0) {
            free(shs); close(fd); return -1;
        }
    }

    const ncg_shdr_t *strh = &shs[shstrndx];
    char *strtab = (char *)calloc(strh->size + 1, 1);
    if (!strtab) { free(shs); close(fd); return -1; }
    if (pread(fd, strtab, strh->size, (off_t)strh->offset)
        != (ssize_t)strh->size) {
        free(strtab); free(shs); close(fd); return -1;
    }

    int found = -1;
    for (int i = 0; i < shnum; i++) {
        if (shs[i].name_off >= strh->size) continue;
        const char *n = strtab + shs[i].name_off;
        if (strcmp(n, name) == 0) { *out = shs[i]; found = 0; break; }
    }
    free(strtab);
    free(shs);
    close(fd);
    return found;
}

/* so 路径解析：用 head 本体的地址 dladdr（dladdr 是 libc 的，但本体已在
 * 明文状态才被调用，所以这里用 libc 无妨——约束只针对明文 stub） */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_resolve_self(const void *self_addr, void **base, char *path,
                            size_t pathcap) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!self_addr) return -1;
    if (dladdr(self_addr, &info) == 0
        || info.dli_fbase == NULL) return -1;
    *base = info.dli_fbase;
    if (info.dli_fname) {
        strncpy(path, info.dli_fname, pathcap - 1);
        path[pathcap - 1] = 0;
        return 0;
    }
    return -1;
}

/* ── P1-a 辅助（2026-10-19）：运行期定位自身 APK / 自身包名 ───────────
 *
 * 为什么不解析 AndroidManifest.xml 拿包名：
 *   那要在运行期跑一个 AXML 二进制解析器（字符串池 + 资源映射），
 *   任何边界 bug 都是新的崩溃源（参见报错四十九：为自检新增的类没生成
 *   → ULE 被 catch 吞掉 → 连带跳过心跳 → watchdog 误杀）。
 *   本机制只做"校验"不做"发现"：包名从 /proc 拿，指纹在构建期写进 slot，
 *   两者对不上就 fail-closed。零新增解析器、零新崩溃面。
 */

/* 从 /proc/self/cmdline 取包名（第一个 NUL 分隔字段）。
 *
 * ⚠️ 2026-10-19：Android 的 cmdline 是【进程名】，不一定是包名——
 * 子进程会带 ":remote" / ":push" / ":service" 之类后缀。若不截断，
 * 主进程能通过指纹校验、子进程全部 fail-closed(-12) → 正常功能挂掉。
 * 这里统一截到第一个 ':' 之前，与 AndroidManifest 的 package 对齐。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
/* ncg_self_pkg 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/


/* 包名指纹：把构建期写入 slot[NC_OFF_PKG_SHA] 的 8 字节与运行期算出的
 * SHA256(包名)[:8] 做【异或，并返回该偏差】——不是返回 bool。
 *
 * ⚠️ 2026-10-22 改造（消除可 patch 的判定点）：原实现返回 int（0/1），
 *    调用方写 `if (!ncg_pkg_matches(...)) return -12;`。攻击者只要把本函数
 *    改成 `return 1;`（4 字节）就绕过了整个包名绑定。
 *
 * 现在返回【偏差字节数】的逐字节异或值：
 *   匹配   → 返回全 0  → 调用方把它异或进密钥，密钥不变（正常工作）
 *   不匹配 → 返回非 0  → 密钥被污染 → 解出乱码 → 后续全崩
 *
 * 关键：调用方【不再有 if】，改返回值也没用——改成本 0 反而让攻击者
 * 自己解不出东西（因为他不知道正确密钥）。这是"数据依赖"对"分支判断"
 * 的本质差别：攻击者要绕过，必须知道正确包名并伪造，而不是改一行代码。
 *
 * 为什么不返回 bool：bool 只有两种语义落点，patch 成本极低；
 * 返回实际偏差值则让"校验"和"密钥派生"共用同一次运算，不可分离。
 *
 * 指纹长度 8 字节 = 64 bit，碰撞概率对本用途可忽略。存指纹而非明文包名
 * 的理由：明文会暴露"密钥与包名有关"这条线索，而 slot 是明文段。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
/* ncg_pkg_fault 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/


/* ── 反多开：APK 路径白名单（2026-11-02，对齐 Epic report §2.4）────────
 *
 * 威胁模型：攻击者把 App 装进「应用双开 / 虚拟空间」里跑。
 *   - 双开（MIUI/EMUI/ColorOS 的「应用分身」）路径：/data/user/<uid>/pkg/
 *   - 虚拟空间（VirtualXposed / 太极 / 平行空间）：/data/data/<宿主>/virtual/
 *   这些环境里：
 *     · 包名与主环境【完全相同】→ ncg_pkg_fault 的包名指纹校验照样通过
 *     · 调试器/hook 框架可以随意 attach 而不污染主环境
 *     · 攻击者可以「改一处 → 跑一次」反复试错，主环境零痕迹
 *   即：包名绑定挡不住「同一个包名的另一个实例」。
 *
 * 与 Epic 的差异（刻意，不是遗漏）：
 *   Epic 的做法是【硬拒】——路径不合规就 pause() 永久挂起。
 *   实测风险：中国 ROM 的「应用双开」会走 /data/user/<uid>/，
 *   硬拒会让所有双开用户直接闪退。这是产品事故，不是安全收益。
 *
 * 本实现的取法：**不做判定点，只污染密钥**（与 ncg_pkg_fault 同一思路）。
 *   合法路径 → *fault 全 0 → 密钥不变 → 正常工作
 *   异常路径 → *fault 非 0 → k_so 被污染 → 解出乱码 → MAC 失败 → fail-closed
 *
 * 关键：调用方没有 if，攻击者无法通过「把某个判断改成 return 1」绕过。
 * 要绕过必须【同时】伪造路径与包名，且伪造结果要能算出正确的 k_so——
 * 而 k_so 的输入含证书 DER，攻击者不知道。
 *
 * 白名单（合法安装路径，实测覆盖 Google Play / 国内商店 / ADB 安装）：
 *   /data/app/            — 正常安装（含 /data/app/~~<hash>==/pkg-<hash>==/）
 *   /mnt/expand/          — 可 adoption 存储（SD 卡安装）
 *   /data/user_de/        — 部分设备 DE 存储
 * 黑名单（异常环境）：
 *   /data/user/           — 双开
 *   /data/data/           — 虚拟空间（App 私有目录里塞一份 APK）
 *   /data/local/tmp/      — 手动 push（调试/攻击测试）
 *
 * ⚠️ 路径字面量不落明文：走 ncg_path_s 那套密文表会牵动 gen-paths.py 与
 *    布局契约（新增 ID 要同步 Python 侧），收益不抵风险。这里改用
 *    「首字节 + 长度」的轻量比对，字符串在 .rodata 里是分段常量，
 *    `strings` 扫不到完整路径（实测见 commit message）。
 *    这是【混淆】不是【加密】——如实标注，别高估。 */

/* 判「异常安装路径」，结果写到 fault 的 8 字节里（不做 if 判定）。
 *
 * 调用方把它和 ncg_pkg_fault 的偏差【一起】异或进 k_so，两者不可分离：
 * 攻击者想只绕过路径，就得让本函数返回全 0——但那要求他知道正确算法与
 * 常量，而常量在 .ncxh 密文段里。
 *
 * ⚠️ 规则表用 XOR 0x5A 加密存储：直接写 "/data/user/" 会让 strings
 *    `strings -n 6 | grep /data/user` 一行扫出来，等于把「我们在查双开」
 *    告诉攻击者。加密后文件里只有 0x75 0x3E 0x3B ... 这样的字节序列。
 *    生成方式见 commit message。
 *    这是【混淆】不是【加密】——如实标注，别高估。 */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static void ncg_apk_path_fault(const char *apk_path, uint8_t fault[8]) {
    /* 扁平存储：所有规则拼在一个数组里，用 (off,len,bad) 索引。
     * 不能用「复合字面量数组」做静态初始化（C 不允许非常量初始化器）。 */
    static const uint8_t kEnc[] = {
        /* 黑名单 */
        0x75,0x3E,0x3B,0x2E,0x3B,0x75,0x2F,0x29,0x3F,0x28,0x75,                     /* /data/user/ */
        0x75,0x3E,0x3B,0x2E,0x3B,0x75,0x3E,0x3B,0x2E,0x3B,0x75,                     /* /data/data/ */
        0x75,0x3E,0x3B,0x2E,0x3B,0x75,0x36,0x35,0x39,0x3B,0x36,0x75,0x2E,0x37,0x2A,0x75, /* /data/local/tmp/ */
        /* 白名单 */
        0x75,0x3E,0x3B,0x2E,0x3B,0x75,0x3B,0x2A,0x2A,0x75,                         /* /data/app/ */
        0x75,0x37,0x34,0x2E,0x75,0x3F,0x22,0x2A,0x3B,0x34,0x3E,0x75,               /* /mnt/expand/ */
        0x75,0x3E,0x3B,0x2E,0x3B,0x75,0x2F,0x29,0x3F,0x28,0x05,0x3E,0x3F,0x75,     /* /data/user_de/ */
    };
    static const struct { int off; int len; int bad; } kRules[] = {
        {  0, 11, 1 },   /* 黑名单：双开 */
        { 11, 11, 1 },   /* 黑名单：虚拟空间 */
        { 22, 16, 1 },   /* 黑名单：手动 push */
        { 38, 10, 0 },   /* 白名单：正常安装 */
        { 48, 12, 0 },   /* 白名单：SD 卡 */
        { 60, 14, 0 },   /* 白名单：DE 存储 */
    };
    const int n = (int)(sizeof(kRules) / sizeof(kRules[0]));

    /* ⚠️ 宿主测试豁免（2026-11-02）：
     * Termux 的整个家目录就在 /data/data/com.termux/ 下，与真机
     * 「虚拟空间」的特征路径（/data/data/<宿主>/virtual/...）前缀相同，
     * 光看前缀无法区分。而 test.sh 的 V5/V6/V7 用
     *   cd fake/<pkg> && exec ... ./lib/<abi>/libtest.so
     * 加载产物，maps 里反推出的 apk_path 必然是
     *   /data/data/com.termux/files/usr/tmp/.../fake/<pkg>/base.apk
     * → 会被黑名单误判 → 宿主测试全红（实测 V6/V7 挂）。
     *
     * 用宏区分而不是放宽生产逻辑：生产构建（lib-ndk.sh）定义
     * NCG_PATH_STRICT，宿主测试不定义 → 测试放行、真机收紧。
     * 这与本仓库既有惯例一致（NC_GUARD_SECTIONED / NCLINK_HOST_TEST）。
     *
     * 安全边界（如实）：若有人用「不加该宏」的方式自建生产产物，
     * 本项防护失效。但生产链路由 lib-ndk.sh 统一控制，不存在这条路径。 */
#if !defined(NCG_PATH_STRICT)
    for (int i = 0; i < 8; i++) fault[i] = 0;
    (void)apk_path; (void)kEnc; (void)kRules;
    return;
#endif

    /* 基线：只对【绝对路径】施加白名单。
     *
     * 为什么放行相对路径：宿主测试（nox/test.sh 的 V5/V6/V7）用
     * `cd fake/<pkg> && exec ... ./lib/arm64-v8a/libtest.so` 加载，
     * ncg_find_apk_path 据此反推出相对路径 `./fake/<pkg>/base.apk`。
     * 若把「非 / 开头」判为异常，宿主测试全部失败，而 Android 上
     * apk_path 永远来自 /proc/self/maps，必然是绝对路径。
     *
     * 安全边界（如实）：攻击者若能让 maps 里出现相对路径就绕过本项——
     * 但 /proc/self/maps 的路径列由内核填，用户在 Android 上无法伪造
     * 成相对路径。所以这条放行不构成实际绕过面。 */
    uint32_t bad = 0u;

    /* 逐条比对，命中即把正负标志累加。
     * ⚠️ 不早退：早退会让攻击者按耗时推断命中了哪条，
     * 且 -Oz 可能把「首个不等就跳走」优化掉，留下可 patch 的跳转。 */
    for (int i = 0; i < n; i++) {
        /* 逐字节比较，累积「不相等的字节数」。
         * ⚠️ 必须用计数而不是布尔：布尔会被编译器折成早退分支，
         *    留下一条可 patch 的条件跳转（本轮首版就是这么错的）。 */
        uint32_t diff = 0;
        for (int k = 0; k < kRules[i].len; k++) {
            uint8_t c = (uint8_t)apk_path[k];
            uint8_t e = (uint8_t)(kEnc[kRules[i].off + k] ^ 0x5A);
            diff |= (uint32_t)(c ^ e);
        }
        /* diff == 0 → 全等 → 该规则生效 */
        bad += (uint32_t)(((diff - 1u) >> 31) & (uint32_t)kRules[i].bad);
    }

    /* 摊到 8 字节：全 0 = 通过、非 0 = 污染密钥。
     * 不用 memset（-Oz 会把死存储删掉，见 ncg_wipe 的教训）。 */
    for (int i = 0; i < 8; i++)
        fault[i] = (uint8_t)((bad >> ((i & 3) * 8)) & 0xFF);
}


/* 定位自身 APK 路径。两条来源：
 *   ① /proc/self/maps 中含 "base.apk" 的行（extractNativeLibs=false 时
 *      so 直接映射自 APK；true 时也能命中，因为 ART 会映射 APK）
 *   ② 由 so 自身路径反推：.../lib/<abi>/libnc.so → .../base.apk
 * 与 sig_check.c:find_apk_path() 同思路，但不复用它——那是冻结模块，
 * 且这里在密文段里，必须自包含。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
/* ncg_find_apk_path 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/



/* 用后即毁交接区 —— 定义已移到 nc_guard_crypto.c（2026-11-06）。
 * ⚠️ 为什么不能定义在本文件：本文件混有 .ncxh（AXR 可执行）段的函数，
 * 无段属性的全局变量会被 clang 归到「当前段」，与 ncg_rc4 冲突并报
 *     'ncg_head_live' causes a section type conflict with 'ncg_rc4'
 * 这是 AGENTS.md §2.2 记的老坑（数据不能进 AXR 段）。
 * 挪到 crypto.c（该文件无 AXR 段，两个变量会进通常的 .bss/.data）。
 * 声明见 nc_guard_internal.h。 */

/* ── unlock 本体主流程：解出 .ncx 业务段 ──────────────────────
 * 由明文 stub 解密后才可调用（此前它是密文）。
 * 返回 0 成功；负值含义与 nc_guard_unlock.c 的码表一致。 */
/* ── 证书/包名派生 k_so（2026-11-12 从 ncg_head_unlock 拆出）──────────
 *
 * 为什么拆：主函数 428 行 / 34 个局部变量，Amice 报 values=25（预算 32）。
 * 这一段自带 apk_path[512] 与三个派生/污染步骤，是峰值的主要来源之一。
 *
 * ⚠️ 语义完全不变，特别是那两条【污染】纪律：
 *   ① 包名不符 → pkg_fault 非 0 → 摊进 k_so → 解出乱码（不是 if 分支）
 *   ② APK 路径异常 → path_fault 非 0 → 同样摊进 k_so
 *   刻意不做 `if (!path_ok) return -12` —— 那会变成可一条指令 patch
 *   掉的判定点（2026-10-22 的教训）。改这段时不要"优化"成 if。
 *
 * 返回 0 成功并把派生结果写进 k_out；-12 = 证书/包名任一不可得（fail-closed）。 */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_derive_kso_bound(const char *so_path,
                                const uint8_t master[32],
                                uint8_t *der, size_t *der_len,
                                char *pkg, size_t pkgcap,
                                const uint8_t *slotdata,
                                uint8_t k_out[16]) {
    char apk_path[512];

    apk_path[0] = '\0';
    if (ncg_find_apk_path(so_path, apk_path, sizeof(apk_path)) != 0) return -12;
    if (ncg_apk_first_cert_der(apk_path, der, 1536, der_len) != 0) return -12;
    if (ncg_self_pkg(pkg, pkgcap) != 0) return -12;
    if (ncg_derive_k_so_from_der(master, der, *der_len, pkg, k_out) != 0)
        return -12;

    /* 污染一：包名（详见 ncg_pkg_fault 的注释） */
    {
        uint8_t fault[8];
        ncg_pkg_fault(slotdata, pkg, fault);
        for (int i = 0; i < 16; i++) k_out[i] ^= fault[i & 7];
        ncg_wipe(fault, sizeof(fault));
    }
    /* 污染二：APK 路径（反多开）。与包名同款数据依赖，不做分支。 */
    {
        uint8_t pf[8];
        ncg_apk_path_fault(apk_path, pf);
        for (int i = 0; i < 16; i++) k_out[i] ^= pf[i & 7];
        ncg_wipe(pf, sizeof(pf));
    }
    return 0;
}

/* ── 密文完整性校验（2026-11-12 从 ncg_head_unlock 拆出）──────────────
 *
 * 为什么拆：Amice 的 values 按 alloca 计，主函数超预算（VM 只有 32 个
 * x 寄存器，实测 values=25）。这一段自带 k_mac[16]+got_mac[32]+hcbuf[256]
 * 三个栈槽，抽出去能降峰值。
 *
 * ⚠️ 语义与时序完全不变：仍是「先验后解」，且在 mprotect/解密【之前】。
 *    MAC 不符 → 一个字节都不解 → 段保持密文 → 调用即 SIGILL（fail-closed）。
 *    不擦调用方的 key —— 由调用方统一处理（行为等价）。
 *
 * 返回 0 通过；-11 不通过；-12 密钥派生失败。 */
NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_verify_seg_mac(const uint8_t master[32],
                              const uint8_t *der, size_t der_len,
                              const char *pkg,
                              const ncg_shdr_t *segs, int nseg,
                              const void *base,
                              const uint8_t *slotdata) {
    uint8_t k_mac[16], got_mac[32];
    const uint8_t *want = slotdata + NC_OFF_EXPMAC;
    uint8_t diff = 0;
    int i;

    if (ncg_derive_k_mac_from_der(master, der, der_len, pkg, k_mac) != 0)
        return -12;

    {
        _Alignas(KHMAC_CTX_ALIGN) unsigned char hcbuf[KHMAC_CTX_SIZE];
        khmac_ctx *hc = (khmac_ctx *)hcbuf;
        khmac_init(hc, k_mac, 16);
        for (i = 0; i < nseg; i++) {
            const uint8_t *p = (const uint8_t *)base + segs[i].addr;
            khmac_update(hc, p, segs[i].size);
        }
        khmac_final(hc, got_mac);
        memset(hcbuf, 0, sizeof(hcbuf));
    }
    for (i = 0; i < 32; i++) diff |= (uint8_t)(got_mac[i] ^ want[i]);
    ncg_wipe(k_mac, sizeof(k_mac));
    ncg_wipe(got_mac, sizeof(got_mac));
    return (diff != 0) ? -11 : 0;
}

/* ── 分段解密 + 段权限 + 完整性基线（2026-11-12 从 ncg_head_unlock 拆出）
 *
 * 为什么拆：Amice 的 values 按 alloca 计，主函数超预算。
 * 这一段自带循环变量、segkey[16]、buf 等栈槽，抽出去降峰值。
 *
 * 语义与拆分前完全一致：逐段 mprotect(RW[+X]) → 派生段密钥 → RC4 解
 * → 恢复最小权限 → 采集完整性基线（ncg_baseline_init）。
 *
 * ⚠️ 段序必须与 so-section-lock.py 的 _SEG_KEYS 一致（代码段在前）。
 * ⚠️ 失败路径擦 k_out；成功时 k_out 保留（后续要用）。
 * ⚠️ 返回码同原实现：-8/-9/-10/-12。
 */
/* ── 解一个段（2026-11-12 从 ncg_decrypt_segments 的循环体抽出）───────
 *
 * 为什么拆：ncg_decrypt_segments 报 values=28/29（预算 32）。
 * 循环体自带 tgt/len/is_code/s/e/segkey/buf/prot 等 8 个局部量，
 * 每次迭代都在峰值上。抽成独立函数后主函数只剩循环变量。
 *
 * ⚠️ 语义逐字保留，特别是「数据段若与可写段同页则保持 RW」那段
 *    （2026-10-30 修 SIGSEGV 的实证结论，不要简化）。
 * ⚠️ 返回码同原实现：-8 (mprotect RW) / -9 (malloc) / -10 (mprotect 恢复) / -12 (派生)。
 */
/* ── ncg_decrypt_one_seg 的上下文（2026-11-12）────────────────────────
 *
 * 为什么打包：Amice 报 "only up to 8 flattened scalar ... arguments"。
 * 原参数表 9 个（so_path/base/master/der/der_len/pkg/sg/i/ps/k_out），
 * 其中 master[32] / k_out[16] 是数组，扁平化后占位更多。
 * 把「派生密钥需要的四个值」打包成一个指针，参数降到 6 个。
 */
struct ncg_seg_ctx {
    const uint8_t *master;   /* 32 字节 */
    const uint8_t *der;
    size_t der_len;
    const char *pkg;
    size_t seg_ord;          /* 段号：决定用哪把钥匙，见 ncg_decrypt_one_seg */
    const char *so_path;     /* ncg_page_has_writable_neighbor 要用 */
    /* 2026-11-13：本产物是否有 .nct（第二套 VMP 数据段）。
     * .nct 是【可选段】—— 没开第二套 VMP 的构建没有它。
     * 段序必须动态决定，写死索引会让钥匙错配：
     *   有 .nct： 0=.nct(k_nct)  1=.ncx(k_so)  2=.ncxr(k_so_r)
     *   无 .nct： 0=.ncx(k_so)   1=.ncxr(k_so_r)
     * 曾写死成 "0→k_nct / 1→k_so / 2→k_so_r"，无 .nct 时把 k_nct 用在
     * .ncx 上 → 解出乱码 → test.sh 的 V6 报"正常包也会挂"。 */
    int has_nct;
};

NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_decrypt_one_seg(const void *base,
                               const struct ncg_seg_ctx *cx,
                               uint64_t seg_ord,
                               const ncg_shdr_t *sg_in,
                               uint8_t k_out[16]) {
    /* 2026-11-12：入参用非 const 局部别名接一下 ——
     * const 指针参数在 -Oz 下会被 LLVM 标 captures(none)，
     * 而 Amice 的 native call 宽度推断对该属性处理有误
     * （报 "argument 1 width mismatch: value is 64, callee expects 32"）。 */
    const char *so_path = cx->so_path;
    const ncg_shdr_t *sg = sg_in;
    /* ⚠️ 2026-11-12：ps（页大小）在循环外已算好，这里重取一次——
     * 少传一个参数（Amice 只支持 8 个扁平参数）。
     * getpagesize() 是常量，重取代价可忽略。 */
    const uintptr_t ps = (uintptr_t)getpagesize();
    /* sg 已指向 &segs[原 i]，所以循环体里一律用 segs[0]；
     * 而「哪一段」这个信息用 seg_ord 单独带（决定用 k_so 还是 k_so_r）。 */
    const ncg_shdr_t *segs = sg;
    {
        uint8_t *tgt = (uint8_t *)base + segs[0].addr;
        size_t len = (size_t)segs[0].size;
        /* 数据段不需要 EXEC；代码段需要 */
        int is_code = (segs[0].flags & SHF_EXECINSTR) != 0;
        uintptr_t s = (uintptr_t) tgt & ~(ps - 1);
        uintptr_t e = ((uintptr_t) tgt + len - 1 & ~(ps - 1)) + ps;
        if (mprotect((void *) s, e - s,
                     PROT_READ | PROT_WRITE | (is_code ? PROT_EXEC : 0)) != 0) {
            ncg_wipe(k_out, 16);
            return -8;
        }
        /* ── 段密钥（2026-10-28，逆向报告 §6.2）───────────────────────
         * 第 0 段（.ncx 代码）用 k_so；第 1 段（.ncxr 常量表）用 k_so_r。
         * 与锁箱侧 so-section-lock.py 的 _SEG_KEYS 顺序必须逐字节一致。
         *
         * 为什么必须分钥匙：RC4 是流密码，两段共用 k_so 且都从 keystream
         * 偏移 0 起 = two-time-pad 误用。实测已知 .ncxr 明文
         * （96 字节签名表，结构高度可猜）即可反推 .ncx 前 96 字节明文。
         *
         * 向后兼容：老产物（只有 .ncx、nseg==1）仍走 k_so，行为与历史一致。
         * 老产物若有两段（升级前的锁箱产物），.ncxr 会被 k_so_r 解出乱码 →
         * MAC 覆盖两段密文，验签在解密【之前】已经比对过密文，不受影响；
         * 但解出的表是乱码 → 判定必然失败（fail-closed，不会静默放行）。
         * 这不是兼容性 bug，是刻意的格式版本边界：老包必须用老 so。 */
        uint8_t segkey[16];
        /* 2026-11-13：段序【动态】决定，与 so-section-lock.py 的
         * _KEY_BY_NAME 按段名映射保持一致。
         *
         *   有 .nct： 0=.nct→k_nct   1=.ncx→k_so   2=.ncxr→k_so_r
         *   无 .nct： 0=.ncx→k_so    1=.ncxr→k_so_r
         *
         * ⚠️ 为什么 .nct 必须排在 .ncx 之前解密：
         *   .ncx 里的函数带 VMP wrapper，wrapper 第一条就 bl 到解释器、
         *   读 .nct 里的字节码。若 .nct 还是密文 → 解释器把密文当 opcode
         *   → 跳到无效地址 → 真机 SIGILL（2026-11-12 实测，崩溃点
         *   constant at libnc.so+0x82598，.ncx 段内）。
         *   而 k_nct 只需 master（来自 .ncxhr，二级锁箱已解），与 .ncx
         *   无依赖，所以"先解 .nct"不构成循环依赖。 */
        {
            const size_t kso_idx  = cx->has_nct ? (size_t)1 : (size_t)0;
            const size_t ksor_idx = cx->has_nct ? (size_t)2 : (size_t)1;
            if (cx->has_nct && seg_ord == 0) {
                if (ncg_derive_k_nct_from_der(cx->master, cx->der, cx->der_len,
                                              cx->pkg, segkey) != 0) {
                    ncg_wipe(k_out, 16);
                    return -12;
                }
            } else if (seg_ord == kso_idx) {
                memcpy(segkey, k_out, 16);
            } else if (seg_ord == ksor_idx) {
                if (ncg_derive_k_so_r_from_der(cx->master, cx->der, cx->der_len,
                                               cx->pkg, segkey) != 0) {
                    ncg_wipe(k_out, 16);
                    return -12;
                }
            } else {
                /* 段数超过契约（_KEY_BY_NAME 只有 3 项）—— 说明锁箱侧
                 * 与运行期的段序契约漂移，fail-closed 而不是猜。 */
                ncg_wipe(k_out, 16);
                return -12;
            }
        }
        uint8_t *buf = (uint8_t *)malloc(len);
        if (!buf) { ncg_wipe(k_out, 16); return -9; }
        ncg_rc4(segkey, 16, tgt, buf, len);
        ncg_wipe(segkey, sizeof(segkey));
        memcpy(tgt, buf, len);
        free(buf);
        if (is_code) __builtin___clear_cache((char *)tgt, (char *)(tgt + len));
        /* ⚠️⚠️ 2026-10-30 修 SIGSEGV（实测复现）：
         *   原实现对数据段设 PROT_READ（只读）——前提是"该页只属于它"。
         *   但实测布局里 .ncxr 与 .bss 同页：
         *       .ncxr  addr=0xc54e size=17   ┐ 同属页 0xc000
         *       .bss   addr=0xc560 size=9968 ┘
         *   mprotect 粒度是页 → 把整页设成只读 → .bss 也变只读 →
         *   之后任何 .bss 写入即 SIGSEGV（dlopen 阶段直接崩）。
         *
         *   这与 .ncxhr/master 段踩的是同一个坑（见 ncg_stub_recover 里
         *   "恢复成 RW 而不是 R" 的注释）。当时的修法只覆盖了 master，
         *   没覆盖这里 —— 因为主项目的 .ncxr（96 字节签名表）恰好与
         *   .data 同页而非 .bss，没暴露出来。
         *
         *   修法：数据段若与"本来可写"的段同页，保持 RW。
         *   密文段的安全性从来靠"内容是密文"，不靠页权限 ——
         *   所以放宽成 RW 不降低防护（攻击者能读，本来就该能读；
         *   能写也没用，MAC 会拒）。 */
        {
            int prot = PROT_READ;
            if (is_code) {
                prot |= PROT_EXEC;
                /* ⚠️ 2026-11-11 实验开关：NC_CODE_SEG_RWX
                 *
                 * 背景：VMP（Amice）改写过的函数需要运行期写入自己的
                 * dispatch/token 区域，而这里原本只给 RX。实测开 --vmp 后
                 * 必现 SIGSEGV / SEGV_ACCERR，崩溃地址低 12 位恒在页尾
                 * （0xff0/0xff8），是典型的"写只读页"特征。
                 * 同一份代码不开 --vmp 则完全正常（进程存活、签名校验通过）。
                 *
                 * 代价（如实，别低估）：RWX 段是 Frida 脚本的第一眼目标，
                 * 也更容易被内存 dump —— 这是用「防动态分析」换「VMP 可用」。
                 *
                 * 默认不开。要验证推断时加 -DNC_CODE_SEG_RWX 重编 nox；
                 * 长期方案应该是让 VMP 的数据落在独立可写段（amice 侧改），
                 * 而不是把整个代码段放宽。 */
#if defined(NC_CODE_SEG_RWX)
                prot |= PROT_WRITE;
#endif
            } else {
                /* 数据段：同页若含 .data/.bss（原始权限可写），保持 RW，
                 * 否则会误伤。判据：检查覆盖该段的整页范围内，
                 * 是否有其它段要求 SHF_WRITE。 */
                if (ncg_page_has_writable_neighbor(so_path, (uintptr_t)tgt,
                                                   len, ps)) {
                    prot |= PROT_WRITE;
                }
            }
            if (mprotect((void *) s, e - s, prot) != 0) {
                ncg_wipe(k_out, 16);
                return -10;
            }
        }
    }
    return 0;
}

NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_decrypt_segments(const char *so_path, const void *base,
                                const uint8_t master[32],
                                const uint8_t *der, size_t der_len,
                                const char *pkg,
                                const ncg_shdr_t *segs, int nseg,
                                int has_nct,
                                uint8_t k_out[16]) {
    /* ── 解密：逐段处理，权限各自最小 ──────────────────────────────
     * 代码段解完是 RX（可执行不可写），常量表段解完是 R（只读不可执行）。
     * 给数据段加 X 是没有必要的权限扩大——它从来不需要执行。
     * 页对齐：目标段可能与相邻段同页（历史报错五十：.ncx 与 .text 尾部
     * 同页导致 pwrite 写坏代码）。这里是 mprotect 而非 pwrite，同页只会
     * 让权限短暂放宽，不会破坏内容；但 mprotect 粒度是页，所以范围必须
     * 按页对齐，否则会失败。 */
    uintptr_t ps = getpagesize();
    for (int i = 0; i < nseg; i++) {
        struct ncg_seg_ctx cx;
        cx.master = master; cx.der = der; cx.der_len = der_len;
        cx.pkg = pkg; cx.so_path = so_path;
        cx.has_nct = has_nct;   /* 2026-11-13：段序动态分派的关键 */
        cx.seg_ord = (size_t)i;
        int src = ncg_decrypt_one_seg(base, &cx, (uint64_t)i, &segs[i], k_out);
        if (src != 0) return src;
    }

    /* ── 提交二（2026-10-30）：记录解密后 .ncx 明文的完整性基线 ─────────
     * 动机：解锁成功后 .ncx 明文常驻文件映射页，此后【再无任何自检】。
     *   Frida 的 Interceptor 默认走 inline hook —— 必然改写该页指令，
     *   而当前实现对"代码被改"完全无感知、不报错、不处置。
     * 这是整个方案目前最大的空白（环境探针只查外部环境，不查自身代码）。
     *
     * 为什么必须在【这里】采集基线（不能等到 watchdog 首轮）：
     *   攻击者可以在 unlock 返回后、watchdog 首次轮询前挂 hook。
     *   若基线在 hook 之后才采，就把"已被 hook 的版本"当成正确基线，
     *   检测永久失效。基线必须紧贴解密完成的时刻。
     *
     * 为什么能这样比（前提已实测）：.ncx 段【零重定位】——
     *   实测 365 个重定位全部落在 0x12310 之后，而 .ncx 结束于 0xded4。
     *   故文件字节 == 内存字节，运行期内存 CRC 与构建期一致，可直接
     *   以"解锁后内存快照"作基线自比（不依赖文件读取，零 I/O）。
     *
     * 只记基线不启动线程：本函数在 .ncxh（密文段）内，起线程会与
     *   env_check.c 的 watchdog 重复。轮询统一由 .text 侧的
     *   ncguard_code_check() 承担（见其定义）。
     *
     * ⚠️ 采集范围覆盖两段（.ncx 代码 + .ncxr 常量表）：签名表被改同样
     *   要检出，否则攻击者改常量表绕过判定而不触发任何检测。 */
    {
        uint8_t *addrs[NC_CODE_SEG_MAX];
        uint32_t sizes[NC_CODE_SEG_MAX];
        for (int i = 0; i < nseg && i < NC_CODE_SEG_MAX; i++) {
            addrs[i] = (uint8_t *)base + segs[i].addr;
            sizes[i] = (uint32_t)segs[i].size;
        }
        ncg_baseline_init(addrs, sizes, nseg);
    }
    return 0;
}

NC_VMP_FUNC
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
int ncg_head_unlock(const void *self_addr) {
    void *base;
    char so_path[512];
    if (ncg_resolve_self(self_addr, &base, so_path, sizeof(so_path)) != 0) return -1;

    ncg_shdr_t sec, slot;
    if (ncg_find_section(so_path, NC_SEC_CODE, &sec) != 0) return -2;
    if (ncg_find_section(so_path, NC_SEC_SLOT, &slot) != 0) return -3;
    if (sec.size == 0) return -4;
    if ((sec.flags & SHF_ALLOC) == 0) return -5;

    uint8_t slotdata[NC_SLOT_SIZE];
    /* scrbuf：probe（8B）与 dec（96B）共用的暂存区，两者作用域不重叠。
     * 合并后少一个 alloca（Amice 的 values 按 alloca 计）。 */
    uint8_t scrbuf[NC_SLOT_SIZE];
    memset(slotdata, 0, sizeof(slotdata));
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -6;
    ssize_t got = pread(fd, slotdata, sizeof(slotdata), slot.offset);
    close(fd);
    if (got < 32) return -7;

    /* ── T4（2026-10-28）：.nck 已加密，先解密 ──────────────────────
     * .nck 整段（96 字节）在锁箱时被 boot_key 加密（见 _encrypt_slots）。
     * 这里 pread 拿到的是密文，必须先用同一把 boot_key 解开才能读字段。
     *
     * ⚠️ 2026-10-29 修正：这里原来【无条件】解密，但未锁箱（开发期）
     *    .nck 本就是明文 —— 无条件解会解出乱码然后被误判成"未锁"。
     *    改为先看 .ncks 的 magic 判断是否已锁，只有已锁才解 .nck。
     * ⚠️ boot_key 不缓存（缓存＝又一处常驻明文）。这里重算一次，
     *    代价是再跑一次 CRC+HKDF（实测微秒级），只在 constructor 一次。 */
    int so_locked = 0;
    {
        /* 用 .ncks 的 magic 判"是否已锁"（.ncks[0:8) 永远明文） */
        ncg_shdr_t nks;
        if (ncg_find_section(so_path, NC_SEC_STUBSLOT, &nks) == 0
            && nks.size >= NC_OFF_FRAGS_ENC) {
            int pfd = open(so_path, O_RDONLY);
            if (pfd >= 0) {
                memset(scrbuf, 0, sizeof(scrbuf));
                if (pread(pfd, scrbuf, 8, nks.offset) == 8
                    && ncg_magic_ok(scrbuf, NCG_MAGIC_SEED_STUB))
                    so_locked = 1;
                close(pfd);
            }
        }
    }
    if (so_locked && slot.size >= NC_SLOT_SIZE) {
        /* 2026-11-12：原先这里再调一次 dladdr(&ncg_head_unlock) ——
         * 那是本函数内的第二次「取自身地址」，会让 Amice 判定
         * "non-call address uses" 并跳过 VMP。
         * 而 so_path / base 在本函数开头已由 ncg_resolve_self 得到，
         * 直接复用即可，语义完全相同（同一 so，同一基址）。 */
        uint8_t bk2[16];
        if (ncg_boot_key(so_path, (uintptr_t)base, bk2) != 0) {
            ncg_wipe(bk2, sizeof(bk2));
            return -12;   /* fail-closed */
        }
        {
            ncg_rc4(bk2, 16, slotdata, scrbuf, NC_SLOT_SIZE);
            memcpy(slotdata, scrbuf, NC_SLOT_SIZE);
            ncg_wipe(scrbuf, sizeof(scrbuf));
        }
        ncg_wipe(bk2, sizeof(bk2));
    }
    if (!ncg_magic_ok(slotdata, NCG_MAGIC_SEED_SLOT)) {
        return 0;   /* 未锁，无需解锁 */
    }

    /* ── 槽完整性（2026-10-28 修 fail-open，对应逆向报告 §6.1）───────────
     *
     * 原实现：`int have_mac = (got >= NC_SLOT_SIZE) && (slot.sh_size >=
     * NC_SLOT_SIZE);` 然后 `if (have_mac) { 验 MAC }`。
     * 后果：把 .nck 段表里的 sh_size 改小 → have_mac == 0 → 【整个完整性
     * 校验被静默跳过】→ 直接 mprotect + RC4 解密 + 执行被篡改的代码。
     *
     * 为什么这是个真漏洞而不是理论风险：
     *   ① sh_size 在 section header table 里，【不在】crc32(.text) 的覆盖
     *      范围，也不在任何 MAC 里 → 改它零成本、不触发任何自毁；
     *   ② 门槛比 patch 密文低得多：攻击者不用算 k_mac，改 4 字节即可；
     *   ③ RC4 是流密码，改密文 1 位恰好只翻明文 1 位 —— MAC 一旦被关掉，
     *      "改一位→跑→看行为"这个廉价 oracle 就重新打开了（本文件
     *      so-section-lock.py 的注释里已论证过这一点）。
     *
     * 实测四个变体（逆向报告 §6.1 表）：
     *   A 原样                     → selftest 59（明文）
     *   B 只改 sh_size→0           → selftest 59（明文）  ← 校验被跳过
     *   C 只篡改 .ncx 1 字节        → selftest -11（密文） ← 校验本来有效
     *   D 关 MAC + 篡改同一字节     → selftest 137（篡改生效）
     *
     * 修法（纪律）：magic 判"未锁"必须在前（开发期不锁箱要能跑）；
     *   magic 之后【不允许】再有"长度不够就放行"的分支。
     *   ——这与报错五十二（lock_head 段缺失 return 0）、报错五十四
     *   （env_mem_readable 取不到就当通过）是同一类病，本仓库第三次复发。 */
    if (got < NC_SLOT_SIZE || slot.size < NC_SLOT_SIZE) {
        /* 此刻尚未派生任何密钥（key[] 在下方才声明），故只需清槽缓冲。
         * 清 slotdata 是既有纪律：它含 wrapped 值，不留残渣。 */
        memset(slotdata, 0, sizeof(slotdata));
        return -11;   /* 复用"密文/密钥不匹配"语义，不新增码值 */
    }

    static int ncg_unlocked = 0;
    if (ncg_unlocked) return 0;

    uint8_t key[16];
    {
        uint8_t xk[8];
        ncg_xor_key(slotdata, xk);
        for (int i = 0; i < 16; i++) key[i] = slotdata[16 + i] ^ xk[i & 7];
        ncg_wipe(xk, sizeof(xk));
    }

    /* ═══ P1-a（2026-10-19）：运行期证书派生，取代 slot 里的 wrapped k_so ═══
     *
     * 修的是强度报告（简盒-07 §4）的核心指控「证书绑定是构建期属性、
     * 运行期零参与」——此前 k_so 直接由 slot[16:32] ^ XOR_KEY 得到，
     * 意味着【拿到 so 就能离线解密，不需要 APK 也不需要证书】。实测：
     * 20 秒纯静态 PoC 即可 dump 出全部明文（见 .p1a/attack_poc.py）。
     *
     * 现在：从【已安装的 APK】读第一签名者证书 → SHA256 → HKDF 派生 k_so。
     * slot[16:32] 保留但不再参与派生（见 locked 侧的 derive 分支），
     * 它只是"未启用证书绑定"时的兼容路径。
     *
     * fail-closed（用户 2026-10-19 拍板）：证书读不到 / 派生结果与
     * slot 里记录的指纹不符 → 直接返回 -12，不解密。
     * 与流程文档「重签必须用同一 keystore」的既有契约一致，
     * 只是把这条契约从"提示"升级为"强制"。
     *
     * 性能实测（真机级存储，真实 4.7MB 已签名 APK）：提取+SHA256+HKDF
     * 中位 14.1 us，占 60fps 一帧的 0.08%，且只在 constructor 跑一次。 */
    /* der_buf/pkg_buf 用 static：约 1.6KB 栈上开对 ART 的 8KB 线程栈偏大，
     * 且本函数全进程只跑一次，static 无并发风险（有 ncg_unlocked 守门）。 */
    static uint8_t der_buf[1536];
    static char pkg_buf[128];
    size_t der_len = 0;

    /* master 来自 head 段内的 ncg_master（2026-10-19 随机化 + 藏进密文）。
     *
     * 本函数【自身就在 head 段内】，所以执行到这里时 ncg_master 已经是
     * 明文（stub 已把整段解开）。这是关键前提：master 的可见性完全
     * 依附于"head 是否已解开"。
     *
     * 全零 = 未锁箱（开发期）：此时不应派生任何真密钥。用全零 master 走
     * 一遍 HKDF 也能算出结果，但那种产物本就未加密（.ncx 明文），
     * 所以行为等价于"没加锁"，不构成安全降级。
     * 锁箱器强制：master 必须非全零，否则 fail-fast。 */
    const uint8_t *master = ncg_master;
    {
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++) acc |= master[i];
        if (acc == 0) {
            /* 未锁箱：走原来的路径（.ncx 本就是明文，不需要解密密钥），
             * 但也不应把全零 master 当成"有效派生源"去算 —— 直接返回 0
             * 让上层走"未锁"分支（magic 不匹配时本就返回 0）。 */
            return 0;
        }
    }
    /* 2026-11-12：拆成独立函数（降寄存器压力）。两条污染纪律不变。 */
    {
        uint8_t k_cert[16];
        if (ncg_derive_kso_bound(so_path, master, der_buf, &der_len,
                                 pkg_buf, sizeof(pkg_buf), slotdata, k_cert) != 0) {
            ncg_wipe(k_cert, sizeof(k_cert));
            ncg_wipe(key, sizeof(key));
            memset(slotdata, 0, sizeof(slotdata));
            return -12;   /* fail-closed：证书/包名任一不可得 */
        }
        memcpy(key, k_cert, 16);
        ncg_wipe(k_cert, sizeof(k_cert));
    }


    /* ── 2026-10-19：受保护资产是两个段（代码 + 常量表）────────────
     * 实测报告 §8.1 的核心缺陷：判定算法（nc_verify_t1）与两张签名表
     * （SIG_SALT / SIG_HASH_STORED）原先全在明文 .rodata，攻击者 od
     * 一条命令读出、5 分钟反推出 32 字节通过凭据。加密层只保护了
     * ncVerify 这个转发壳，核心留在明文中——"锁很好，钥匙挂门上"。
     *
     * 现在拆成两段，共用一把 k_so、一个 MAC：
     *   .ncx     代码（AXR）—— nc_verify_t1 等
     *   .ncxr  常量表（AWR，不可执行）—— SIG_SALT / SIG_HASH_STORED
     * 为什么必须分两段：clang 拒绝 let const 数据进 AXR 段
     * （'causes a section type conflict'），见 nc_link.c 的注释。
     *
     * 向后兼容：老产物只有 .ncx、没有 .ncxr，此时 nseg=1，
     * MAC 与解密行为与历史版本逐字节一致（单段时 MAC 输入 == 该段密文）。 */
    ncg_shdr_t segs[3];
    int nseg = 0;
    /* 2026-11-13：段序 —— .nct 必须排在最前。
     *
     * 为什么不是 .ncx 打头：.ncx 里的函数带 VMP wrapper，wrapper 第一条
     * 就 bl 到解释器、读 .nct 里的字节码。若 .nct 仍为密文 → 解释器把
     * 密文当 opcode → 跳无效地址 → 真机 SIGILL（2026-11-12 实测，崩溃点
     * constant at libnc.so+0x82598，落在 .ncx 段内）。
     * 而 k_nct 只需 master（.ncxhr 已解），与 .ncx 无依赖 → 先解不循环。
     *
     * ⚠️ .nct 是可选段（没开第二套 VMP 的构建没有它），所以 has_nct
     *    要传给 ncg_decrypt_one_seg 做动态钥匙分派。
     * ⚠️ 三处段序必须一致：本函数的 segs[] / ncg_decrypt_one_seg 的
     *    kso_idx / so-section-lock.py 的 _KEY_BY_NAME（后者按名映射，
     *    与位置无关，但 MAC 覆盖顺序仍要与这里一致）。 */
    int has_nct = 0;
    {
        ncg_shdr_t vmp2;
        if (ncg_find_section(so_path, NC_SEC_VMP2, &vmp2) == 0
            && vmp2.size > 0 && (vmp2.flags & SHF_ALLOC)) {
            segs[nseg++] = vmp2;
            has_nct = 1;
        }
    }
    segs[nseg++] = sec;
    {
        ncg_shdr_t ro;
        if (ncg_find_section(so_path, NC_SEC_CONST, &ro) == 0
            && ro.size > 0 && (ro.flags & SHF_ALLOC)) {
            segs[nseg++] = ro;
        }
    }

    uint8_t *target = (uint8_t *)base + sec.addr;

    /* 完整性校验：先验后解（位置在 mprotect/解密之前）。
     * 2026-11-12：拆成独立函数（降 alloca）。⚠️ 时序不变。 */
    {
        int mrc = ncg_verify_seg_mac(master, der_buf, der_len, pkg_buf,
                                     segs, nseg, base, slotdata);
        if (mrc != 0) {
            ncg_wipe(key, sizeof(key));
            if (mrc == -12) memset(slotdata, 0, sizeof(slotdata));
            return mrc;
        }
    }

    /* 2026-11-12：拆成独立函数（降 alloca）。逐段解密+权限+基线都在里面。 */
    {
        int drc = ncg_decrypt_segments(so_path, base, master, der_buf, der_len,
                                       pkg_buf, segs, nseg, has_nct, key);
        if (drc != 0) return drc;
    }
    memset(slotdata, 0, 16);   /* 只清前 16 字节（magic 区），保持历史行为 */
    ncg_unlocked = 1;

    /* 用后即毁已挪至 ncguard_unlock（.text 侧）——第一版放在这里
     * （ncg_head_unlock 尾部）是错的：PC 还在本段执行时把自己置零
     * → SIGSEGV（T4 实测 CRASH(139)）。见 ncguard_unlock 内大注释。 */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * 第二部分：明文 stub（.text，攻击者唯一能直接读到的部分）
 * ═══════════════════════════════════════════════════════════════════ */

/* stub 的密钥槽：由 so-section-lock.py 在锁箱时写入（88 字节，见上方布局图）
 *
 * ⚠️ 2026-10-18 为什么不存 entry_delta（入口符号 − 段起始偏移）：
 *   那需要从 .symtab 读符号地址，而 NDK ndk-build 默认 strip 符号表
 *   （CI 39074690534 实测：lock_head 报「符号 ncg_head_unlock 不在
 *   .symtab」→ protect.sh exit 1 → 构建失败）。
 *   也不能靠"让 CI 不 strip"绕过——那会把 frida_port_probe /
 *   xposed_maps_probe 等探针名暴露进符号表，等于泄露检测意图。
 *   改用【段头信息】推导：strip 只删 .symtab/.strtab，section header
 *   table 始终完整，段地址与段大小照样拿得到。
 *   镜像基址 = &ncg_stub_slot(运行期, PC 相对) − stub_slot_sh_addr(链接期) */
__attribute__((section(NC_SEC_STUBSLOT), used, aligned(1), retain))
const volatile unsigned char ncg_stub_slot[NC_STUB_SIZE] = {0};

/* CRC32（IEEE 802.3，多项式 0xEDB88320）。软件实现——不用 __crc32d：
 * 那需要 -march=armv8-a+crc，而 armeabi-v7a 根本没有该指令，arms 上编译
 * 直接失败。实测软件版对 1.4KB（stub 区）耗时 8.4 us，可接受。
 * 用途：代码自绑定（见 ncg_self_bound_kstub）。 */
static uint32_t ncg_crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

/* 代码自绑定恢复 k_stub（2026-10-19，阶段3）。
 *
 * 攻击面背景（强度报告 §6「抗静态 patch = 弱」）：此前 k_stub 直接
 * slot[8:24] ^ XOR_KEY 得到，与代码零关联。攻击者 patch 明文 stub
 * （例如把 HMAC 校验改成恒真）无需付出任何代价——11 处 patch 点彼此
 * 独立、无链式依赖。
 *
 * 现在：k_stub = HKDF(master, slot_seed, crc32(自身代码区间)) 的前 16 字节。
 *   - 改任何一处 stub 代码 → CRC 变 → k_stub 变 → head 解出乱码
 *   - 没有"校验分支"可以单独 patch 掉：密钥本身就是错的
 *   - 攻击者要绕过，必须同时改代码【并】重新算出正确的 slot seed
 *     （而 seed 在锁箱期才生成，不随 so 分发）
 *
 * 代价实测：CRC32 对 stub 区（约 1.4KB）8.4 us，每次进程一次。
 * 区间取 .text 段中 [ncguard_unlock 起始, .ncxh 起始) ——
 * 该区间无重定位（readelf -r 全部落在 0x71d0 之后），文件字节与内存
 * 字节一致，所以锁箱期算的值与运行期算的值天然相同。 */
uint32_t ncg_self_crc;   /* 由 ncguard_unlock() 在调用前算好 */

/* ── 提交二（2026-10-30）：解密后代码页完整性基线 ─────────────────────
 *
 * 威胁：解锁后 .ncx/.ncxr 明文常驻文件映射页，Frida 的 inline hook 必然
 *   改写该页指令，而原实现对"自己的代码被改"完全无感知。
 *
 * 设计要点（每条都有具体理由，勿简化）：
 *   ① 基线在 ncg_head_unlock 解密完成处采集（ncg_baseline_init），
 *      不在 watchdog 首轮 —— 否则攻击者在 unlock 返回后、首轮轮询前
 *      挂的 hook 会被当成"正确基线"，检测永久失效。
 *   ② 校验函数 ncg_code_check() 放【.ncx 加密段】：它是防御本体，
 *      静态视角下必须是密文（与 env_delayed_kill 同理）。调用方
 *      ncguard_code_check() 留在 .text（它是 unlock 的使用者，
 *      标段即死锁 —— 本文件与 env_check.c 的共同纪律）。
 *   ③ 未解锁态（开发期）一律返回"通过"：基线长度 0 即视为未锁，
 *      保证"不锁箱也能跑"这条既有契约不被破坏。
 *   ④ 比对用【恒定时间累或】而非早退：不是为了防时序（这里没有
 *      秘密可泄露），而是避免编译器把循环优化成"首个不等就返回"后，
 *      攻击者按耗时推断匹配了多少字节。代价近似为零。
 *
 * 能力边界（如实，勿高估）：
 *   能挡：inline hook（Frida Interceptor 默认形态）、代码段 patch 后加载。
 *   挡不住：PLT/GOT hook（不改 .ncx 字节）、ART 层 hook、以及把本校验
 *     函数自身 patch 成恒真。后者只能靠"校验逻辑在密文段"提高门槛。 */

static volatile uint8_t  *ncg_bl_base[NC_CODE_SEG_MAX];
static volatile uint32_t  ncg_bl_len[NC_CODE_SEG_MAX];
static volatile uint32_t  ncg_bl_crc[NC_CODE_SEG_MAX];
static volatile int       ncg_bl_n;      /* 已采集段数；0 = 未解锁/未采集 */

/* 采集基线。由 ncg_head_unlock（.ncxh 内）在解密并 mprotect 之后调用。
 * 只读内存、零 I/O；CRC 用 .text 里现成的 ncg_crc32。
 * 入参是已解析好的运行期地址与长度（.ncxh 侧持有 Elf64_Shdr，不把该
 * 结构体的布局知识复制到 .text —— 少一处"改一处漏一处"的契约副本）。 */
__attribute__((noinline))
static void ncg_baseline_init(uint8_t *const *addrs, const uint32_t *sizes,
                              int nseg) {
    int n = nseg > NC_CODE_SEG_MAX ? NC_CODE_SEG_MAX : nseg;
    int i;
    for (i = 0; i < n; i++) {
        ncg_bl_base[i] = addrs[i];
        ncg_bl_len[i] = sizes[i];
        ncg_bl_crc[i] = ncg_crc32(addrs[i], (size_t)sizes[i]);
    }
    ncg_bl_n = n;
}

/* 用后即毁交接区：定义/前向声明见 ncg_head_unlock 上方。
 * stub（ncg_stub_recover）解出 .ncxh 后把明文区间写这里，
 * ncg_head_unlock 完成使命后按它自毁。 */

/* ncg_magic_ok 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/

/* ncg_rd32 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/


/* ── 不可优化的清零（2026-10-22）──────────────────────────────────────
 * 为什么不能直接用 memset：编译器有权删除"死存储"——当它判定某块栈内存
 * 在函数返回前不再被读取时，会把 memset 整条优化掉，密钥就留在栈上了。
 *
 * 实测证据（-Oz，本仓源码）：ncguard_unlock 里有 6 处 memset 清密钥，
 * 但反汇编里只有 2 条零写入指令 —— 其余 4 处被优化掉了。
 *
 * 做法：通过 volatile 指针写 0。volatile 告诉编译器"这个写入有可观测
 * 副作用，不许删"，因此每次都会生成真实的 strb。
 * ⚠️ 不用 explicit_bzero：那是 BSD/glibc 扩展，Android bionic 的可用性
 *   随 API level 变化，且会引入 PLT 表项（本项目明令禁止）。
 * ⚠️ 不用 memset_s：那是 C11 附录 K 的可选接口，NDK 未提供。
 * 本实现零依赖、零 PLT、任何工具链都能编。 */
void ncg_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* ── SHA-256-CTR 密钥流（2026-10-30）────────────────────────────────
 *
 * 取代原【16 字节周期 XOR】（`cipher[i] = plain[i] ^ k[i & 15]`）。
 * 周期 XOR 是本仓库唯一的密码学硬伤：
 *   ARM64 机器码的函数序言高度可猜（stp x29,x30,[sp,#-16]! 等），
 *   攻击者对密文做间隔 16 的自相关即可看出周期 → 恢复 k_stub_eff
 *   全 16 字节 → head 段明文直接到手（.ncxh 装着 unlock 本体）。
 *   周期 XOR 只能提供"混淆"，提供不了"抗已知明文"。
 *
 * 为什么用 SHA-256 而不是 RC4：
 *   ① stub 只能调 .text 里的函数，而 .text 是攻击者唯一能直读的部分。
 *      RC4 需要 256 字节 S 盒初始化循环 —— 那是"这是 RC4"的活招牌，
 *      且会显著撑大 stub。SHA-256 已在 .text 明文段可用
 *      （nc_guard_key.c 的 ksha256，且 stub 已在调 khmac_sha256 验
 *      head MAC）→ 零新增依赖、零新增 PLT 表项。
 *   ② SHA-256 无 RC4 的统计偏差，也无 RC4 的已知明文攻击。
 *   ③ 代价可接受：.ncxh 实测 1.6KB → 50 次 SHA-256 ≈ 几十微秒，
 *      只在 constructor 跑一次（与 .ncx 的 RC4 解密 102.5μs 同量级）。
 *
 * ⚠️ 域分隔：head 与 master 共用同一把 k_stub_eff，若都从 counter=0
 *   起算即构成 two-time pad（密文 XOR 可还原明文 XOR）。dom 区分两段：
 *   0x01=.ncxh，0x02=.ncxhr。这同时修掉了原实现里 head[0:32] 与
 *   master[0:32] 密钥流完全相同的问题。
 *
 * ⚠️ 两侧必须逐字节一致：构建期见 so-section-lock.py 的 ctr_xor()，
 *   跨语言对拍由 test-so-lock.sh 的 T32 负责。
 *
 * ⚠️ 本函数必须在 .text（不能标 .ncxh）——stub 解 head 时就要用它，
 *   标进 .ncxh 就是"用密文解密文"（本文件已踩过两次的坑）。 */
#define NC_CTR_DOM_HEAD    0x01
#define NC_CTR_DOM_HEADRO  0x02

/* ncg_ctr_xor 已移到 nc_guard_crypto.c（2026-11-06，VMP 覆盖）*/


/* ── ncguard_stub_recover 已拆到 nc_guard_crypto.c（2026-11-06）──────
 *
 * 为什么拆：要给本函数上指令级 VMP。而它原先取了自己的地址 ——
 *     dladdr((const void *)&ncg_stub_recover, &info)
 * Amice 的 vm_virtualize 把除"直接调用"和"annotations 表"之外的
 * 所有函数 use 判为 "has non-call address uses" 并静默跳过
 * （crates/amice/src/aotu/vm_virtualize/mod.rs:128）。所以取自身地址
 * 与 VMP 不可共存，必须先把这个动作移到调用方。
 *
 * 现在的签名多了两个参数（so_path / base），由 ncguard_unlock 传入 ——
 * 它本来就已经为自绑定 CRC 算过这两个值，零额外成本。
 *
 * ⚠️ 搬走后仍在 .text（明文）：它必须在 .ncxh 尚未解锁时运行。
 * ⚠️ 时序约束未变：先验 MAC → mprotect → 解密 → 用后即毁。
 * ⚠️ 它调用的 ncg_slot_read / ncg_ctr_xor / ncg_rd32 等都留在本文件，
 *    通过 nc_guard_internal.h 跨文件引用。
 */

/* ═══════════════════════════════════════════════════════════════════
 * 第三部分：对外接口与触发（.text 明文）
 * ═══════════════════════════════════════════════════════════════════ */

/* ── 提交二（2026-10-30）：解密后代码页完整性校验 ─────────────────────
 *
 * 本函数是【防御本体】，标进 .ncx 加密段 —— 静态视角下它是密文，
 * 攻击者必须先破开 .ncx 才能看到"有这么个校验"，才能针对性 patch。
 * 与 env_delayed_kill / sig_raw_die 的处置一致（"杀的逻辑要藏"）。
 *
 * 调用方 ncguard_code_check() 留在 .text（见其定义）——它是 unlock 的
 * 使用者，标进 .ncx 即死锁。这与全文反复强调的纪律同向：
 *   被调用方进密文段，调用方留明文。
 *
 * ⚠️ 条件化：宿主测试（NCLINK_HOST_TEST / 无 NC_GUARD_SECTIONED）下
 *   不标段，否则宿主没有解锁设施，标了就读密文 → 假红。
 *   （本文件在宿主测试里靠 NC_GUARD_SECTIONED 是否存在决定；
 *    test-so-lock.sh 定义了它，故走真产物形态。） */
#if defined(NC_GUARD_SECTIONED)
#  define NC_CHECK_SECTION __attribute__((section(NC_SEC_CODE), retain, used, noinline))
#else
#  define NC_CHECK_SECTION
#endif

/* 返回 1 = 完好，0 = 被改过。
 * 未解锁/未采集基线（ncg_bl_n == 0）时返回 1 —— 保证开发期"不锁箱也能跑"。
 *
 * ⚠️ 全程零 I/O、零 malloc：只对已映射的内存重算 CRC。
 *   不用"读文件比对"（env_check.c 的 self_text_crc_probe 那种形态）——
 *   这里比的是【解密后的明文】，而文件里是密文，二者天然不同。
 */
NC_CHECK_SECTION
static int ncg_code_check_impl(void) {
    int n = ncg_bl_n;
    int i, ok = 1;
    if (n <= 0) return 1;        /* 未锁箱 / 尚未解锁：不判定 */
    if (n > NC_CODE_SEG_MAX) n = NC_CODE_SEG_MAX;
    for (i = 0; i < n; i++) {
        volatile uint8_t *p = ncg_bl_base[i];
        uint32_t len = ncg_bl_len[i];
        uint32_t want = ncg_bl_crc[i];
        uint32_t got;
        if (!p || len == 0) continue;
        got = ncg_crc32((const uint8_t *)p, (size_t)len);
        /* 恒定时间风格的累或：不早退，避免"匹配了多少字节"可从耗时推断 */
        ok &= (got == want);
    }
    return ok;
}

/* 对外入口（.text，明文）：供 env_check.c 的 watchdog 周期调用。
 *
 * ⚠️ 为什么不把这段逻辑直接写进 env_check.c：
 *   env_check.c 在 sigcheck-only 组合下【不参与编译】（protect.sh 的拷贝
 *   清单只在勾了 envcheck 时拷它）。若检测只存在于它的 watchdog，则
 *   "只勾签名校验"的组合完全没有周期检测 —— 而那是最常见的组合之一。
 *   放在本文件（任何组合都必编）才是全覆盖的。
 *
 * ⚠️ weak 引用：env_check.c 若不在工程里，本函数无人调用（无害）；
 *   若在，则 watchdog 每轮调它。用普通 extern 即可，不需要 weak——
 *   因为调用方在 env_check.c（可选），被调用方在此（必有）。
 */
int ncguard_code_check(void) {
    return ncg_code_check_impl();
}

/* ── 自包含周期检测线程（2026-10-30 提交二，补 sigcheck-only 缺口）──────
 *
 * 为什么需要它：env_check.c 的 watchdog 只在"勾了 envcheck"时存在。
 *   而 sigcheck-only（最常见的组合之一）没有任何周期检测线程 ——
 *   若把 hook 检测只挂在 env_check 上，该组合等于裸奔。
 *
 * 为什么不复用 env_check 的线程：两个文件在不同组合下可能只有一个存在，
 *   跨文件依赖会让某个组合链接失败（本仓库已踩过：sig_check.c 与
 *   env_check.c 各自写一份 kill 实现，注释里写明原因）。
 *   所以本文件自带一份，用静态标志保证"只起一次"，与 env_check 的
 *   线程并存也无害（两者都是只读比对，没有共享写状态）。
 *
 * ⚠️ NC_NO_SELF_WATCHDOG 宏：当 env_check.c 参与编译时由构建侧定义，
 *   避免同一功能起两个线程（浪费一次唤醒/秒级开销，虽无害但没必要）。
 *   默认（未定义）即启用 —— fail-safe 方向正确：宁可多一个线程，
 *   也不要出现"某个组合没有检测"的静默空洞。
 *
 * ⚠️ 间隔 25s：与 env_check 的 CRC 重探针（每 5 轮 × 5s）对齐。
 *   单次全段 CRC（.ncx ~8.5KB + .ncxr 96B）实测 < 20 μs，
 *   25s 一次对 CPU 的影响在小数点后第三位。
 */
#ifndef NC_CODE_CHECK_INTERVAL_SEC
#define NC_CODE_CHECK_INTERVAL_SEC 25
#endif

/* 极简的"自我了断"：不引 libc、不走 PLT（与项目既有纪律一致）。
 * 用 __builtin_trap 而非 abort：arm64 上生成 brk #1 → SIGILL，
 * 会留 tombstone，且二进制里没有 abort@plt 可被 patch。 */
static void ncg_self_kill(void) {
    for (;;) {
        __builtin_trap();
    }
}

static void *ncg_code_watchdog(void *arg) {
    (void)arg;
    for (;;) {
        /* 用 nanosleep 而非 sleep：避免与 env_check 的 sleep 语义混淆，
         * 且 nanosleep 不占额外栈。失败也无所谓，继续下一轮。 */
        struct timespec ts;
        ts.tv_sec = NC_CODE_CHECK_INTERVAL_SEC;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        if (!ncg_code_check_impl()) {
            ncg_self_kill();
        }
    }
    return NULL;
}

static void ncg_code_watchdog_start(void) {
#if !defined(NC_NO_SELF_WATCHDOG)
    static int started = 0;
    pthread_t t;
    pthread_attr_t attr;
    if (started) return;
    started = 1;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, ncg_code_watchdog, NULL) != 0) {
        /* 起不来线程：不在这里杀（避免"线程资源紧张"被误判成攻击）。
         * 检测仍有 env_check 那条路；且基线采集已完成，selftest 仍可用。
         * 静默失败优于误杀正常用户 —— 与 error 四十九 的教训同向。 */
    }
    pthread_attr_destroy(&attr);
#else
    /* 构建侧显式关闭（env_check 已有同功能线程） */
#endif
}

/* 与 nc_guard_unlock.c 同名的对外入口：nc_guard_jni.c 的 selftest 依赖它 */
int ncguard_unlock(void) {
    static int done = 0;
    if (done) return 0;

    /* ── T4：读槽到本函数栈缓冲（2026-10-28 / 10-29 修正）────────────
     * 顺序很关键：自绑定 CRC 要读 slot[36:40]/[40:44]，而那是密文区，
     * 必须先解密。
     * ⚠️ 2026-10-29：不再有全局副本，改为本函数栈缓冲，用完即 wipe。 */
    uint8_t slot_buf[NC_STUB_SIZE];
    int slot_ok = 0;
    {
        char _p[512];
        Dl_info _di;
        memset(&_di, 0, sizeof(_di));
        if (dladdr((const void *)&ncguard_unlock, &_di) != 0
            && _di.dli_fbase && _di.dli_fname) {
            strncpy(_p, _di.dli_fname, sizeof(_p) - 1);
            _p[sizeof(_p) - 1] = 0;
            if (ncg_slot_read(_p, (uintptr_t)_di.dli_fbase, slot_buf) == 0)
                slot_ok = 1;
        }
    }

    /* 阶段3 自绑定：先算自身代码 CRC，再进 stub 恢复。
     *
     * 区间取【ncguard_unlock 函数自身起始, 长度由 slot[36:40] 记录】——
     * 锁箱期把这段代码当作"受保护代码"，其 CRC 直接混进 k_stub。
     * 区间必须【不含】CRC 计算代码本身（否则自指、无解），所以：
     *   - 区间起点 = ncg_stub_recover 的地址（stub 主体）
     *   - 区间长度 = slot 里存的长度（锁箱期由 Python 按段表算）
     * 未锁时 slot 无 magic，ncg_self_crc 保持 0，stub 会直接返回，
     * 不影响开发期"不锁箱也能跑"。
     * ⚠️ 2026-10-28：字段读取一律走 ncg_slot_live（解密后的副本），
     *    不再读 ncg_stub_slot（文件里的密文）。 */
    if (slot_ok) {
        uint32_t code_addr = ncg_rd32(slot_buf + NC_OFF_CODE_ADDR);
        uint32_t code_len  = ncg_rd32(slot_buf + NC_OFF_CODE_LEN);
        if (code_len > 0 && code_len < (64u << 20) && code_addr != 0) {
            /* 镜像基址 = slot 运行期地址 − slot 链接期地址（同 stub 的算法） */
            uintptr_t base = (uintptr_t) ncg_stub_slot
                             - (uintptr_t) ncg_rd32(slot_buf + 24);
            const uint8_t *code = (const uint8_t *)(base + code_addr);
            ncg_self_crc = ncg_crc32(code, code_len);
        }
    }

    (void)ncg_decoy_sink();      /* 诱饵消费：防 .data 碎片被 gc-sections 回收 */
    /* 先确保 head 本体是明文。
     * ⚠️ 2026-11-06：签名变了 —— so_path / base 由本函数传入（上面已算好）。
     *    原先 stub 自己 dladdr(&自身) 取这两个值，那是 non-call address use，
     *    会让 VMP 判定跳过它。现在取地址只发生在本函数（.text，不虚拟化）。 */
    {
        char _sp[512];
        uintptr_t _base = 0;
        Dl_info _di;
        int _ok = 0;
        memset(&_di, 0, sizeof(_di));
        if (dladdr((const void *)&ncguard_unlock, &_di) != 0
            && _di.dli_fbase && _di.dli_fname) {
            strncpy(_sp, _di.dli_fname, sizeof(_sp) - 1);
            _sp[sizeof(_sp) - 1] = 0;
            _base = (uintptr_t)_di.dli_fbase;
            _ok = 1;
        }
        if (_ok) ncguard_stub_recover(_sp, _base);
    }
    /* 2026-11-12：把自身地址传进去，替掉 .ncxh 内部那两处
     * dladdr(&自身)。理由见 ncg_resolve_self 与 ncg_head_unlock 的注释：
     * 函数内取自身地址会被 Amice 判 "non-call address uses" 而跳过 VMP。
     * 本函数在 .text（不虚拟化），取地址在这里是安全的。 */
    int rc = ncg_head_unlock((const void *)&ncguard_unlock);  /* 再调本体解 .ncx */
    if (rc == 0) {
        done = 1;
        /* 提交二（2026-10-30）：基线已由 ncg_head_unlock 采集完毕，
         * 此处启动周期校验线程（sigcheck-only 组合的唯一检测来源）。
         * 必须在 rc==0 之后：未解锁时 .ncx 是密文，CRC 比对没有意义。 */
        ncg_code_watchdog_start();
        /* ══ 用后即毁（针对破解复盘"最致命破绽"）════════════════════
         *
         * 攻击面：stub XOR 解出 .ncxh 明文后，攻击者在 SIGILL handler 里
         * 抢 dump。此前明文从解密起【直到进程死】一直驻留。
         *
         * 现在只抹 master（32B）：断掉"dump 全内存 → 离线重算 k_so"这条路。
         * 攻击者 dump 到的是全零 master，有调度器代码也推不出密钥。
         *
         * ⚠️ .ncxh 代码区【不抹】——两轮实测均 SIGSEGV：
         *   ① 在 ncg_head_unlock 尾部自抹：PC 在本段内执行时自毁 → 崩。
         *   ② 挪到本函数（.text 侧，PC 已离开）仍崩：抹除 + clear_cache
         *      会破坏 .ncxh 段内的链接器常量池/veneer（ARM64 ldr-literal
         *      池就在函数尾同 section），I-cache 失效后取指落在已毁数据。
         *      veneer 位置随链接器版本变，安全边距不可靠，故放弃。
         *   代价：代码区驻留 = "逻辑可读但无密钥可用"（复盘报告的攻击者
         *   正是卡在这一点），动态路径由 hook 探针 + anti-diff 继续把守。
         *
         * ⚠️ 抹除必须在【本函数】（.text）里做，不能放在 ncg_head_unlock
         *   （.ncxh 内）——那里 PC 还在本段，自毁会取到半新半旧的指令流。
         *
         * 此刻安全的前提：.ncx 已解密、done=1 后 ncg_head_unlock 不再被调、
         *   .ncxhr 与 .data 同页不能动权限但 memset 32B 自身安全。 */
        {
            /* ⚠️ 下面两行不是残留：ncg_head_live/_len 由明文 stub 写入
             * （见 ncg_stub_recover 尾部），此处消费一次以维持"交接区"语义——
             * 曾设计为抹 .ncxh 代码区用，抹除方案放弃后该值仍必须被引用，
             * 否则 --gc-sections 会回收这两个变量（实测产物字节变化）。 */
            volatile uint8_t *self = (volatile uint8_t *)ncg_head_live;
            uint32_t n = ncg_head_live_len;
            (void)self; (void)n;
            /* 真正的抹除：master（32B）。*/
            {
                volatile uint8_t *m = ncg_master;
                for (int i = 0; i < 32; i++) m[i] = 0;
            }
        }
    }
    return rc;
}

/* so 加载即跑：先解 head 本体，再由本体解业务段。
 * 优先级 50：早于任何可能的其它 constructor，确保业务段在 App 代码前就绪。 */
__attribute__((constructor(50)))
static void ncg_boot_init(void) {
    (void) ncguard_unlock();
}

/* maps 扫描子函数（2026-11-06 从 ncg_find_apk_path 拆出）。
 * 为什么拆：主函数有 17 个基本块、5 个 phi，VMP 实测报
 *     skip function "ncg_find_apk_path": values=22
 *     VM x-register budget exceeded
 * phi 会被 translator 固定到 VM 寄存器贯穿全函数，是压力主因。
 * 拆出扫描循环后主函数只剩线性调度，压力大降。
 *
 * ⚠️ noinline 不可省（-Oz 会内联回去，拆分失效）。 */
__attribute__((noinline))
int ncg_scan_maps_for_base_apk(const char *maps_path,
                                      char *out, size_t cap) {
    int fd = open(maps_path, O_RDONLY);
    if (fd < 0) return -1;

    /* maps 可能上百 KB，按块读，逐行拼装。
     * buf 只是【读块】，line 才累积一行 —— 换行符跨块时 ll 继续累积，
     * 所以 buf 小于 line 不影响正确性。 */
    static char buf[512];
    char line[600];
    size_t ll = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n') {
                line[ll] = 0;
                ll = 0;
                const char *p = strstr(line, "base.apk");
                if (p) {
                    /* 行格式：addr perms offset dev inode  path
                     * 路径从第一个 '/' 开始 */
                    const char *sl = strchr(line, '/');
                    if (sl && sl <= p) {
                        size_t l = (size_t)(p - sl) + 8;   /* 含 "base.apk" */
                        if (l < cap) {
                            memcpy(out, sl, l);
                            out[l] = 0;
                            close(fd);
                            return 0;
                        }
                    }
                }
            } else if (ll + 1 < sizeof(line)) {
                line[ll++] = c;
            }
        }
    }
    close(fd);
    return -1;
}

