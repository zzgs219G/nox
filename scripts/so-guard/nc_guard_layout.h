/* nc_guard_layout.h — so 段加密设施的【唯一契约真相源】
 *
 * 本文件不含任何逻辑，只有契约常数。存在目的：把"改一处必须同步另一处"
 * 从注释变成编译期/构建期强制。
 *
 * 背景：契约常数此前散落 4 种语言、7 个文件、24 处副本。slot 已扩过两次
 * （80→96、88→104），漏同步的症状是【运行期 SIGILL】——Java 侧只看到
 * selftest != 59，完全指不出"某个长度常量没同步"。历史报错三/九/十一/十二
 * 全是同类根因。
 *
 * ⚠️ 纪律：改本文件任何常量，必须跑 bash scripts/lib/tests/test-so-lock.sh
 *   T20 与 so-section-lock.py 逐字节对拍；T21 扫描全仓段名字面量；
 *   T22 验证不改变产物字节。任一红 = 构建期 fail-fast 而非运行期 SIGILL。
 *
 * ⚠️ 本文件会被拷进 NDK 工程，故不得 include 仓库内其它头文件
 *    （零依赖，任何工具链都能编）。
 */
#ifndef _NC_GUARD_LAYOUT_H_
#define _NC_GUARD_LAYOUT_H_

/* ═══ 一、段名（6 + 3 个）═══════════════════════════════════════════
 * 2026-10-19 中性化改名（旧名自解释，readelf -S 即可列举加固结构）：
 *   .ncguard     → .ncx     .ncguard_ro      → .ncxr
 *   .ncguard_head→ .ncxh    .ncguard_head_ro → .ncxhr
 *   .nckey       → .nck     .nckey_stub      → .ncks
 *
 * 2026-11-13 新增 3 个 VMP 段（.ncr/.nct/.ncd，见下方注释）。
 * 它们是【可选段】——不开 VMP 的构建没有，所以不影响历史产物的契约。
 *
 * ⚠️ 段名是 so 的指纹特征。改名会让所有历史产物的锁箱/开箱契约失效，
 *    故 2026-10-19 之后不再变动。要加新段，先在 T21 登记。
 *
 * 消费方（改名前同步检查）：
 *   C:  nc_guard_boot.c / nc_link.c / env_check.c / sig_check.c / nc_guard_probe.c
 *   Py: so-section-lock.py / so_section_mark.py
 *   Sh: make-sig-hash.sh / protect.sh
 */
#define NC_SEC_CODE      ".ncx"    /* 加密代码段（AXR，可执行）*/
#define NC_SEC_CONST     ".ncxr"   /* 加密常量表段（AWR，不可执行）*/
#define NC_SEC_HEAD      ".ncxh"   /* unlock 本体（二级锁箱对象）*/
#define NC_SEC_HEADRO    ".ncxhr"  /* master 数据段（AWR，32B）*/
#define NC_SEC_SLOT      ".nck"    /* 一级密钥槽*/
#define NC_SEC_STUBSLOT  ".ncks"   /* 二级 stub 密钥槽*/

/* ── VMP 解释器段（2026-11-13 按用户架构重定，amice ≥ v0.1.6-nox15）───
 *
 * 架构（用户明确）：
 *
 *   .ncx   业务代码被 VMP 后的【字节码 + wrapper】  ← 锁箱加密的就是它
 *   .ncr   第一套 VMP（本仓库解密链）的【解释器】   ← 明文
 *   .nct   第二套 VMP（消费方 sigcheck）的【解释器】 ← 锁箱加密
 *
 * Amice（编译期 LLVM pass）把被 VMP 的函数体换成「wrapper + 解释器」：
 *   · wrapper 留在函数原来的段（业务代码 → .ncx）
 *   · 字节码跟着函数走（不单独指定段 → 落在 .ncx 旁边）
 *   · 解释器（dispatch）由 AMICE_VM_INSN_SECTION 指定段
 *
 * amice v0.1.6-nox15 起解释器段可配置（此前 runtime.rs 里 set_section
 * 出现 0 次，解释器全落在 .text —— 锁箱根本覆盖不到）。
 *
 * 两套的区别只在【何时执行】：
 *
 *   .ncr  第一套解释器 → 【必须明文】
 *         循环依赖：解 .ncx 要 k_so ← master ← .ncxhr ← k_stub ← .ncks
 *         ← boot_key ← ncg_boot_key，而 ncg_boot_key 自己被 VMP，
 *         执行它要经过第一套解释器。若解释器加密，解锁前跑不了 → 自锁。
 *
 *   .nct  第二套解释器 → 【锁箱加密】
 *         那些函数在 constructor(65535) 才跑，那时解锁（constructor(50)）
 *         早已完成，解释器已可解密，无循环依赖。
 *
 * ⚠️⚠️ 解释器段必须是【可执行】的（SHF_EXECINSTR）。它是 ARM64 代码，
 *    放进只读数据段执行即 SIGSEGV。锁箱解密后会 mprotect 成 RX。
 *    （2026-11-13 之前的 .ncr/.nct 是纯数据段 A，装的是字节码不是代码；
 *      现在语义变了 —— 装代码，必须 AX。）
 *
 * ⚠️ 段名刻意不带 vm/vmp/amice 字样：段名留在 .shstrtab（strip 删不掉），
 *    自解释的名字等于直接告诉逆向者"这里是 VM"。.ncr/.nct 与
 *    .ncx/.ncxh/.ncxr 同族。
 * ⚠️ 本仓库不定义任何 __attribute__((section(NC_SEC_VMP*))) —— 这些段由
 *    Amice 插件生成，这里只登记段名供解锁时查找。
 * ⚠️ .nct 与 .ncr 都是【可选段】：没开 VMP 的构建两者都没有。消费顺序
 *    必须动态决定（见 nc_guard_boot.c 的 has_nct），写死索引会让钥匙错配。 */
#define NC_SEC_VMP       ".ncr"    /* 第一套解释器（明文，循环依赖，AX）*/
#define NC_SEC_VMP2      ".nct"    /* 第二套解释器（锁箱加密，AX）*/
/* 2026-11-13：VMP 数据段。与解释器段分开是 clang 硬约束 ——
 * 同名段里既有函数又有 const 数据会报
 *   `error: 'f' causes a section type conflict with 'tbl'`（实测确认）。 */
/* ⚠️⚠️ 两套 VMP 必须用【不同】段名（2026-11-13 实测踩过）：
 *    第一版两套都用 ".ncq,.ncs" → 链接后混在同一段里 →
 *    第一套解释器（.ncr）按 adr 偏移去 .ncs 找表，找到的却是第二套的
 *    → 寄存器读到垃圾（x20=0x48416df089015220）→ SIGSEGV。
 *
 *    实测证据（2026-11-13 06:42 产物）：
 *      .ncs 里 129 个 RELATIVE 重定位的 addend 全部指向 .text
 *      （那是第二套的 handler 表），第一套的表被挤掉/错位。
 *
 *    命名沿用同族风格，不暴露"vm/vmp/amice"字样：
 *      第一套：.ncq 字节码 / .ncs 表
 *      第二套：.ncv 字节码 / .ncw 表
 */
#define NC_SEC_VMPBC     ".ncq"    /* 第一套 VM 字节码（纯数据，可加密）*/
#define NC_SEC_VMPTBL    ".ncs"    /* 第一套 descriptor/native 表（明文）*/
#define NC_SEC_VMPBC2    ".ncv"    /* 第二套 VM 字节码（消费方）*/
#define NC_SEC_VMPTBL2   ".ncw"    /* 第二套 descriptor/native 表（消费方）*/

/* ═══════════════════════════════════════════════════════════════════
 * 二、.nck 一级密钥槽：96 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局（偏移为相对 slot 起始的字节数）：
 *   [ 0:16) magic        seed + 8 个 0
 *   [16:32) decoy        诱饵（P1-a 起非真密钥，真 k_so 由运行期证书派生）
 *   [32:48) decoy_mac    诱饵（同上）
 *   [48:80) expect_mac   HMAC-SHA256(k_mac, 密文) 32B
 *   [80:88) pkg_sha8     SHA256(包名) 前 8 字节
 *   [88:96) reserved     对齐预留
 *
 * 锁箱侧：so-section-lock.py lock() 的 blob 组装
 * 开箱侧：nc_guard_boot.c ncg_head_unlock()
 * C 侧段本体：nc_guard_probe.c 的 ncg_key_slot[NC_SLOT_SIZE]
 */
#define NC_SLOT_SIZE      96
#define NC_OFF_EXPMAC     48   /* [48:80) expect_mac 起点*/
#define NC_OFF_PKG_SHA    80   /* [80:88) 包名指纹起点*/

/* ═══════════════════════════════════════════════════════════════════
 * 三、.ncks 二级 stub 密钥槽：104 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局：
 *   [ 0: 8) magic seed
 *   [ 8:24) wrapped k_stub      = k_stub ^ XOR_KEY
 *   [24:28) stub_sh_addr        .ncks 段自身链接期虚拟地址
 *   [28:32) head_sh_addr        .ncxh 链接期虚拟地址
 *   [32:36) head_size           .ncxh 字节数
 *   [36:40) code_addr           .text 段起始（自绑定 CRC 区间起点）
 *   [40:44) code_len            .text 段长度
 *   [44:48) reserved
 *   [48:64) wrapped k_mac_head  = k_mac_head ^ XOR_KEY
 *   [64:96) expect_mac_head     HMAC-SHA256(k_mac_head, head 密文)
 *   [96:100) head_ro_addr       .ncxhr 段链接期虚拟地址
 *   [100:104) head_ro_size      该段字节数
 *   [104:112) frag[4]           XOR_KEY 碎片（构建期随机，见 NC_OFF_FRAGS）
 *
 * 锁箱侧：so-section-lock.py lock_head() 的 blob 组装 + 两条 assert
 * 开箱侧：nc_guard_boot.c 明文 stub（ncg_stub_recover / ncguard_unlock）
 * C 侧段本体：nc_guard_boot.c 的 ncg_stub_slot[NC_STUB_SIZE]
 */
#define NC_STUB_SIZE        112   /* [104:112) 为碎片区，见 NC_OFF_FRAGS */
/* 碎片区：XOR_KEY 的 4 个 uint16，构建期随机生成后写进 slot。
 * 为什么放这里而不放 .data：破解复盘实测"objdump 读 .data + 反汇编
 * 5 分钟重组出 XOR_KEY"。挪进 slot 后攻击者必须先读懂 slot 布局
 * （壳的核心格式）才有重组输入——把"读常量"变成"读格式"。
 * 详细演进与反向纪律见 nc_guard_boot.c 的 XOR_KEY 碎片化注释。 */
#define NC_OFF_FRAGS        104   /* [104:112) 4×uint16 碎片（随机）*/
#define NC_OFF_CODE_ADDR    36   /* 代码自绑定 CRC 区间起始*/
#define NC_OFF_CODE_LEN     40   /* 区间长度（字节）*/
#define NC_OFF_K_MAC_HEAD   48   /* wrapped k_mac_head 起点*/
#define NC_OFF_EXPMAC_HEAD  64   /* expect_mac_head 起点*/
#define NC_OFF_HEADRO_ADDR  96   /* .ncxhr 段链接期虚拟地址*/
#define NC_OFF_HEADRO_SIZE 100   /* .ncxhr 段字节数*/

/* ═══════════════════════════════════════════════════════════════════
 * 三点五、T4：槽段加密（2026-10-28）
 * ═══════════════════════════════════════════════════════════════════
 * 动机（逆向报告实测）：.ncks / .nck 是【明文段】，攻击者 readelf 拿到
 * 偏移后 dd 读 8 字节即可拼出 XOR_KEY → 整条解密链 1 分钟内走完。
 * 这是"28 分钟摸清 90% 结构"的真因，不是段名或标准常数。
 *
 * 设计：boot_key 由 .text 内容派生，用它 RC4 加密两个槽段。
 *
 * 循环依赖的解法（关键）：
 *   boot_key 需要 .text 的 CRC，但 .text 的地址存在 .ncks 里，而 .ncks
 *   又要 boot_key 才能解 → 环。
 *   解法：stub 用 &ncg_stub_recover 作锚点（PC 相对，编译期生成 adr），
 *   （历史：曾设计成锚点±区间，后因 Python 侧无法复现 strip 后的符号
 *    地址而废弃，改用段表起点。详见 nc_guard_boot.c 的 ncg_boot_key。）
 *
 * 加密范围（解不开 magic 就无法判"未锁"，故 magic 区必须豁免）：
 *   .ncks[0:8)    不加密   —— magic seed，解密前必需
 *   .ncks[8:112)  加密     —— 全部密钥材料
 *   .nck[0:96)    加密     —— .nck 的 magic 判定发生在其后，可先解再判
 *
 * ⚠️ 攻击者仍可反汇编 stub 复现 boot_key 派生（算法在明文 .text 里）。
 *    本改动提高的是"发现与理解"成本，不是数学上的不可绕过。
 *    如实记录，避免后人高估。
 * ⚠️ 区间必须无重定位（文件内容 == 内存内容），否则正常包也解不开。
 *    test-so-lock.sh 新增 T31 断言这一点。 */
/* CRC 区间长度上限。
 * ⚠️ 2026-10-28 CI 实测踩过的坑：原写法是 BACK=0x1000 + FWD=0x3000 两个
 *    常量相加 = 16384 字节，但 armeabi-v7a 的 .text 只有 12000 字节 →
 *    锁箱直接 fail-fast（"boot_key CRC 区间 16384 > .text 段 12000"）。
 *    arm64 的 .text 更大所以本地没暴露 —— 典型的"只验证了一个 ABI"。
 * 改法：只留一个上限，锁箱期与运行期都取 min(上限, .text 实际长度)，
 *    两个 ABI 自动适配，未来 .text 变小时也不会再炸。 */
#define NC_BOOT_SPAN        0x4000   /* CRC 区间长度上限（16KB） */
#define NC_BOOT_SPAN_MIN    0x0800   /* 下限：太短则 boot_key 强度不足 */
#define NC_BOOT_SALT_INIT \
    { 0x6e, 0x63, 0x1f, 0x2b, 0x7a, 0x44, 0x91, 0xd8, \
      0x03, 0x5c, 0xe6, 0x18, 0xaf, 0x72, 0x39, 0xc4 }  /* "nc" + 16B 区分值 */
/* HKDF 的 info 参数（boot 域）。
 *
 * ⚠️ 2026-11-06 P0：本宏【只作 so-section-lock.py 的抽取源】，
 *    C 代码不得直接引用它 —— 一旦被 .c 引用，字符串就以明文进 .rodata。
 *    实测 v0.9.5 产物："nc-boot-v1" 在 .rodata 0xcd96，r2 一条
 *        axt 0xcd96  →  0x389bc（VM wrapper 旁边）
 *    就把"这里是 boot_key 派生"告诉了攻击者，VMP 的保护被绕过一半。
 *
 *    现在 C 侧走 nc_guard_key.c 的 ncg_label_boot()，从 XOR 0x5A 密文表
 *    还原到栈缓冲，二进制里不留常量。派生结果逐字节不变（已对拍）。
 *
 *    为什么不像别处那样改成整数表：so-section-lock.py:114 用正则
 *    `#define\s+NC_BOOT_INFO\s+"([^"]+)"` 从这里抽字符串给 Python 侧算，
 *    改成整数会让正则抽不到 → 锁箱 fail-fast。
 *    宏不被 C 引用就不会进二进制（已实测确认），所以保留字符串是安全的。
 *
 * ⚠️ 改本值等于改派生产物 → 所有历史产物失效。真要改必须同步
 *    nc_guard_key.c 的 ncg_label_enc_boot[] 与 Python 侧 derive。 */
#define NC_BOOT_INFO        "nc-boot-v1"
#define NC_OFF_FRAGS_ENC    8   /* .ncks 加密区间起点（magic 之后）*/

/* ═══════════════════════════════════════════════════════════════════
 * 四、magic 种子（8 字节）
 * ═══════════════════════════════════════════════════════════════════
 * 语义：slot 前 8 字节 == 本 seed ⇒ 已锁箱；不匹配 ⇒ 未锁，放行。
 * 锁箱器落盘的就是 seed 本身（不是 seed ^ XOR_KEY），运行期直接逐字节比。
 *
 * ⚠️ 真实收益仅一条：strings 搜不到 "NCKEYLOCK"/"NCSTUBLK" 字面量。
 *    碎片密钥【不参与】magic 比较（见 ncg_magic_ok：只做 got[i]^seed[i]
 *    累或）——它只在 ncg_xor_key() 里用于恢复 k_stub / k_mac_head。
 *    攻击者 dump 到 slot 前 8 字节即可直接比对，零额外成本。
 *    写清楚这条是防止后人据此高估防御强度、少做别的加固。
 */
#define NC_SEED_SLOT_INIT \
    { 0x30, 0x72, 0xEE, 0x48, 0x91, 0xDE, 0x04, 0xB5 }
#define NC_SEED_STUB_INIT \
    { 0x30, 0x72, 0xF6, 0x59, 0x9D, 0xD0, 0x07, 0xBD }

/* ═══════════════════════════════════════════════════════════════════
 * 五、XOR_KEY 碎片表
 * ═══════════════════════════════════════════════════════════════════
 * 完整 8 字节 XOR_KEY 由 4 个 volatile uint16 在运行期拼回
 * （见 nc_guard_boot.c 的 ncg_xor_key()）。
 * 本表是"逻辑字节 i 取哪个碎片"的映射；i<4 取低位、i>=4 取高位。
 *
 * ⚠️ 与 so-section-lock.py 的 XOR_KEY 必须逐字节一致（T20 对拍）。
 *    碎片常量本体（ncg_frag_a/b/c/d）刻意【不】进本文件——它们是运行期
 *    才知道的值，集中放一个表就等于把它们重新聚成一串可被一次性读走的
 *    常量。分散在 volatile 变量里正是为了阻止编译期折叠与集中读取。
 */
#define NC_XOR_FRAG_INIT \
    { 1, 0, 2, 3, 0, 1, 3, 2 }

/* ═══════════════════════════════════════════════════════════════════
 * 六、编译期自检
 * ═══════════════════════════════════════════════════════════════════
 * 这几条 _Static_assert 挡的是"偏移重叠/越界"类手误——那是上一轮
 * 88→104 扩容时最危险的错误模式（新字段与既有 MAC 字段重叠会
 * 【静默】破坏校验，编译期完全不报）。 */
_Static_assert(NC_OFF_EXPMAC + 32 <= NC_SLOT_SIZE,
               "NC_OFF_EXPMAC+32 溢出 .nck slot");
_Static_assert(NC_OFF_PKG_SHA + 8 <= NC_SLOT_SIZE,
               "NC_OFF_PKG_SHA+8 溢出 .nck slot");
_Static_assert(NC_OFF_HEADRO_SIZE + 4 <= NC_STUB_SIZE,
               "NC_OFF_HEADRO_SIZE+4 溢出 .ncks slot");
_Static_assert(NC_OFF_EXPMAC_HEAD + 32 <= NC_OFF_HEADRO_ADDR,
               "expect_mac_head 与 head_ro 字段重叠");
_Static_assert(NC_OFF_K_MAC_HEAD + 16 <= NC_OFF_EXPMAC_HEAD,
               "k_mac_head 与 expect_mac_head 重叠");
_Static_assert(NC_OFF_FRAGS + 8 <= NC_STUB_SIZE,
               "碎片区溢出 .ncks slot");
/* T4：加密区间自洽性（magic 之后到段尾，必须非空且不越界） */
_Static_assert(NC_OFF_FRAGS_ENC == 8, "T4 加密区间起点必须紧跟 magic(8B)");
_Static_assert(NC_OFF_FRAGS_ENC < NC_STUB_SIZE, "T4 加密区间为负长度");
_Static_assert(NC_BOOT_SPAN >= NC_BOOT_SPAN_MIN,
               "T4 CRC 区间上限小于下限，配置矛盾");
_Static_assert(NC_BOOT_SPAN_MIN >= 0x400,
               "T4 CRC 区间下限过小，boot_key 强度不足");

#endif /* _NC_GUARD_LAYOUT_H_ */
