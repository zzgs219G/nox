/* nc_guard_layout.h — 契约唯一真相源（零逻辑，只有常数）
 *
 * ⚠️ 改任何常量必须跑 test-so-lock.sh：T20 跨语言对拍 / T21 段名登记 /
 *    T22 字节等价。任一红 = 构建期 fail-fast，好过运行期 SIGILL。
 * ⚠️ 会被拷进各种 NDK 工程 → 不得 include 仓库内其它头文件，不要加逻辑。
 *
 * 段名对照表、加密取舍、两套 VMP 的关系见 docs/so防护架构.md §15
 */
#ifndef _NC_GUARD_LAYOUT_H_
#define _NC_GUARD_LAYOUT_H_

/* ═══ 一、段名 ══════════════════════════════════════════════════════
 * ⚠️ 改名 = 所有历史产物的锁箱/开箱契约失效。加新段先在 T21 登记。
 * 消费方（改名时同步）：C 侧 6 个 .c / so-section-lock.py /
 * so_section_mark.py / make-sig-hash.sh / protect.sh
 */
#define NC_SEC_CODE      ".ncx"    /* 加密代码段（AXR，可执行）*/
#define NC_SEC_CONST     ".ncxr"   /* 加密常量表段（AWR，不可执行）*/
#define NC_SEC_HEAD      ".ncxh"   /* unlock 本体（二级锁箱对象）*/
#define NC_SEC_HEADRO    ".ncxhr"  /* master 数据段（AWR，32B）*/
#define NC_SEC_SLOT      ".nck"    /* 一级密钥槽*/
#define NC_SEC_STUBSLOT  ".ncks"   /* 二级 stub 密钥槽*/

/* ── VMP 段（Amice 生成，本仓库 C 代码不标记它们）
 *   第一套（nox 解密链）      .ncr 解释器  .ncq 字节码  .ncs 表
 *   第二套（消费方 sigcheck） .nct 解释器  .ncv 字节码  .ncw 表
 * 判断代码还是数据：readelf 权限列带 x = 代码，别靠段名猜。
 * ⚠️ 两套段名必须不同（同名会混淆 → 寄存器读垃圾 → SIGSEGV，K-06）。
 * ⚠️ .nct/.ncv 不加密（体积 +150KB，强度增益接近零）；.ncr/.ncq 必须明文
 *    （解 .ncx 的钥匙要执行第一套解释器）。
 * 详见 docs/so防护架构.md §15.2 / §15.5 */
#define NC_SEC_VMP       ".ncr"    /* 第一套解释器（代码，明文）*/
#define NC_SEC_VMP2      ".nct"    /* 第二套解释器（代码，明文）*/
#define NC_SEC_VMPBC     ".ncq"    /* 第一套字节码（数据，明文）*/
#define NC_SEC_VMPTBL    ".ncs"    /* 第一套 descriptor/native 表（数据）*/
#define NC_SEC_VMPBC2    ".ncv"    /* 第二套字节码（数据，明文）*/
#define NC_SEC_VMPTBL2   ".ncw"    /* 第二套 descriptor/native 表（数据）*/
/* ═══ 二、.nck 一级密钥槽：96 字节 ═══════════════════════════════════
 *   [ 0:16) magic        seed + 8 个 0
 *   [16:48) decoy        诱饵（非真密钥；真 k_so 由运行期证书派生）
 *   [48:80) expect_mac   HMAC-SHA256(k_mac, 密文)
 *   [80:88) pkg_sha8     SHA256(包名) 前 8 字节
 *   [88:96) reserved
 * 锁箱 so-section-lock.py lock() / 开箱 ncg_head_unlock() / 段本体在 probe.c */
#define NC_SLOT_SIZE      96
#define NC_OFF_EXPMAC     48   /* [48:80) expect_mac 起点*/
#define NC_OFF_PKG_SHA    80   /* [80:88) 包名指纹起点*/
/* ═══ 三、.ncks 二级 stub 密钥槽：112 字节 ═══════════════════════════
 *   [ 0: 8) magic seed
 *   [ 8:24) wrapped k_stub      = k_stub ^ XOR_KEY
 *   [24:28) stub_sh_addr        .ncks 段自身链接期虚拟地址
 *   [28:32) head_sh_addr        .ncxh 链接期虚拟地址
 *   [32:36) head_size           .ncxh 字节数
 *   [36:40) code_addr           .text 起始（自绑定 CRC 区间起点）
 *   [40:44) code_len            .text 长度
 *   [44:48) reserved
 *   [48:64) wrapped k_mac_head  = k_mac_head ^ XOR_KEY
 *   [64:96) expect_mac_head     HMAC-SHA256(k_mac_head, head 密文)
 *   [96:100) head_ro_addr       .ncxhr 链接期虚拟地址
 *   [100:104) head_ro_size      该段字节数
 *   [104:112) frag[4]           XOR_KEY 碎片
 * 锁箱 lock_head() / 开箱 ncg_stub_recover() / 段本体在 boot.c */
#define NC_STUB_SIZE        112   /* [104:112) 为碎片区，见 NC_OFF_FRAGS */
/* 碎片区：XOR_KEY 的 4 个 uint16，构建期随机。放 slot 而非 .data ——
 * 破解复盘实测"objdump 读 .data + 反汇编 5 分钟重组出 XOR_KEY"。
 * 详见 踩坑记录 K-02 */
#define NC_OFF_FRAGS        104   /* [104:112) 4×uint16 碎片（随机）*/
#define NC_OFF_CODE_ADDR    36   /* 代码自绑定 CRC 区间起始*/
#define NC_OFF_CODE_LEN     40   /* 区间长度（字节）*/
#define NC_OFF_K_MAC_HEAD   48   /* wrapped k_mac_head 起点*/
#define NC_OFF_EXPMAC_HEAD  64   /* expect_mac_head 起点*/
#define NC_OFF_HEADRO_ADDR  96   /* .ncxhr 段链接期虚拟地址*/
#define NC_OFF_HEADRO_SIZE 100   /* .ncxhr 段字节数*/

/* ═══ 三点五、T4 槽段加密 ═══════════════════════════════════════════
 * boot_key 由 .text 派生，加密两个槽段（原为明文，dd 读 8 字节即得 XOR_KEY）。
 * 范围：.ncks[8:112) 与 .nck[0:96) —— magic 区豁免，"是否已锁"的判定在解密前。
 * ⚠️ 循环依赖已解：.text 地址由 ncg_find_section 直接读 ELF 头（段表从不加密）。
 * ⚠️ 区间必须无重定位，T31 断言。攻击者仍可反汇编 stub 复现派生 ——
 *    提高的是"发现与理解"成本，不是数学上的不可绕过。 */
#define NC_BOOT_SPAN        0x4000   /* CRC 区间长度上限（16KB） */
#define NC_BOOT_SPAN_MIN    0x0800   /* 下限：太短则 boot_key 强度不足 */
#define NC_BOOT_SALT_INIT \
    { 0x6e, 0x63, 0x1f, 0x2b, 0x7a, 0x44, 0x91, 0xd8, \
      0x03, 0x5c, 0xe6, 0x18, 0xaf, 0x72, 0x39, 0xc4 }  /* "nc" + 16B 区分值 */
/* HKDF info（boot 域）。⚠️ 只作 so-section-lock.py 的抽取源，C 代码不得引用
 * —— 一旦被 .c 引用，字符串就明文进 .rodata（实测 0xcd96）。C 侧走
 * ncg_label_boot() 从密文表还原。改本值 = 所有历史产物失效。 */
#define NC_BOOT_INFO        "nc-boot-v1"
#define NC_OFF_FRAGS_ENC    8   /* .ncks 加密区间起点（magic 之后）*/

/* ═══ 四、magic 种子（8 字节）═══════════════════════════════════════
 * slot 前 8 字节 == seed ⇒ 已锁箱。锁箱器落盘就是 seed 本身，逐字节比。
 * ⚠️ 真实收益仅一条：strings 搜不到字面量。碎片密钥不参与 magic 比较。 */
#define NC_SEED_SLOT_INIT \
    { 0x30, 0x72, 0xEE, 0x48, 0x91, 0xDE, 0x04, 0xB5 }
#define NC_SEED_STUB_INIT \
    { 0x30, 0x72, 0xF6, 0x59, 0x9D, 0xD0, 0x07, 0xBD }

/* ═══ 五、XOR_KEY 碎片表 ════════════════════════════════════════════
 * 逻辑字节 i 取哪个碎片；i<4 取低位、i>=4 取高位（T20 与 Python 对拍）。
 * 碎片常量本体刻意不在这里 —— 集中成表等于重新聚成可一次性读走的常量。 */
#define NC_XOR_FRAG_INIT \
    { 1, 0, 2, 3, 0, 1, 3, 2 }

/* ═══ 六、编译期自检 ════════════════════════════════════════════════
 * 挡"偏移重叠/越界"手误 —— 88→104 扩容时新字段与 MAC 字段重叠会**静默**
 * 破坏校验，编译期不报。 */
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
