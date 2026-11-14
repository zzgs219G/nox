#!/usr/bin/env python3
"""gen-trace.py — 生成 nc_guard_trace.c 的阶段追踪文案密文表

## 为什么需要这张表

阶段追踪（`ncg_trace("U9 OK boot_key")` 之类）把 26 条中文明文写进了
`.rodata`，`strings` 一条命令就能拿到完整解锁流程：

    U1 resolve_self → U2 找 .ncx → U3 找 .nck 密钥槽 →
    U6 open(so_path) → U7 pread(.nck) → U9 boot_key →
    U11 master → U12 k_so → U14 MAC → U15 解密

这等于把「解锁分几步、每步干什么、密钥链有几层」的说明书直接送给
攻击者。项目文档里早有这条教训（变更历史 2026-10-19 P2 三项）：

    「字符串字面量永远进 .rodata，不会跟着函数进自定义段
      —— nc_guard_boot.c 的函数在加密段，但它的路径字面量锁箱后
         仍在 .rodata 可搜」

我加追踪时没意识到这一点，于是重犯了同一个错误。

## 做法：与 nc_guard_paths.c 完全同构

    · 明文只活在【本文件的 STAGES 列表】里（人/AI 可读）
    · so 里只有密文数组；strings 搜不到「boot_key」「master」等路标词
    · 运行期 ncg_trace_s(id) 用同一 key 解回来再写日志

密钥流算法、key、域分离方式都与 gen-paths.py 一致（同一个 ncg_path_ctr_xor），
只是换了一张表、换了一组 msg_id 空间（从 0x40 起，避免与路径表撞号）。

## 强度边界（如实）

这是【混淆】不是【加密】：key 与算法都在源码里，反汇编 ncg_path_ctr_xor
就能还原。买到的是「strings 扫不到」+「跨包 diff 失效」。

⚠️ 密钥每次构建可以随机化（见 KEY 的注释），但当前沿用固定 key ——
   与 nc_guard_paths.c 保持一致，避免「两张表强度不同」的误解。

## 用法

    python3 scripts/so-guard/gen-trace.py          # 打印 C 数组，贴回源文件

改动 STAGES 后必须重跑，否则解出乱码。
"""
import hashlib
import struct

# 与 nc_guard_paths.c 同一把 key（同一设施、同一威胁模型）。
# 若要改成每次构建随机，两边必须一起改 —— 只改一边会让另一张表解不开。
KEY = bytes([0x4F, 0x1C, 0x8A, 0x73, 0xD5, 0x26, 0xE9, 0x0B,
             0x37, 0xC4, 0x6F, 0x92, 0xA1, 0x58, 0xED, 0x30])

# msg_id 从 0x40 起：与路径表（0/1）分开，避免域冲突。
MSG_ID_BASE = 0x40

# ── 阶段文案表（唯一真相源）──────────────────────────────────────────
# 顺序即 msg_id 顺序：索引 i 对应 MSG_ID_BASE + i。
# 改这里的任何一条都要重跑本脚本并更新 nc_guard_trace.h 的枚举。
#
# 设计约束：
#   · 每条必须能独立看懂（崩溃时只看最后一行）
#   · 进入/OK/FAIL 三种前缀固定，便于 grep 与脚本解析
#   · 不带参数的值（如 so_path）由调用方另附，不写进文案
STAGES = [
    ("U1_ENTER", "U1 resolve_self 进入"),
    ("U1_OK_PATH", "U1 OK so_path"),
    ("U1_FAIL", "U1 FAIL resolve_self（拿不到 so 路径与基址）"),
    ("U2_ENTER", "U2 找 .ncx 段"),
    ("U2_OK_SIZE", "U2 OK .ncx 大小"),
    ("U2_FAIL", "U2 FAIL 找不到段"),
    ("U3_ENTER", "U3 找 .nck 密钥槽"),
    ("U3_OK_SIZE", "U3 OK .nck 大小"),
    ("U3_FAIL", "U3 FAIL 找不到段"),
    ("U4_ENTER", "U4 检查 .ncx 大小非零"),
    ("U4_OK", "U4 OK .ncx 非空"),
    ("U4_FAIL", "U4 FAIL .ncx 段大小为 0"),
    ("U5_ENTER", "U5 检查 .ncx 可分配"),
    ("U5_OK", "U5 OK .ncx 可分配"),
    ("U5_FAIL", "U5 FAIL .ncx 不可分配(flags)"),
    ("U6_ENTER", "U6 打开 so 文件"),
    ("U6_OK_FD", "U6 OK 已打开 fd"),
    ("U6_FAIL", "U6 FAIL open 失败"),
    ("U7_ENTER", "U7 读 .nck 密钥槽"),
    ("U7_OK_BYTES", "U7 OK 读到字节数"),
    ("U7_FAIL", "U7 FAIL pread 字节数"),
    ("U8_ENTER", "U8 判定锁箱状态"),
    ("U8_STATE", "U8 锁箱状态(1=已锁 0=未锁)"),
    ("U9_ENTER", "U9 派生 boot_key 进入"),
    ("U9_OK_BK", "U9 OK boot_key 已派生"),
    ("U9_FAIL", "U9 FAIL boot_key 派生失败（fail-closed -12）"),
    ("U10_UNLOCKED", "U10 未锁箱（magic 不匹配）→ 直接返回 0"),
    ("U10_LOCKED", "U10 已确认锁箱，进入解锁流程"),
    ("U11_ZERO", "U11 master 全零（未锁箱）→ 返回 0"),
    ("U11_NONZERO", "U11 master 非零，继续派生"),
    ("U12_ENTER", "U12 派生 k_so 进入（读证书+包名）"),
    ("U12_OK_KSO", "U12 OK k_so 已派生"),
    ("U12_FAIL", "U12 FAIL k_so 派生失败 —— 证书/包名不匹配（fail-closed -12）"),
    ("U13_NSEG", "U13 待校验段数"),
    ("U14_OK", "U14 OK 段完整性校验通过（MAC 一致）"),
    ("U14_FAIL", "U14 FAIL 段完整性校验 rc"),
    ("U15_ENTER", "U15 逐段解密进入"),
    ("U15_OK", "U15 OK 所有段已解密"),
    ("U15_FAIL", "U15 FAIL 逐段解密 rc"),
    ("U16_DONE", "U16 解锁完成（ncg_unlocked=1）"),
]


def ks_for(msg_id: int, blk: int) -> bytes:
    """密钥流：SHA256(key || msg_id || counter)，与 gen-paths.py 同算法。

    msg 布局（24 字节，与 nc_guard_paths.c 的 ncg_path_ctr_xor 逐字节一致）：
        [0:16]  key
        [16:20] 0,0,0,msg_id      ← msg_id 在低字节
        [20:24] counter_be32
    因此每 (key, msg_id, counter) 产生 32 字节独立密钥流，
    不同消息永不共享密钥流（避免 two-time pad）。
    """
    msg = bytearray(24)
    msg[0:16] = KEY
    msg[19] = msg_id
    struct.pack_into(">I", msg, 20, blk)
    return hashlib.sha256(bytes(msg)).digest()


def encrypt(msg_id: int, plain: bytes) -> bytes:
    out = bytearray(len(plain))
    blk = 0
    off = 0
    while off < len(plain):
        ks = ks_for(msg_id, blk)
        for i in range(32):
            if off + i >= len(plain):
                break
            out[off + i] = plain[off + i] ^ ks[i]
        off += 32
        blk += 1
    return bytes(out)



# ── 报告正文文案表 ───────────────────────────────────────────────
REPORT_STAGES = [
    ("TITLE", "# ncguard 自检 v3\n"),
    ("LEGEND", "\n> 符号：✅ 通过 · ❌ 有问题 · ⚠️ 无法判断（样本不足）· — 段不存在\n"),
    ("UNLOCK_OK", "\n**解锁**：✅ %d 段全部解密\n"),
    ("UNLOCK_FAIL", "\n**解锁**：❌ 失败 rc=%d（%d 段）\n"),
    ("FAIL_MAC", "\n> ❌ **MAC 校验失败** —— 段序或段内容与锁箱侧不一致\n"),
    ("FAIL_KSO", "\n> ❌ **密钥派生失败** —— 证书/包名不匹配，或段序错导致钥匙错配\n"),
    ("FAIL_MPROT", "\n> ❌ **mprotect 失败** —— 页权限/同页可写段\n"),
    ("FAIL_SLOT", "\n> ❌ **密钥槽缺失** —— 找不到 `.nck`\n"),
    ("FAIL_NOMEM", "\n> ❌ **内存不足** —— malloc 失败\n"),
    ("ENT_HDR", "\n> **熵(文件)** = 逆向者拿到的磁盘状态（8.0 = 密文 / 6.x = 明文）；**熵(内存)** = 解锁后的运行状态。\n"),
    ("ENT_HINT", "> 两列对照才有意义：文件密 + 内存明 = 锁箱生效；两列都明 = 该段本就不加密。\n"),
    ("SEG_HDR", "\n| 段名 | 大小 | 权限 | 熵(文件) | 熵(内存) | VMP | 判定 |\n"),
    ("SEG_SEP", "|:---|--:|:---|--:|--:|:-:|:---|\n"),
    ("SEG_ABSENT", "| `%s` | - | - | - | - | %s | - 段不存在 |\n"),
    ("SEG_TINY", "| `%s` | %s | %s | %s | %s | %s | %s（小段，按内容判） |\n"),
    ("SEG_ROW", "| `%s` | %s | %s | %s | %s | %s | %s |\n"),
    ("VMP_HDR", "\n## VMP\n\n"),
    ("VMP_N", "**套数**：%d"),
    ("VMP_OFF", "（本次构建未开 VMP）\n"),
    ("VMP_TBL", "\n| 套 | 解释器 | 字节码 | 数据表 |\n"),
    ("VMP_SEP", "|:---|:---|:---|:---|\n"),
    ("VMP1", "| 1. nox解密链 | `%s` %llu B %s | `%s` %s | `%s` %s |\n"),
    ("VMP1_OFF", "| 1. nox解密链 | — 未开 | — | — |\n"),
    ("VMP2", "| 2. 消费方 | `%s` %llu B %s | `%s` %s | `%s` %s |\n"),
    ("VMP2_OFF", "| 2. 消费方 | — 未开 | — | — |\n"),
    ("VMP_NOEXEC", "❌ 不可执行"),
    ("SZ_HDR", "\n## 体积归因\n\n| 组 / 段 | 大小 |\n|:---|--:|\n"),
    ("SZ_NOX", "nox 设施"),
    ("SZ_VMP", "VMP 载荷"),
    ("SZ_BIZ", "业务载荷"),
    ("SZ_BASE", "基础代码"),
    ("SZ_TOTAL", "已统计"),
    ("SZ_NOTE", "  （合计小于 so 总大小属正常：ELF 头/符号表/dynamic 等未纳入）\n"),
    ("CONCL_HDR", "\n## 结论\n\n"),
    ("CONCL_OK", "✅ **全部正常**"),
    ("CONCL_UNK", "（其中 %d 项标 ! 是样本不足无法判断熵，不影响功能）"),
    ("CONCL_BAD", "❌ **有 %d 项异常**，见上方 ❌ 标记\n"),
    ("CONCL_BAD2", "\n另有 %d 项标 ! 无法判断（样本不足），不算异常\n"),
    ("END", "\n---\n"),
    ("V_READFAIL", "— 无法读取内存"),
    ("V_DECRYPTED", "✅ 已解密"),
    ("V_STILL_ENC", "❌ 仍是密文"),
    ("V_PLAIN_DATA", "✅ 明文数据（本就不加密）"),
    ("V_HIGH_ENT", "⚠️ 高熵异常"),
    ("V_CIPHER", "✅ 密文"),
    ("V_NOT_ENC", "❌ 未加密"),
    ("V_ENC_LOCKED", "密文（未解锁）"),
    ("V_PLAIN_INHERENT", "明文（本就不加密）"),
    ("V_DISK_PLAIN", "⚠️ 磁盘上就不是密文（锁箱可能没生效）"),
    ("T_EMPTY", "— 空段"),
    ("T_UNREADABLE", "— 无法读取"),
    ("T_PLAIN", "✅ 明文"),
    ("T_CIPHER", "🔒 密文"),
    ("ROLE_CODE", "业务代码+壳"),
    ("ROLE_VMP2", "第二套解释器"),
    ("ROLE_BC2", "第二套字节码"),
    ("ROLE_VMP1", "第一套解释器"),
    ("ROLE_BC1", "第一套字节码"),
    ("ROLE_TBL1", "第一套数据表"),
    ("ROLE_CONST", "签名表"),
    ("ROLE_HEAD", "解锁器"),
    ("ROLE_MASTER", "master"),
]

REPORT_MSG_BASE = 0x80


def emit_table(tab_name: str, eprefix: str, items: list, base: int) -> None:
    """输出【枚举 + 密文表】。

    枚举与表由同一个 items 列表生成，索引天然一一对应 ——
    调用方只写名字（NCG_TR_U9_OK_BK / RPT_UNLOCK_OK），不写数字，
    增删条目不会错位。

    ⚠️ 密文旁边不留明文注释：注释等于答案，strings 照样能读到。
       要查某条文案是什么，看本文件的列表。
    """
    ename = eprefix.lower()
    print("/* %s 文案 ID（顺序与 %s 表一致，同一列表生成）*/"
          % (eprefix, tab_name))
    print("typedef enum {")
    for i, (name, _) in enumerate(items):
        print("    %s_%s%s," % (eprefix, name, " = 0" if i == 0 else ""))
    print("} %s;" % ename)
    print()
    print("static const struct { const uint8_t *blob; uint8_t len; } "
          "%s[] = {" % tab_name)
    for i, (_, text) in enumerate(items):
        ct = encrypt(base + i, text.encode("utf-8"))
        body = ", ".join("0x%02X" % b for b in ct)
        print("    { (const uint8_t[]){%s}, %d }," % (body, len(ct)))
    print("};")
    print()
    print("#define %s_COUNT ((int)(sizeof(%s) / sizeof(%s[0])))"
          % (tab_name.upper(), tab_name, tab_name))
    print()


def main() -> None:
    print("/* ── 由 gen-trace.py 生成（勿手改）─────────────────────────────")
    print(" * 重跑：python3 scripts/so-guard/gen-trace.py")
    print(" * 改动本脚本的 STAGES / REPORT_STAGES 后必须重跑。")
    print(" *")
    print(" * ⚠️ 枚举名与密文表由同一个列表生成，天然一一对应 ——")
    print(" *    调用点只写名字（NCG_TR_U9_OK_BK），不写数字，")
    print(" *    以后增删条目也不会错位。这是本轮返工的直接原因：")
    print(" *    上一版用裸数字索引，加一条文案就让后面全部偏移 1，")
    print(" *    测试从 52 通过掉到 39 失败。 */")
    print()
    print("static const uint8_t ncg_trace_key[16] = {")
    print("    " + ", ".join("0x%02X" % b for b in KEY[:8]) + ",")
    print("    " + ", ".join("0x%02X" % b for b in KEY[8:]) + ",")
    print("};")
    print()
    print("/* 阶段追踪文案（msg_id 域 0x40）*/")
    emit_table("ncg_trace_tab", "NCG_TR", STAGES, MSG_ID_BASE)
    print("/* 报告正文文案（msg_id 域 0x80）*/")
    emit_table("ncg_report_tab", "RPT", REPORT_STAGES, REPORT_MSG_BASE)


if __name__ == "__main__":
    main()
