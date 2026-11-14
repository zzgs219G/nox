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
    # U1 取自身路径与基址
    "U1 resolve_self 进入",
    "U1 OK so_path",
    "U1 FAIL resolve_self（拿不到 so 路径与基址）",
    # U2 找 .ncx
    "U2 找 .ncx 段",
    "U2 OK .ncx 大小",
    "U2 FAIL 找不到段",
    # U3 找 .nck
    "U3 找 .nck 密钥槽",
    "U3 OK .nck 大小",
    "U3 FAIL 找不到段",
    # U4 .ncx 非空
    "U4 检查 .ncx 大小非零",
    "U4 OK .ncx 非空",
    "U4 FAIL .ncx 段大小为 0",
    # U5 .ncx 可分配
    "U5 检查 .ncx 可分配",
    "U5 OK .ncx 可分配",
    "U5 FAIL .ncx 不可分配(flags)",
    # U6 打开 so
    "U6 打开 so 文件",
    "U6 OK 已打开 fd",
    "U6 FAIL open 失败",
    # U7 读密钥槽
    "U7 读 .nck 密钥槽",
    "U7 OK 读到字节数",
    "U7 FAIL pread 字节数",
    # U8 锁箱判定
    "U8 判定锁箱状态",
    "U8 锁箱状态(1=已锁 0=未锁)",
    # U9 派生 boot_key
    "U9 派生 boot_key 进入",
    "U9 OK boot_key 已派生",
    "U9 FAIL boot_key 派生失败（fail-closed -12）",
    # U10 magic 校验
    "U10 未锁箱（magic 不匹配）→ 直接返回 0",
    "U10 已确认锁箱，进入解锁流程",
    # U11 master 检查
    "U11 master 全零（未锁箱）→ 返回 0",
    "U11 master 非零，继续派生",
    # U12 派生 k_so
    "U12 派生 k_so 进入（读证书+包名）",
    "U12 OK k_so 已派生",
    "U12 FAIL k_so 派生失败 —— 证书/包名不匹配（fail-closed -12）",
    # U13 段数
    "U13 待校验段数",
    # U14 MAC
    "U14 OK 段完整性校验通过（MAC 一致）",
    "U14 FAIL 段完整性校验 rc",
    # U15 逐段解密
    "U15 逐段解密进入",
    "U15 OK 所有段已解密",
    "U15 FAIL 逐段解密 rc",
    # U16 完成
    "U16 解锁完成（ncg_unlocked=1）",
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


def main() -> None:
    print("/* ── 由 gen-trace.py 生成的追踪文案密文（勿手改）───────────────")
    print(" * 重跑：python3 scripts/so-guard/gen-trace.py")
    print(" * 改动 STAGES 后必须重跑，否则运行期解出乱码。 */")
    print()
    print("static const uint8_t ncg_trace_key[16] = {")
    print("    " + ", ".join("0x%02X" % b for b in KEY[:8]) + ",")
    print("    " + ", ".join("0x%02X" % b for b in KEY[8:]) + ",")
    print("};")
    print()
    print("/* msg_id → 密文。下标 i 对应 NCG_TR_* 枚举的第 i 项。 */")
    print("static const struct { const uint8_t *blob; uint8_t len; } "
          "ncg_trace_tab[] = {")
    for i, s in enumerate(STAGES):
        mid = MSG_ID_BASE + i
        ct = encrypt(mid, s.encode("utf-8"))
        body = ", ".join("0x%02X" % b for b in ct)
        print("    /* [%d] msg_id=0x%02X  %s */" % (i, mid, s))
        print("    { (const uint8_t[]){%s}, %d }," % (body, len(ct)))
    print("};")
    print()
    print("#define NCG_TRACE_COUNT %d" % len(STAGES))


if __name__ == "__main__":
    main()
