#!/usr/bin/env python3
"""gen-label-tables.py — 生成 nc_guard_key.c 的四张 HKDF label 表

## 为什么需要这个脚本

`nc_guard_key.c` 里的四张 `ncg_label_enc_*` 表是**手工放进源码的常量**，
一旦 SALT 或编码方案变了，必须重算。没有脚本时只能靠人算，而算错的表现是
"真机上 .ncx 解出乱码" —— 症状完全不指向 label。

本脚本是那四张表的**可复核生成器**：跑一遍，把输出贴回 `nc_guard_key.c`。

## 编码方案（2026-11-08）

    label 明文 "nc-so-v1"
      ↓ 逐字节 ^ 基值（每张表不同：0x5A / 0xA7 / 0x3C / 0xE1）
    真实字节
      ↓ 与噪声交错（偶数位=真实字节，奇数位=噪声）
    存储形态（长度 = 2n）

    噪声(i, kidx) = SALT[(i*5 + kidx*3) % 16] ^ 0x9E

为什么交错：只换基值时四张表仍紧邻排布（间隔 8/12/10 字节，总跨度 40 字节），
攻击者能看到"40 字节常量块"再逐字节试 XOR。交错后真实字节被噪声隔开。

## 基值从哪来

    基值[i] = SALT[idx[i]] ^ perturb[i]
    idx     = [0, 4, 8, 12]
    perturb = [0x34, 0xDD, 0x3F, 0x4E]

## 用法

    ./scripts/so-guard/gen-label-tables.py          # 打印 C 代码
    ./scripts/so-guard/gen-label-tables.py --check  # 只校验，与源码对拍

退出码：0 = 一致；1 = 不一致（--check 模式）
"""
import sys
import re
import pathlib

# ── 契约（改这里必须同步 nc_guard_key.c 的 ncg_label_key）──
SALT = [0x6e, 0x63, 0x1f, 0x2b, 0x7a, 0x44, 0x91, 0xd8,
        0x03, 0x5c, 0xe6, 0x18, 0xaf, 0x72, 0x39, 0xc4]
PERTURB = [0x34, 0xDD, 0x3F, 0x4E, 0x7B, 0x81, 0x2C]
SALT_IDX = [0, 4, 8, 12, 2, 6, 10]
NOISE_XOR = 0x9E

LABELS = [
    ("so",   b"nc-so-v1",       "ncg_label_enc_so",   "NCGL_SO"),
    ("mac",  b"nc-so-mac-v1",   "ncg_label_enc_mac",  "NCGL_MAC"),
    ("so_r", b"nc-so-r-v1",     "ncg_label_enc_so_r", "NCGL_SO_R"),
    ("boot", b"nc-boot-v1",     "ncg_label_enc_boot", "NCGL_BOOT"),
    # 2026-11-13：第 5 张表，给 .nct（消费方 VMP 数据段）用。
    # label 明文 "nc-insn-v1" 与 so-section-lock.py 的 derive_app_keys
    # 里 'nc-insn-v1' → 'insn' 域【必须逐字节一致】。
    # 基值 0x64（= SALT[2] 0x1f ^ 0x7B）刻意与前四个都不同。
    ("insn", b"nc-insn-v1",     "ncg_label_enc_insn", "NCGL_INSN"),
    # 2026-11-13：.ncq（VM 字节码段）用。与 so-section-lock.py 的
    # derive_app_keys 里 ('nc-warm-v1','warm') 必须逐字节一致。
    ("bc",   b"nc-warm-v1",     "ncg_label_enc_bc",   "NCGL_BC"),
    # 2026-11-13：.ncv（消费方第二套 VM 字节码段）用。
    # 与 nox 第一套的 .ncq（nc-warm-v1）必须【不同钥匙】——
    # 两套链接进同一个 so，同钥匙等于 keystream 复用。
    ("bc2",  b"nc-dex-v1",      "ncg_label_enc_bc2",  "NCGL_BC2"),
]


def base_keys():
    """四个基值 = SALT 对应字节 ^ 私有扰动量"""
    return [SALT[i] ^ p for i, p in zip(SALT_IDX, PERTURB)]


def noise(i, kidx):
    return (SALT[(i * 5 + kidx * 3) % 16] ^ NOISE_XOR) & 0xFF


def encode(plain, key, kidx):
    """label → 交错存储形态（2n 字节）"""
    out = []
    for i, b in enumerate(plain):
        out.append(b ^ key)
        out.append(noise(i, kidx))
    return out


def gen_c():
    keys = base_keys()
    lines = []
    lines.append("/* 基值: " + " / ".join("0x%02X" % k for k in keys) + " */")
    for kidx, (dom, plain, cname, lenmacro) in enumerate(LABELS):
        enc = encode(plain, keys[kidx], kidx)
        lines.append("static const uint8_t %s[%s * 2] = {" % (cname, lenmacro))
        for i in range(0, len(enc), 8):
            chunk = enc[i:i + 8]
            lines.append("    " + ", ".join("0x%02x" % b for b in chunk) + ",")
        lines.append("};")
    return "\n".join(lines)


def check(src_path):
    """与源码里的表对拍"""
    text = pathlib.Path(src_path).read_text(encoding="utf-8")
    keys = base_keys()
    ok = True
    for kidx, (dom, plain, cname, _) in enumerate(LABELS):
        want = encode(plain, keys[kidx], kidx)
        m = re.search(re.escape(cname) + r"\[[^\]]*\]\s*=\s*\{(.*?)\};",
                      text, re.S)
        if not m:
            print("✗ %s: 源码里找不到" % cname)
            ok = False
            continue
        got = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))]
        if got != want:
            print("✗ %s: 不一致" % cname)
            print("    期望 %s" % " ".join("%02x" % b for b in want))
            print("    实际 %s" % " ".join("%02x" % b for b in got))
            ok = False
        else:
            # 反向验证：解出来必须等于原 label
            dec = bytes(got[i * 2] ^ keys[kidx] for i in range(len(plain)))
            if dec != plain:
                print("✗ %s: 解码结果 %r != %r" % (cname, dec, plain))
                ok = False
            else:
                print("✓ %s → %r" % (cname, dec.decode()))
    return ok


def main():
    if "--check" in sys.argv:
        src = pathlib.Path(__file__).parent / "nc_guard_key.c"
        sys.exit(0 if check(src) else 1)

    keys = base_keys()
    print("/* ── 由 gen-label-tables.py 生成，勿手改 ──")
    print(" * 基值: " + " / ".join("0x%02X" % k for k in keys))
    print(" * 明文: " + " / ".join(p.decode() for _, p, _, _ in LABELS))
    print(" */")
    print(gen_c())


if __name__ == "__main__":
    main()
