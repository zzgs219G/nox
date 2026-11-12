#!/usr/bin/env python3
"""test-k-nct-parity.py — C 侧 ncg_derive_k_nct 与 Python 侧 insn 域对拍

## 为什么需要这个测试

`.nct`（消费方 VMP 数据段）的密钥 `k_nct` 在两侧各算一次：

    Python（构建期）：so-section-lock.py 的 derive_app_keys()['insn']
    C     （运行期）：nc_guard_key.c 的 ncg_derive_k_nct()

两侧必须【逐字节一致】。不一致的症状是"解锁后解开的是乱码"，
而乱码不会报错——解释器把密文当 opcode，跳过无效地址，最终真机
SIGILL 且崩溃点落在 `.ncx` 段内，完全不指向 `.nct`。

历史教训（2026-11-12 实测）：`NCGL_INSN` 写成 11，而 `"nc-insn-v1"`
实际长度 10。C 侧多读一个字节（读到噪声位）→ 还原出
`"nc-insn-v1\\x??"` → HKDF info 错 → k_nct 错 → 真机 SIGILL。
**Python 侧能解只证明文件加密正确，不证明 C 侧能解。**

## 做法

编译一个只 link `nc_guard_key.c` 的小程序，把 C 算出的 k_nct 打印出来，
与 Python 侧的 derive_app_keys()['insn'] 对拍。

    python3 scripts/so-guard/test-k-nct-parity.py

判据：任一侧不一致 → 退出码 1。
"""
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
KEY_C = HERE / "nc_guard_key.c"
LOCK_PY = HERE / "so-section-lock.py"


def py_side(master: bytes, cert_der: bytes, pkg: str) -> bytes:
    """直接复用锁箱器的实现，避免"两处各写一份"——那正是本次的教训。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("slock", LOCK_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    cert_sha = hashlib.sha256(cert_der).digest()
    return mod.derive_app_keys(master, cert_sha, pkg)["insn"]


def c_side(master: bytes, cert_der: bytes, pkg: str, cc: str) -> bytes:
    """编译 nc_guard_key.c 并调用 ncg_derive_k_nct_from_der。"""
    src = r'''
#include <stdio.h>
#include <string.h>
#include "nc_guard_key.h"
int main(int argc, char **argv) {
    (void)argc;
    unsigned char master[32];
    static unsigned char der[4096];
    unsigned char out[16];
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    if (fread(master, 1, 32, f) != 32) return 3;
    fclose(f);
    f = fopen(argv[2], "rb");
    if (!f) return 4;
    size_t n = fread(der, 1, sizeof der, f);
    fclose(f);
    if (ncg_derive_k_nct_from_der(master, der, n, argv[3], out) != 0) return 5;
    for (int i = 0; i < 16; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / "drv.c").write_text(src)
        (td / "master.bin").write_bytes(master)
        (td / "cert.der").write_bytes(cert_der)
        exe = td / "drv"
        r = subprocess.run(
            [cc, "-O1", "-I", str(HERE), "-o", str(exe),
             str(td / "drv.c"), str(KEY_C)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("✗ C 侧编译失败：\n%s" % r.stderr[:2000])
            sys.exit(1)
        r = subprocess.run(
            [str(exe), str(td / "master.bin"), str(td / "cert.der"), pkg],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("✗ C 侧调用失败 rc=%d\n%s" % (r.returncode, r.stderr[:1000]))
            sys.exit(1)
        return bytes.fromhex(r.stdout.strip())


def main() -> int:
    cc = os.environ.get("CC", "cc")
    # 固定输入（不随机）——失败时能逐字节复现
    master = bytes(range(32))
    cert_der = bytes((i * 7 + 3) & 0xFF for i in range(512))
    cases = [
        ("com.nox.fixture", "常规包名"),
        ("com.example.app", "另一包名（验证 pkg 参与 HKDF info）"),
        ("a", "最短包名"),
    ]
    bad = 0
    for pkg, why in cases:
        p = py_side(master, cert_der, pkg)
        c = c_side(master, cert_der, pkg, cc)
        if p == c:
            print("✓ k_nct(%s) = %s   [%s]" % (pkg, p.hex(), why))
        else:
            print("✗ k_nct(%s) 两侧不一致   [%s]" % (pkg, why))
            print("    Python: %s" % p.hex())
            print("    C     : %s" % c.hex())
            bad += 1

    # 反向验证：k_nct 必须与其它四个域都不同（label 复用 = 两条链互相印证）
    import importlib.util
    spec = importlib.util.spec_from_file_location("slock", LOCK_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    cert_sha = hashlib.sha256(cert_der).digest()
    keys = mod.derive_app_keys(master, cert_sha, "com.nox.fixture")
    if len(set(keys.values())) != len(keys):
        print("✗ 域密钥出现重复：%s" % keys)
        bad += 1
    else:
        print("✓ 六个域密钥互不相同（insn 与 so/so_r/mac/dex/warm 全不同）")

    print()
    if bad:
        print("结果: %d 项失败" % bad)
        return 1
    print("结果: 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
