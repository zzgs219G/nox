#!/usr/bin/env python3
"""check-vmp-eligibility.py — 预检某函数能否被 Amice VMP 接受（2026-11-06）

## 为什么需要它

Amice 的 vm_virtualize 在改写函数前会检查它的所有 use
（crates/amice/src/aotu/vm_virtualize/mod.rs:1067 的
has_unsupported_function_uses）：

    除了「直接调用」和「@llvm.global.annotations」，
    其它任何对函数地址的引用都判为 "has non-call address uses"
    → 静默跳过该函数（只有 RUST_LOG=amice=debug 才看得到日志）

最典型的踩雷写法就是取自身地址传出去：

    dladdr((const void *)&my_func, &info)      ← 会被跳过

2026-11-06 实测：ncg_stub_recover 原先这么写，拆文件上 VMP 时必然被跳过。
改法是把取地址移到调用方（不虚拟化的函数），用参数传入。

## 用法

    ./scripts/check-vmp-eligibility.py <源文件.c> <函数名...>

    # 例：上 VMP 前预检
    ./scripts/check-vmp-eligibility.py scripts/so-guard/nc_guard_crypto.c \\
        ncg_boot_key ncguard_stub_recover

退出码：0 = 全部可虚拟化；1 = 有函数会被跳过；2 = 用法/环境错误

## ⚠️ 这只是必要条件，不是充分条件

本脚本只查「自身地址被非调用用途引用」这一条（最常见、最容易犯）。
VMPDesign_zh_CN.md:1259 还列了一长串会跳过的构造（varargs、naked、
strictfp、coroutine、非常规向量、异常处理、inline asm、……），这里没有
逐一检查。真正的判定仍要看 Amice 自己的 RUST_LOG=amice=debug 输出，
以及最终产物上的 evidence：scripts/check-obf.sh 的 VM 子段数。

## 实现说明

看的是 clang 生成的 LLVM IR，不是源码 —— 因为 Amice 判断的是 IR 层的
use list。源码里有 `&f` 不代表 IR 里还剩（可能被优化掉），源码里没有
`&f` 也可能因为宏展开出现。以 IR 为准。

匹配用 `@name(?![.\\w])` 而不是 `@name`，是为了排除编译器给函数内 static
变量加的前缀：`@ncguard_stub_recover.recovered` 中的 recovered 是**变量**，
不是函数地址引用，不构成跳过条件（这一步曾误报过）。
"""
import re
import subprocess
import sys
import tempfile
import os


def emit_ir(src_path, inc_dir):
    """用 clang 生成 LLVM IR 文本，返回字符串。失败返回 None。"""
    fd, out = tempfile.mkstemp(suffix='.ll')
    os.close(fd)
    cmd = ['clang', '-S', '-emit-llvm', '-Oz', '-DNC_GUARD_SECTIONED',
           '-I', inc_dir, src_path, '-o', out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write('✗ clang 生成 IR 失败:\n%s\n' % r.stderr[:800])
        if os.path.exists(out):
            os.unlink(out)
        return None
    try:
        with open(out) as f:
            return f.read()
    finally:
        os.unlink(out)


def function_body(ll, name):
    m = re.search(r'^define[^\n]*@' + re.escape(name) + r'\((.*?)\n\}',
                  ll, re.S | re.M)
    return m.group(0) if m else None


def non_call_self_uses(body, name, ll=None):
    """返回对自身地址的非调用引用（每行一条）。

    ⚠️ 2026-11-10 修（盲区）：原实现只扫函数体（body），完全看不到
    【模块级全局变量】里的地址引用。实测踩到：
        @tbl = global [1 x %struct] [{ ptr @.str, ptr @.str.1,
                                       ptr @Java_..._onCreate }]
    这是 dex2c --dynamic-register 生成的 JNINativeMethod 表 —— 最典型的
    non-call address use，Amice 必然跳过，而本脚本却报 ✓ 可虚拟化（假绿）。
    现已改为扫整份 IR。

    同时按 Amice 的真实判据（vm_virtualize/mod.rs:1067
    has_unsupported_function_uses）实现豁免：
      · 直接调用（call ... @name）            → 允许
      · @llvm.global.annotations 表里的引用   → 允许（annotate 配置用）
      · 其余一律算 offender，包括 @llvm.used（clang 因 used/retain 属性生成）
    """
    pat = re.compile(r'@' + re.escape(name) + r'(?![.\w])')
    call_pat = re.compile(r'\bcall\b[^@]*@' + re.escape(name) + r'(?![.\w])')
    # Amice 只豁免 global.annotations；llvm.used 也算违规（实测确认）
    ann_ok = re.compile(r'@llvm\.global\.annotations')
    scan = ll.splitlines() if ll is not None else body.splitlines()
    offenders = []
    for line in scan:
        s = line.strip()
        if s.startswith('define') and ('@' + name) in s:
            continue                             # 函数自身定义行
        if not pat.search(s):
            continue
        if call_pat.search(s):
            continue                             # 直接调用：允许
        if ann_ok.search(s):
            continue                             # annotations 表：允许
        offenders.append(s)
    return offenders


def main(argv):
    if len(argv) < 3:
        sys.stderr.write('用法: %s <源文件.c> <函数名...>\n' % argv[0])
        return 2
    src = argv[1]
    if not os.path.isfile(src):
        sys.stderr.write('✗ 源文件不存在: %s\n' % src)
        return 2
    inc = os.path.dirname(os.path.abspath(src))

    ll = emit_ir(src, inc)
    if ll is None:
        return 2

    print('源文件: %s' % src)
    print('（判据：函数地址若被非调用用途引用 → Amice 会静默跳过 VMP）')
    print('')

    bad = 0
    for name in argv[2:]:
        body = function_body(ll, name)
        if body is None:
            print('  ? %-28s 找不到定义（拼写错？被内联了？）' % name)
            bad += 1
            continue
        off = non_call_self_uses(body, name, ll=ll)
        if not off:
            print('  ✓ %-28s 无自身引用 → 可虚拟化' % name)
        else:
            print('  ✗ %-28s 有 %d 处 non-call 自身引用 → VMP 会跳过'
                  % (name, len(off)))
            for l in off[:5]:
                print('       %s' % l[:110])
            bad += 1

    print('')
    if bad:
        print('❌ %d 个函数不满足 VMP 前置条件。' % bad)
        print('   改法：把取地址的动作移到调用方（不虚拟化的函数），用参数传入。')
        print('   例：dladdr(&self, &i)  →  调用方算好 so_path/base 后传入')
        return 1
    print('✅ 全部满足前置条件。')
    print('   ⚠️ 这只是必要条件 —— varargs/naked/异常处理等其它跳过条件未查，')
    print('      最终仍以 RUST_LOG=amice=debug 与 check-obf.sh 的 VM 子段数为准。')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
