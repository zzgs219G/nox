#!/usr/bin/env python3
"""so_section_mark.py — 通用"段标记器"：按函数头规则给 C/C++ 源码打加密段标记

这是什么（第2层设施）：
    把"哪些代码要进 .ncx 加密段"这件事，从"每个模块自己在源码里手写
    __attribute__((section(...)))"变成"一条可配置规则"。

    使用者（第3层）只管声明"我要保护长这样的函数"，不用管段名、不用管
    加密算法、不用管密钥、不用管解锁——那些全在第1层设施里
    （nc_guard_boot.c + so-section-lock.py + nc_guard_key.c）。

    为什么要单独一层：
        sigcheck 的探针是手写 attribute 的（env_check.c，冻结文件，只追加）；
        dex2c 的转译产物是引擎生成的，不该为它去改冻结的引擎；
        stringenc 的桩、未来的新模块……如果每个都各自想办法，就是"每个模块
        单独写一套防御"。有了本脚本，加一个消费者 = 加一条规则。

规则怎么定：
    内置若干常用规则（见 BUILTIN_RULES），也支持 --pattern 自定义。
    每条规则 = 一段正则 + 命中后替换成的模板。匹配发生在"函数定义行"上，
    即形如  <返回类型> <函数名>(<参数>) {  的那一行。

安全性（重要，别当普通文本替换看）：
    ① 幂等：已带目标 attribute 的行不再注入（重复跑 = 零改动）
    ② 只注入"函数定义行"：靠行尾 { 与行首非空白判定，不碰声明/调用/注释
    ③ --check 模式：只报告会改哪些行、不写文件，供 CI 预检
    ④ 失败即 fail-fast：文件读写出错立刻抛，不静默跳过（静默跳过 =
       以为加密了其实没有）

用法：
    so_section_mark.py <目录或文件> [选项]

    --rule dex2c-jni     内置规则名（可多次指定）
    --pattern REGEX      自定义匹配（与 --rule 等价，二选一）
    --section .ncx       目标段名（默认 .ncx）
    --check             只报告不写
    --dry-run           同 --check
    -v                  列出每个命中位置

退出码：
    0 = 成功（或 --check 下无需改动）
    2 = 参数错误 / 路径不存在
    3 = 有文件需要改动（仅 --check 模式）
"""
import argparse
import os
import re
import sys

SECTION = '.ncx'
ATTR = '__attribute__((section("%s"), used, retain))' % SECTION


class MarkError(Exception):
    pass


# ── 内置规则 ────────────────────────────────────────────────────────
# 每条 = (名字, 说明, 匹配函数定义行的正则, 需要的前置条件函数)
#
# 正则统一约定：
#   捕获组1 = 返回类型（含 cv/存储类修饰，如 extern "C" JNIEXPORT jint）
#   捕获组2 = 函数名
#   捕获组3 = 参数列表（到 { 之前）
# 这样替换时能把 attribute 插在"返回类型"之前，不破坏任何语义。
BUILTIN_RULES = {
    # dex2c 转译产物的 JNI 函数（writer.py:111 生成的形态）：
    #   extern "C" JNIEXPORT jint JNICALL
    #   Java_com_demo_app_MainActivity_onCreate__Landroid_os_Bundle_2V(...)
    #
    # ⚠️ 2026-10-18 两个坑（都实测踩过）：
    #   ① 本规则只匹配【头部行】。原写法在正则里用 \n? 连接下一行的函数名，
    #      但 mark_text 是逐行匹配的，单行内 JNICALL 后没有任何字符 →
    #      永远匹配不上 → 实测 0 命中。函数名归属交给 _is_definition 向后扫。
    #   ② 括号里别误留尾逗号：值会变成 1 元组，re.compile 直接 TypeError。
    #
    # 只认定义不认声明：声明由 _is_definition（遇 ; 判否）挡掉。
    'dex2c-jni': (
        r'^[ \t]*(?:extern[ \t]+"C"[ \t]+)?'
        r'JNIEXPORT[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]+JNICALL'
    ),
    # 普通 C 风格函数定义（不带 static，即对外链接的）：
    #   jint nc_something(...) {
    # 保守起见要求行尾紧跟 { —— 声明行（分号结尾）不命中。
    # ⚠️ 括号里别误留尾逗号：值会变成 1 元组，re.compile 直接 TypeError
    # （2026-10-18 在 dex2c-jni 上实测踩过，本规则同）。
    'c-export': (
        r'^([ \t]*)((?:JNIEXPORT|jint|jboolean|jobject|void|int|bool)'
        r'[ \t]+[A-Za-z_][A-Za-z0-9_]*)([ \t]*\()'
    ),
    # dex2c 转译产物在【动态注册】形态下的 JNI 函数（writer.py:106）：
    #   void Java_com_demo_app_MainActivity_onCreate(JNIEnv *env, jobject thiz, ...)
    #
    # 为什么不带 JNIEXPORT / JNICALL：`--dynamic-register` 走的是
    # writer.py:106 的分支，只写「返回类型 + 空格 + 长名」，没有
    # `extern "C" JNIEXPORT ... JNICALL` 那一行。产出的符号受
    # -fvisibility=hidden 支配（这正是该开关的目的：业务方法名不进 .dynsym），
    # 由 DynamicRegister.cpp 在 JNI_OnLoad 里 RegisterNatives 注册。
    #
    # ⚠️ 2026-11-10 修：protect.sh 一直传 --dynamic-register，而上面
    #    dex2c-jni 规则要求 JNIEXPORT ... JNICALL → 实测命中 0，
    #    dex2c 产物整批留在明文 .text（实测 .ncx 只 7.9KB 而 dex2c 产物
    #    ≈24KB 全在 .text，onCreate@0x4254c 熵 6.179 = 明文）。
    #    同一正则也被 protect.sh 的「静默失防」守卫复用，所以守卫同样数到 0
    #    而放行 —— 规则与守卫一起失效，形成假绿。
    #
    # 只认 `Java_` 前缀（不是任意标识符）：这是 JNI 长名的必经前缀，
    # 用它把范围锁死在「确实是 JNI 导出函数」，避免误标普通 C 函数。
    # 返回类型取 util.get_native_type 可能产出的全集，含指针返回类型。
    'dynamic-register-jni': (
        r'^[ \t]*(?:jboolean|jbyte|jshort|jchar|jint|jlong|jfloat|jdouble'
        r'|jstring|jobject|jarray|jclass|jthrowable|void|jsize)'
        r'[ \t]+\**[ \t]*(Java_[A-Za-z0-9_]+)[ \t]*\('
    ),
}


def _already_marked(line: str) -> bool:
    """幂等判断：这行是否已经带目标 section 的 attribute。"""
    return 'section("%s")' % SECTION in line


def _marked_above(out: list, line: str) -> bool:
    """幂等判断的另一种形态：attribute 是否已被插在【紧邻上一行】。

    ⚠️ 2026-10-18 修：attribute 是插在函数头行【之前】的独立一行
    （见 mark_text 的 `'%s%s\\n%s%s'`），所以函数头行本身永远不含
    section 字样 —— 只查当前行会导致二次跑重复注入（实测 md5 变了）。
    这里查输出流的最后一行是否是刚插入的那种 attribute 行。

    ⚠️ 2026-11-10 修：原实现用 `out[-1] == indent + ATTR` 精确比对整行，
    但 ATTR 会随参数变化（如二次运行加上 --annotate 后 ATTR 多了
    annotate(...)），于是"已标过段但没标 annotate"的行被判为未标记
    → 重复注入第二行 attribute（同一函数两个 __attribute__ 合法但产物
    形态变了，且 annotate 会重复）。改为结构判据：
    上一行是不是一条【包含目标 section】的 __attribute__ 行。
    要不要再补 annotate 由调用方决定（见 --annotate 的说明：
    本脚本不做"增量补注"，同一函数请一次标全）。
    """
    if not out:
        return False
    indent = re.match(r'^[ \t]*', line).group(0)
    prev = out[-1]
    if not prev.startswith(indent + '__attribute__((',):
        return False
    return ('section("%s")' % SECTION) in prev


def _is_definition(lines, i):
    """从第 i 行（模式命中的函数头行）向后判断：这是函数定义还是声明？

    ⚠️ 2026-10-18 修：旧实现只对【命中行本身】判 `endswith('{')`，但 dex2c 的
    函数头是跨行的（`extern "C" JNIEXPORT jint JNICALL` 一行、函数名+参数+
    `{` 在后续行），导致 is_def 恒假、一个都标不上（实测 0 命中）。
    正确做法：从命中行起向后扫，遇到 `{` → 定义；遇到 `;`（行尾）→ 声明。
    扫描上限 12 行，足够覆盖 JNI 函数头的跨行形态，又不会误吞后续函数。
    """
    limit = min(len(lines), i + 12)
    in_block_comment = False
    for j in range(i, limit):
        line = lines[j]
        stripped = line.strip()
        if in_block_comment:
            if '*/' in line:
                in_block_comment = False
            continue
        if stripped.startswith('/*'):
            if '*/' not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith('//'):
            continue
        # 去掉行尾注释再看结构
        code = stripped.split('//')[0].rstrip()
        if code.endswith(';'):
            return False          # 声明（原型）
        if code.endswith('{'):
            return True           # 定义
        # ⚠️ 2026-10-19 修：一行内写完的紧凑定义（`...JNICALL name(...){}`
        #    或 `...{ return 0; }`）行尾不是 `{` 而是 `}`/`}` 等，旧实现
        #    判为「不是定义」→ 漏标。dex2c 产物是多行形态所以此前没暴露，
        #    但手写/短函数会中招（本地测试文件就是这么写的）。
        #    判据：本行含 `{` 即视为定义（`;` 已在上一步排除）。
        if '{' in code:
            return True
        # 参数跨行时中间行既不是 ; 也不是 {，继续向后看
    # 12 行内没定论：保守判否（宁可漏标也不错标——错标=给不该加密的代码加密）
    return False


def mark_text(text: str, pattern: re.Pattern, verbose: bool = False,
              src: str = '<str>', skip_names=None):
    """对一段源码注入标记。返回 (新文本, 命中数)。"""
    lines = text.split('\n')
    out = []
    hits = 0
    in_block_comment = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # 块注释状态机（先判断再处理，保证注释内的代码不被注入）
        if in_block_comment:
            out.append(line)
            if '*/' in line:
                in_block_comment = False
            i += 1
            continue
        if stripped.startswith('/*'):
            out.append(line)
            if '*/' not in stripped:
                in_block_comment = True
            i += 1
            continue
        if stripped.startswith('//'):
            out.append(line)
            i += 1
            continue

        # 幂等：已带目标 attribute 的不再注入。
        # 必须查两处——当前行（手写 attribute 的形态）与紧邻上一行
        # （本脚本插入的形态）。只查当前行会导致二次跑重复注入。
        if pattern.match(line) and not _already_marked(line) \
                and not _marked_above(out, line) \
                and _is_definition(lines, i) \
                and not _name_skipped(lines, i, skip_names):
            indent = re.match(r'^[ \t]*', line).group(0)
            out.append('%s%s\n%s%s' % (indent, ATTR, indent, line.lstrip()))
            hits += 1
            if verbose:
                print('  [mark] %s:%d  %s' % (src, i + 1, stripped[:70]))
        else:
            out.append(line)
        i += 1
    return '\n'.join(out), hits


def _name_skipped(lines, idx, skip_names):
    """判断 idx 起始的函数定义是否在【函数名】黑名单里。

    为什么需要按函数名排除（2026-10-19）：`nc_link.c` 里既有必须上锁的
    判决核心 `nc_verify_t1`，又有绝不能被锁的 JNI 入口 `ncVerify`/
    `heartbeat`（它们是 unlock 的调用方，锁进去 = 死锁）。
    按文件排除会把整份文件放掉，等于放弃了判决核心的加密。

    实现：对命中行及其后最多 3 行找 `JNICALL <name>` 或 `<name>(`，
    取函数名比对黑名单（子串匹配，兼容 C++ 名称修饰前后缀）。"""
    if not skip_names:
        return False
    blob = '\n'.join(lines[idx:idx + 4])
    for nm in skip_names:
        esc = re.escape(nm)
        # ① `JNICALL <nm>(` —— 形参紧跟的普通 C 函数（JNI_OnLoad 等）
        if re.search(r'JNICALL[ \t]+' + esc + r'[ \t]*\(', blob):
            return True
        # ② `Java_<pkg>_<Class>_<nm>(` —— JNI 短名绑定。
        #    ⚠️ 不能用 \b 边界：`Java_..._ncVerify` 里 nm 前面是 `_`，
        #    那是单词字符，\b 不成立（实测漏判）。改用「前面是 _ 或行首」。
        if re.search(r'(?:^|[\s_])' + esc + r'[ \t]*\(', blob, re.M):
            return True
    return False


def iter_sources(paths):
    """展开目录/文件参数，只收 .c/.cpp/.cc/.cxx。

    --exclude 按【文件基名】匹配（不是全路径）：调用方写 nc_guard_jni.c
    即可，不必关心它在 jni/ 还是 jni/nc/ 下。
    """
    exts = ('.c', '.cpp', '.cc', '.cxx')
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith(exts):
                        yield os.path.join(root, f)
        elif os.path.isfile(p):
            if p.endswith(exts):
                yield p
            else:
                raise MarkError('不是 C/C++ 源文件: %s' % p)
        else:
            raise MarkError('路径不存在: %s' % p)


def _excluded(path: str, excludes) -> bool:
    return os.path.basename(path) in set(excludes or ())


def main(argv=None):
    global SECTION, ATTR
    ap = argparse.ArgumentParser(
        description='按函数头规则给 C/C++ 源码打加密段标记（通用设施，零模块逻辑）')
    ap.add_argument('paths', nargs='+', help='目录或文件')
    ap.add_argument('--rule', action='append', default=[],
                    help='内置规则名（可多次）；可选: %s' % ', '.join(BUILTIN_RULES))
    ap.add_argument('--pattern', default='',
                    help='自定义正则（须含返回类型/函数名捕获组）；与 --rule 等价')
    ap.add_argument('--section', default=SECTION, help='目标段名（默认 %s）' % SECTION)
    ap.add_argument('--exclude-func', action='append', default=[],
                    help='按【函数名】排除（不标段）。用于同文件内既有要上锁的、'
                         '又有绝不能上锁的（如 nc_link.c 的判决核心 vs JNI 入口）')
    ap.add_argument('--exclude', action='append', default=[],
                    help='排除的文件名（可多次）。用于排除\"不能被锁\"的文件 —— '
                         '典型：nc_guard_jni.c（它调 unlock，锁它=死锁）')
    ap.add_argument('--check', '--dry-run', action='store_true', dest='check',
                    help='只报告会改哪些行，不写文件')
    ap.add_argument('--annotate', default='',
                    help='额外注入 annotate("...")（可多次，逗号分隔的表达式原样写入）。'
                         '典型用法：--annotate "+vm_virtualize" —— 让 Amice 的 VMP '
                         '虚拟化这些函数。与段标记叠加在同一个 attribute 里，'
                         '不产生第二行 attribute。')
    ap.add_argument('-v', '--verbose', action='store_true', help='列出每个命中位置')
    args = ap.parse_args(argv)

    SECTION = args.section
    _attrs = ['section("%s")' % SECTION]
    if args.annotate:
        # ⚠️ 走 annotate 路径时【不能加 used / retain】：
        #    实测 clang 会把它们变成 IR 的 @llvm.used 表，而表里存的是
        #    `ptr @func` —— 即函数地址引用。Amice 的
        #    has_unsupported_function_uses（vm_virtualize/mod.rs:1067）
        #    只豁免「直接调用」和「@llvm.global.annotations」，
        #    @llvm.used 会被判 non-call address use → VMP 静默跳过。
        #    实测三种组合：
        #      noinline+section+used+retain+annotate → llvm.used=1 ❌
        #      noinline+section+retain+annotate      → llvm.used=1 ❌
        #      noinline+section+used+annotate        → llvm.used=0 ❌（used 不产生，但 retain 也不加时…见下）
        #      noinline+section+annotate             → llvm.used=0 ✅
        #    安全性：section 归属本身就让函数不被当死代码删（段被锁箱器
        #    引用），且这些是 JNI 入口（有外部调用者），无需 used/retain。
        #
        # annotate 可以有多个，用逗号分隔；每个包成独立 annotate(...)。
        # ⚠️ 不把多个表达式塞进一个 annotate：Amice 按 annotate 逐条解析，
        #    合并后会被当成单个无法识别的 flag 名。
        for expr in args.annotate.split(','):
            expr = expr.strip()
            if expr:
                _attrs.append('annotate("%s")' % expr)
        # noinline：函数被内联掉就没有独立符号可虚拟化。
        _attrs.insert(0, 'noinline')
    else:
        # 纯段标记路径保持原样（used/retain 是历史形态，产物不能变）。
        _attrs += ['used', 'retain']
    ATTR = '__attribute__((%s))' % ', '.join(_attrs)

    if not args.rule and not args.pattern:
        ap.error('必须指定 --rule 或 --pattern（不给规则 = 不知道要保护什么）')

    # 组装规则
    pats = []
    for name in args.rule:
        if name not in BUILTIN_RULES:
            ap.error('未知规则 %r；可用: %s' % (name, ', '.join(BUILTIN_RULES)))
        pats.append((name, re.compile(BUILTIN_RULES[name])))
    if args.pattern:
        try:
            pats.append(('custom', re.compile(args.pattern)))
        except re.error as e:
            ap.error('正则语法错误: %s' % e)

    total_files = 0
    total_hits = 0
    changed = []
    try:
        for src in iter_sources(args.paths):
            if _excluded(src, args.exclude):
                if args.verbose:
                    print('  [skip] %s（--exclude 排除）' % src)
                continue
            with open(src, 'r', encoding='utf-8', errors='surrogateescape') as f:
                text = f.read()
            new_text = text
            file_hits = 0
            for name, pat in pats:
                new_text, h = mark_text(new_text, pat, args.verbose, src,
                                        args.exclude_func)
                file_hits += h
            if file_hits:
                total_files += 1
                total_hits += file_hits
                changed.append((src, file_hits))
                if not args.check:
                    with open(src, 'w', encoding='utf-8',
                              errors='surrogateescape') as f:
                        f.write(new_text)
    except MarkError as e:
        print('❌ %s' % e, file=sys.stderr)
        return 2
    except OSError as e:
        print('❌ 文件读写失败: %s' % e, file=sys.stderr)
        return 2

    for src, h in changed:
        print('  %s: %d 个函数' % (src, h))
    print('%s合计 %d 个函数 / %d 个文件 → 段 %s'
          % ('[check] ' if args.check else '', total_hits, total_files, SECTION))

    if args.check and total_hits:
        print('（--check 模式未写文件；退出码 3 表示有改动待做）')
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
