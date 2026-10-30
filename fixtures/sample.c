/* sample.c — 示例：怎么标记要保护的函数
 *
 * 这份文件既给使用者看（怎么用），也被 test.sh 拿去做自测。
 * 两者共用一份，避免"文档写的和测试跑的不是一回事"。
 *
 * ────────────────────────────────────────────────────────────
 * 规则只有一条：想让哪个函数被加密，就在它上面加这两行
 *
 *     __attribute__((section(".ncx"), used, retain))
 *
 *   · section(".ncx")  把它放进加密段
 *   · used             防止被当死代码删掉
 *   · retain           防止被 --gc-sections 连段回收
 *
 * 不加标记的函数保持明文，正常编译。
 * ────────────────────────────────────────────────────────────
 *
 * ⚠️ 三个容易踩的坑（都是本项目实测踩过的）:
 *
 * ① 不要加 visibility("default")，除非确实需要从 Java 里 dlsym 它。
 *    加了之后函数名会写进 .dynstr（动态符号表），而 strip --strip-all
 *    删不掉动态符号表 → 函数名永久留在产物里，strings 就能看到。
 *    历史上实测：nm -D 一条命令拿到 7 个入口名 + 精确大小，那数字本身
 *    就是情报。
 *
 * ② 字符串字面量不会跟着函数进加密段。
 *    C 的字符串永远落在 .rodata，所在函数即使标了 .ncx，
 *    `strings` 一样能扫到 "/proc/self/cmdline" 这类字面量。
 *    要藏字符串得另想办法（本项目的做法见 nc_guard_paths.c）。
 *
 * ③ const 数据不能进 .ncx。
 *    clang 会报 'causes a section type conflict'（.ncx 是 AXR 可执行段）。
 *    常量表要单独标进 .ncxr（AWR，不可执行）。
 */

#include <stdint.h>

/* ── 示例1：要被保护的函数（加标记）──────────────────────────
 *
 * 这是一个故意写得简单的函数，便于验证：
 *     secret_calc(0) = (0 ^ 0x5A) * 3 = 270
 * test.sh 会用这个确定值断言"解密后的代码真的执行对了"——
 * 只验证"解锁返回 0"是不够的，必须验证解出的指令算得对。 */
__attribute__((section(".ncx"), used, retain))
int secret_calc(int a) {
    return (a ^ 0x5A) * 3;
}

/* ── 示例2：另一个被保护的函数 ────────────────────────────── */
__attribute__((section(".ncx"), used, retain))
int secret_flag(void) {
    return 0x2A;              /* 42 —— 刻意不取 0/1，避免 static 一眼定位 */
}

/* ── 示例3：不需要保护的函数（不加标记）─────────────────────
 *
 * 留在 .text，一直明文。用来对照：stripped 之后 objdump 仍然能
 * 完整反汇编出这个函数，而上面的 secret_* 已经是密文。 */
int plain_add(int a, int b) {
    return a + b;
}

/* ── 示例4：常量数据（默认不启用）────────────────────────────
 *
 * ⚠️ 想保护常量表，要标 .ncxr 而不是 .ncx —— clang 不允许 const 数据
 *    进 AXR 段（会报 'causes a section type conflict'）。
 *    .ncxr 是 AWR（可读写、不可执行），专门装常量表。
 *
 * ⚠️ 启用它有两个连带影响，必须同时处理，否则包会坏：
 *
 *    ① 锁箱时 --section 必须写 ".ncx,.ncxr"（两个段都要列）。
 *       只写 ".ncx" 的话，构建期 MAC 只覆盖 .ncx，而运行期会自动
 *       探测到 .ncxr 存在、把两段都算进 MAC → 不匹配 → 返回 -11。
 *       （实测踩过：同样的 .ncx 单独锁能 unlock=0，带上 .ncxr 就 -11）
 *
 *    ② 常量必须真的被代码引用（否则 --gc-sections 会把它回收，
 *       运行期找不到 .ncxr → 段数与构建期不一致 → SIGSEGV）。
 *
 * 所以这里默认【注释掉】，让最小示例先跑通。
 * 要用常量表保护，取消注释并确认上面两条都做到。
 *
 * ℹ️ 2026-10-30 补充：第三条连带影响已修（.ncxr 与 .bss 同页时 mprotect
 *    会把 .bss 变只读 → dlopen SIGSEGV）。现在启用它是安全的，
 *    test.sh 的 V7 项专门覆盖这个场景。
 *
__attribute__((section(".ncxr"), used, retain))
const uint8_t sample_table[16] = {
    0x3C, 0x5A, 0x91, 0xE7, 0x12, 0x8B, 0xD4, 0x6F,
    0x27, 0xA9, 0x4E, 0xC3, 0x78, 0x05, 0xB6, 0x1D,
};
 */
