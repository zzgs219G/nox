/* mycode.c — 这个例子演示：哪些函数被加密，哪些不加密
 *
 * 想换成你自己的代码：直接改这个文件，然后跑 ./run.sh
 */

#include <stdint.h>
#include <string.h>

/* ── 被保护的函数：加这两行标记 ──────────────────────────────
 *
 *     __attribute__((section(".ncx"), used, retain))
 *
 *   section(".ncx")  放进加密段
 *   used             防止被当死代码删掉
 *   retain           防止被 --gc-sections 连段回收
 *
 * 加密后：反汇编看不到，strings 扫不到，符号表里也没有。
 *
 * ⚠️ 不要加 visibility("default")：那会把函数名写进 .dynstr，
 *    而 strip --strip-all 删不掉动态符号表 → 名字永久留在产物里。
 *    只有需要从 Java 侧 dlsym 的 JNI 入口才加。
 */
__attribute__((section(".ncx"), used, retain))
int algo_checksum(void) {
    /* 一段"看起来像算法"的代码：加密后这些指令全变成密文。
     * 注意：-Oz 会把循环常量折叠成一条 mov（加密前 objdump 能看到
     * "mov w0, #0x5ff"）—— 这正好演示了"为什么需要加密」：
     * 不加密的话，算法被优化成一条指令，等于把答案写在脸上。 */
    int acc = 0;
    for (int i = 0; i < 17; i++) {
        acc = (acc * 31 + i * 7) & 0xFFFF;
    }
    return (acc % 1000) + 1247;   /* 结果 1535，run.sh 断言它 */
}

/* ── 被保护的函数 2：常量字符串也不会出现在产物里 ────────────
 *
 * ⚠️ 注意：字符串字面量本身永远落 .rodata（C 语言规则），
 *    不会跟着函数进 .ncx。这里只是演示"函数被加密"，
 *    如果字符串本身敏感，得另做处理（见 so-guard/nc_guard_paths.c）。 */
__attribute__((section(".ncx"), used, retain))
int algo_verify(int key) {
    return key == 0x5A5A ? 1 : 0;
}

/* ── 不加密的函数：不加标记，一直是明文 ────────────────────
 *
 * 用来对照：加密后 objdump 仍然能完整反汇编这个函数。 */
int public_helper(int a, int b) {
    return a + b;
}

/* ── 导出给外部（run.sh 的驱动要 dlsym 它）──────────────────
 *
 * 这个必须导出，否则测试驱动找不到。它就是"对外接口"的角色。 */
__attribute__((visibility("default")))
int demo_checksum(void) {
    return algo_checksum();
}

__attribute__((visibility("default")))
int demo_verify(int k) { return algo_verify(k); }
