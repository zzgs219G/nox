/* nc_guard_jni.c — .ncx 机制的 JNI 自检入口
 *
 * 为什么需要：-fvisibility=hidden 把 ncguard_unlock/ncguard_probe 全藏了，
 * 真机上"不闪退"什么都证明不了（密文可能根本没被执行）。本文件给一个显式
 * 入口，让 CI/真机拿到可判读的回执。
 *
 * 返回值：59 = 通过；-11 = MAC 校验失败；-12 = 证书/包名不可得；
 *   -100 = 重入。其余见 nc_guard_boot.c 的返回码约定。
 *
 * ⚠️ 必须 used/retain：动态注册后无直接调用者（下游只有 weak 引用），
 *    --gc-sections 会整个回收 → selftest 永远 UnsatisfiedLinkError，
 *    而症状是**静默**的。给 extern 声明加无效（属性只对定义生效）。
 * ⚠️ 调用即触发一次性解锁；再次调用返回 -100 —— 首次解锁尾部的
 *    mprotect(RX)/clear_cache 时序会让第二次取指 SIGILL。
 *
 * 动态注册 vs 短名绑定的取舍见 踩坑记录 K-11 */

#include <jni.h>
#include <stdatomic.h>

/* 实现在 nc_guard_boot.c / nc_guard_probe.c（同一 NDK 工程，非 static） */
extern int ncguard_unlock(void);
extern int ncguard_probe(int token);

/* 一次性守门。为什么必须挡第二次：ncguard_unlock() 在槽已擦时走幂等分支
 * 返回 0，无法区分"首次解锁成功"与"槽已空故跳过" → 会再走一次 probe()，
 * 而首次解锁尾部的 mprotect(RX)/clear_cache 时序会让第二次取指命中 I-cache
 * 不一致 → SIGILL（实测：第一次 59，第二次 Illegal instruction）。 */
static atomic_int ncg_selftest_done = 0;

/* 解锁 + 执行密文段代码，返回可判读的回执。
 * 动态注册（去 JNIEXPORT 与 Java_ 前缀）→ 受 -fvisibility=hidden 支配
 * → 不进符号表，由 RegisterNatives 按字符串名注册。 */
__attribute__((used, retain))
jint nc_link_jni_selftest(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&ncg_selftest_done, &expected, 1)) {
        return (jint) -100;      /* 已自检过，拒绝重入 */
    }
    int rc = ncguard_unlock();
    if (rc != 0) {
        return (jint) rc;        /* 解锁失败：把失败码透传，别吞 */
    }
    /* 解密成功后才可执行 .ncx 里的代码；契约值 59 见 nc_guard_probe.c */
    return (jint) ncguard_probe(0);
}
