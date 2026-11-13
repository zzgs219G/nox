/* nc_guard_jni.c — .ncx 机制的 JNI 自检入口
 *
 * 为什么需要：加固包跑在真机上【没有任何现象】可观测 ——
 * -fvisibility=hidden 把 ncguard_unlock/ncguard_probe 全藏了，
 * "不闪退"因此什么都证明不了（那段密文可能根本没被执行）。
 * 本文件给一个显式入口，让 CI/真机拿到可判读的回执：
 *   Java: NcLink.selftest()
 *
 * 返回值语义：
 *    59     完整链路通过：解锁 → 解密 → 执行 .ncx 代码
 *    -1/-2/-3   dladdr 失败 / .ncx 段定位失败 / .nck 段定位失败
 *    -4/-5  .ncx 段为空 / 非 SHF_ALLOC
 *    -6/-7  open so 失败 / slot 读取不足
 *    -8/-10 mprotect 失败（Android 对 SHF_EXECINSTR 页限制比 Linux 严）
 *    -9     malloc 失败
 *    -11    密文 MAC 校验失败（.ncx/.ncxr 被篡改，或密钥与密文不匹配）
 *    -12    证书/包名不可得（fail-closed）
 *    -100   重入（本进程已自检过）
 *
 * ⚠️ 本函数必须带 used/retain：动态注册后它没有任何直接调用者（下游只有
 *    weak 引用），libnox.a + --gc-sections 会把它整个回收 → selftest 永远
 *    UnsatisfiedLinkError。而症状是【静默】的（构建全绿、判决与心跳照常）。
 *    在消费方给 extern 声明加 used/retain 无效（属性只对定义生效）。
 *
 * ⚠️ 调用本函数即触发一次性解锁；再次调用返回 -100（不是 0）——
 *    首次解锁尾部的 mprotect(RX)/clear_cache 时序会让第二次取指命中
 *    I-cache 不一致 → SIGILL（实测：第一次 59，第二次 Illegal instruction）。
 *
 * 动态注册 / 短名绑定的取舍见 踩坑记录 K-11
 */

#include <jni.h>
#include <stdatomic.h>

/* 实现在 nc_guard_boot.c / nc_guard_probe.c（同一 NDK 工程，非 static） */
extern int ncguard_unlock(void);
extern int ncguard_probe(int token);

/* 一次性守门。为什么必须挡第二次：ncguard_unlock() 在槽已擦时走幂等分支
 * 返回 0，无法区分"首次解锁成功"与"槽已空故跳过"→ 会再走一次 probe()，
 * 而首次解锁尾部的 mprotect(RX)/clear_cache 时序会让第二次取指命中
 * I-cache 不一致 → SIGILL（2026-10-17 实测：第一次 59，第二次 Illegal
 * instruction）。自检语义本就是"只验一次"，别去修 unlock 的时序。 */
static atomic_int ncg_selftest_done = 0;

/* 解锁 + 执行密文段代码，返回可判读的回执。
 *
 * ⚠️ 2026-11-04：改为【动态注册】（见 artifact-pipeline 的 nc_link_jni.c）。
 *   原先是短名绑定 `Java_com_nc_link_NcLink_selftest` + JNIEXPORT，
 *   符号必然进 .dynsym —— JNIEXPORT 自带 visibility("default")，
 *   对 -fvisibility=hidden 免疫，version script 也收敛不掉。
 *   现在去掉 JNIEXPORT 与 Java_ 前缀 → 受 -fvisibility=hidden 支配
 *   → hidden → 不进符号表，由 RegisterNatives 按字符串名在 JNI_OnLoad 注册。
 *
 * ⚠️ 若注册侧（nc_link_jni.c）以 weak 引用本符号且本文件未参与编译
 *   （静态库形态 / --exclude nc_guard_jni.c），则 selftest 不会被注册，
 *   Java 侧调用抛 UnsatisfiedLinkError。这是【允许】的：注入的 smali 已把
 *   selftest 包在独立 try/catch 里（报错四十九的教训），不影响心跳与判决。
 *   代价只是失去自检可观测性，不构成安全降级（selftest 本就不参与判定）。 */
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
