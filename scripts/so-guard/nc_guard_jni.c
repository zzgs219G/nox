/* nc_guard_jni.c — .ncx 机制的 JNI 自检入口
 *
 * 为什么需要：加固包跑在真机上【没有任何现象】可观测 ——
 *   -fvisibility=hidden 把 ncguard_unlock/ncguard_probe 全藏了，
 *   "不闪退"因此什么都证明不了（那段密文可能根本没被执行）。
 * 本文件给一个显式入口，让 CI/真机拿到【可判读的回执】：
 *   Java: NcLink.selftest()   C: Java_com_nc_link_NcLink_selftest()
 *
 * ⚠️ 曾用独立类 Lcom/nc/guard/NcGuard;，但那类从未被 inject-javacheck.py
 *   生成 → selftest 抛 UnsatisfiedLinkError 被 catch 吞掉 → 连带跳过
 *   heartbeat（报错四十九）。现挂到已注入的 NcLink 上，与 ncVerify/
 *   heartbeat 同源。
 *
 * 返回值语义：
 *    59     完整链路通过：解锁 → 解密 → 执行 .ncx 代码（见 nc_guard_probe.c）
 *    -1     dladdr 失败（拿不到 so 基址）
 *    -2     .ncx 段定位失败
 *    -3     .nck 段定位失败
 *    -4/-5  .ncx 段为空 / 非 SHF_ALLOC
 *    -6/-7  open so 失败 / slot 读取不足
 *    -8/-10 mprotect 失败（Android 对 SHF_EXECINSTR 页的限制比 Linux 严）
 *    -9     内存分配失败
 *    -11    密文 MAC 校验失败（.ncx/.ncxr 被篡改，或密钥与密文不匹配）
 *    -12    证书/包名不可得（fail-closed：读不到 APK 证书或包名指纹不符）
 *    -100   重入（本进程已自检过）
 *
 * ⚠️ 调用本函数即触发【一次性】解锁。再次调用走幂等分支返回 0
 *   （不再是 59）—— 故自检只调一次。
 *
 * ⚠️⚠️ 2026-11-04（改动态注册时实测踩到）：本函数必须带
 *   __attribute__((used, retain))。原因：
 *   动态注册后它【没有任何直接调用者】—— 下游 nc_link_jni.c 里只有一个
 *   weak 引用（`if (nc_link_jni_selftest != NULL)`），而 weak 引用不构成
 *   强依赖。静态库形态（libnox.a）+ 消费方 -Wl,--gc-sections 时，
 *   链接器判定"这段没人要" → 整个 .text.nc_link_jni_selftest 被回收。
 *   实测：不加 retain 时 `llvm-nm libnc.so | grep selftest` 无输出，
 *        加 retain 后符号存在（segment flags 里出现 G = SHF_GNU_RETAIN）。
 *   后果是【静默】的：构建全绿、判决与心跳照常，只是 selftest 永远
 *   UnsatisfiedLinkError —— 与报错四十九（自检类没生成、异常被吞）
 *   是同一类"假绿"。retain 是唯一在 .o 侧就能钉住的办法：
 *   在消费方加 used/retain 对 extern 声明无效（属性只对定义生效）。
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
