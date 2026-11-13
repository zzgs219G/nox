#pragma once
#include <stdint.h>
#include <stddef.h>

/* 密钥派生接口：SHA-256 / HMAC / HKDF + 六个域密钥
 *
 * 与 so-section-lock.py 的 derive_app_keys() 必须逐字节一致（T20 对拍）。
 * 每个域一把 16 字节钥匙，label 前缀做域分隔（复用 = 两条链互相印证）。 */

/* SHA-256（实现照抄 sig_check.c 已验证版本；此处只暴露不透明句柄） */
typedef struct ksha_ctx_s ksha_ctx;

void ksha_init(ksha_ctx *ctx);
void ksha_update(ksha_ctx *ctx, const uint8_t *data, size_t len);
void ksha_final(ksha_ctx *ctx, uint8_t out[32]);

/* SHA-256 一步到位（吃完整消息，出 32 字节）。
 * 2026-10-19 新增：ksha_ctx 在 .h 里是不透明句柄，密文段里的调用方
 * （包名指纹校验）开不出栈对象。与 ksha_init/update/final 三步等价。 */
void ksha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* HMAC-SHA256（RFC 2104） */
void khmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* 增量 HMAC：分段喂消息，用于 MAC 覆盖多个不连续段。不透明句柄 —— 调用方
 * 开不出栈对象（所以每个域都要一个 _from_der 便捷版）。 */
typedef struct khmac_ctx_s khmac_ctx;
void khmac_init(khmac_ctx *ctx, const uint8_t *key, size_t key_len);
void khmac_update(khmac_ctx *ctx, const uint8_t *data, size_t len);
void khmac_final(khmac_ctx *ctx, uint8_t out[32]);

/* 增量 HMAC 的上下文尺寸（构造期断言用；调用方需按此开栈对象）。
 * ⚠️ 与 nc_guard_key.c 的 struct khmac_ctx_s 保持一致——改一处必须改另一处，
 *    下面的 static_assert 在编译期把关，不一致会直接编译失败（好事）。 */
#define KHMAC_CTX_SIZE   256   /* 实际 88+88+32 = 208，留余量防将来扩字段 */
#define KHMAC_CTX_ALIGN  8

/* HKDF-SHA256（RFC 5869，与 so-section-lock.py 的 hkdf_sha256() 同算法） */
void khkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                  const uint8_t *salt, size_t salt_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len);

/* 从 APK 提取第一签名者证书 DER（只读 EOCD/CD/Signing Block，几十 KB）。
 * v3 优先，回退 v2。der 需 ≥ 4096；返回 0 成功。 */
int ncg_apk_first_cert_der(const char *apk_path, uint8_t *der, size_t der_cap,
                           size_t *der_len);

/* k_so = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="nc-so-v1"+pkg, 16) */
int ncg_derive_k_so(const uint8_t master[32], const uint8_t cert_sha256[32],
                    const char *pkg, uint8_t out[16]);

/* 便捷版：直接吃 certDER，内部做 SHA256(certDER) 再 HKDF。
 * 2026-10-19 新增：运行期证书派生（P1-a）需要它——ksha_ctx 是不透明句柄，
 * 调用方在栈上开不出对象（head 本体是密文段里的代码，必须尽量小）。
 * 与 ncg_derive_k_so(master, SHA256(der), pkg, out) 逐字节等价。 */
int ncg_derive_k_so_from_der(const uint8_t master[32],
                             const uint8_t *cert_der, size_t der_len,
                             const char *pkg, uint8_t out[16]);

/* 同上的 mac 域版本（label "nc-so-mac-v1"）。
 * 2026-10-19 P1-a：运行期 k_mac 也改为证书派生，不再从 slot 读——
 * slot 里的 wrapped_k_mac 等于把完整性密钥交给攻击者。 */
int ncg_derive_k_mac_from_der(const uint8_t master[32],
                              const uint8_t *cert_der, size_t der_len,
                              const char *pkg, uint8_t out[16]);

/* k_mac = HKDF(master, SHA256(cert), "nc-so-mac-v1"+pkg, 16)
 * 只参与"密文段是否被改过"的 HMAC，绝不能与 k_so 复用
 * （复用 = 知道 RC4 密钥即可伪造 MAC，完整性校验形同虚设）。 */
int ncg_derive_k_mac(const uint8_t master[32], const uint8_t cert_sha256[32],
                     const char *pkg, uint8_t out[16]);

/* k_so_r = HKDF(..., "nc-so-r-v1"+pkg, 16)   .ncxr 常量表专用
 * ⚠️ 必须与 k_so 不同：RC4 流密码两段共用 keystream = two-time-pad 误用
 * （实测 C_ncx[i]^C_ncxr[i] == P_ncx[i]^P_ncxr[i]）。 */
int ncg_derive_k_so_r(const uint8_t master[32], const uint8_t cert_sha256[32],
                      const char *pkg, uint8_t out[16]);

/* 便捷版：吃 certDER，内部 SHA256 再 HKDF。与 ncg_derive_k_so_from_der 同构。 */
int ncg_derive_k_so_r_from_der(const uint8_t master[32],
                               const uint8_t *cert_der, size_t der_len,
                               const char *pkg, uint8_t out[16]);

/* k_nct = HKDF(..., "nc-insn-v1"+pkg, 16)   .nct 解释器段用
 *
 * ⚠️ 别当死代码删掉：.nct/.ncv 目前不加密（体积优先，见 so防护架构 §15.5），
 *    所以运行期没有调用点。但这三个域（insn/warm/dex）：
 *      ① 是 test-k-nct-parity.py 的跨语言对拍对象 —— 删了断言失效
 *      ② 是"将来想重新加密 .nct/.ncv"时的现成钥匙链，改回 segs[] 即可
 *    真正用时**只加密纯数据**：指针表在 .ncs/.ncw 不能加密（含
 *    R_AARCH64_RELATIVE 重定位槽，写回会覆盖链接器填的指针 → SIGILL）。 */
int ncg_derive_k_nct(const uint8_t master[32], const uint8_t cert_sha256[32],
                     const char *pkg, uint8_t out[16]);

/* 便捷版：吃 certDER。与 ncg_derive_k_so_r_from_der 同构。 */
int ncg_derive_k_nct_from_der(const uint8_t master[32],
                              const uint8_t *cert_der, size_t der_len,
                              const char *pkg, uint8_t out[16]);

/* k_bc = HKDF(..., "nc-warm-v1"+pkg, 16)   .ncq 字节码段用
 * k_bc2 = HKDF(..., "nc-dex-v1"+pkg, 16)   .ncv 字节码段用（第二套）
 * ⚠️ 两者与 k_nct 都不同：RC4 流密码共用 keystream = two-time-pad。 */
int ncg_derive_k_bc(const uint8_t master[32], const uint8_t cert_sha256[32],
                    const char *pkg, uint8_t out[16]);

int ncg_derive_k_bc_from_der(const uint8_t master[32],
                             const uint8_t *cert_der, size_t der_len,
                             const char *pkg, uint8_t out[16]);

/* ── k_bc2（.ncv 消费方第二套字节码段，2026-11-13）──────────────────
 * k_bc2 = HKDF-SHA256(..., info="nc-dex-v1"+pkg, 16)
 * 与 derive_app_keys()['dex'] 逐字节一致。
 * ⚠️ 与 k_bc（.ncq，nox 第一套）必须不同 —— 两套链接进同一个 so。 */
int ncg_derive_k_bc2(const uint8_t master[32], const uint8_t cert_sha256[32],
                     const char *pkg, uint8_t out[16]);

int ncg_derive_k_bc2_from_der(const uint8_t master[32],
                              const uint8_t *cert_der, size_t der_len,
                              const char *pkg, uint8_t out[16]);
