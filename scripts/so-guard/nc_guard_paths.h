/* nc_guard_paths.h — 自带的路径密文表
 *
 * 设施原先从主项目的 sig_log_data.h 取两条 /proc 路径，导致单独编译失败。
 * 本文件让设施零外部源码依赖。
 *
 * ⚠️ 强度边界（如实）：这是【混淆】不是【加密】。密钥与算法都在本设施源码里，
 *    愿意反汇编 ncg_path_ctr_xor 的人可以还原。买到的是"strings 扫不到"。
 * ⚠️ 本文件零逻辑、只放接口与常量（实现在 nc_guard_paths.c）。 */
#ifndef _NC_GUARD_PATHS_H_
#define _NC_GUARD_PATHS_H_

#include <stddef.h>

/* 路径 ID。数值即密钥流的 msg_id（域分离用），不要随便改数值 —— 
 * 改了要重跑 gen-paths.py 重新生成密文表。 */
typedef enum {
    NCG_PATH_CMDLINE = 0,   /* "/proc/self/cmdline" —— 取进程名（包名）*/
    NCG_PATH_MAPS    = 1,   /* "/proc/self/maps"    —— 定位自身 APK */
    NCG_PATH_COUNT   = 2
} ncg_path_id;

/* 取第 id 条路径的明文写入 buf，返回 buf；失败返回 NULL。
 * 语义同原 lsg_s()：成功时 buf 以 NUL 结尾；id 越界/buf 为 NULL/cap 不足 → NULL。
 * 调用方自备缓冲；本函数不分配内存、不做 I/O。 */
const char *ncg_path_s(int id, char *buf, size_t cap);

#endif /* _NC_GUARD_PATHS_H_ */
