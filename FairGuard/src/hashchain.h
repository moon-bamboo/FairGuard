/*
 * hashchain.h —— 日志哈希链的「单步推进」（插件与校验工具**共用同一份实现**）
 *
 * ============================ 为什么必须共用 ============================
 *
 * 哈希链的全部意义是"**别人能独立校验**"。
 *
 * 如果插件用一份实现、校验工具用另一份（哪怕是我自己抄过去的），
 * 两边只要差一个字节，链就**永远对不上** —— 而且这种错误极难察觉：
 * 报告会显示"日志被篡改"，用户会去怀疑对局记录，而不是怀疑我们的代码。
 *
 * 所以把这一步抽成头文件，两个程序都 include 它：
 * **物理上不可能跑偏**，也不需要在两边各写一遍测试去对拍。
 *
 * ============================ 记录布局（全部小端） ============================
 *
 *     [0..1]   house    uint16     日志里的 h=
 *     [2..5]   frame    uint32     日志里的 f=
 *     [6..7]   nEvt     uint16     日志里的 MM=
 *     [8..9]   nWhom    uint16     日志里的 units=
 *     [10..11] nDest    uint16     日志里的 veh=
 *     [12..15] idx      uint32     这是第几条 DETECT 行（从 0 起）
 *
 *     chain = SHA256( chain_prev(32) || rec(16) )        chain 初值 = 32 个 0
 *
 * ★ 这六个字段**全部都能从一条 `*** DETECT` 行里读出来** ——
 *   这是刻意设计的：只要算法里混进任何"日志里没有的东西"
 *   （比如时间戳、事件原始字节），第三方就再也无法离线重算了。
 *   1.2 的算法正是栽在这里，1.3 才改成现在这样。
 *
 * ⚠️ 改这个布局 = **改变协议**。老日志会全部校验失败。
 *    真要改就得同时升版本号，并在 CHANGELOG 里写明"旧日志不可校验"。
 */

#ifndef FAIRGUARD_HASHCHAIN_H
#define FAIRGUARD_HASHCHAIN_H

#include "sha256.h"

/* 链值长度（SHA-256 = 32 字节）；日志里只打印前 8 字节的 hex */
#define HASHCHAIN_LEN 32

/* 日志里 chain= 打印多少字节（前 8 字节 = 16 个十六进制字符） */
#define HASHCHAIN_SHOWN 8

static inline void HashChainStep(unsigned char* chain,
                                 int      house,
                                 unsigned frame,
                                 int      nEvt,
                                 int      nWhom,
                                 int      nDest,
                                 unsigned idx)
{
    unsigned char rec[16];
    Sha256Ctx     c;

    rec[0]  = (unsigned char)(house);
    rec[1]  = (unsigned char)((unsigned)house >> 8);

    rec[2]  = (unsigned char)(frame);
    rec[3]  = (unsigned char)(frame >> 8);
    rec[4]  = (unsigned char)(frame >> 16);
    rec[5]  = (unsigned char)(frame >> 24);

    rec[6]  = (unsigned char)(nEvt);
    rec[7]  = (unsigned char)((unsigned)nEvt >> 8);

    rec[8]  = (unsigned char)(nWhom);
    rec[9]  = (unsigned char)((unsigned)nWhom >> 8);

    rec[10] = (unsigned char)(nDest);
    rec[11] = (unsigned char)((unsigned)nDest >> 8);

    rec[12] = (unsigned char)(idx);
    rec[13] = (unsigned char)(idx >> 8);
    rec[14] = (unsigned char)(idx >> 16);
    rec[15] = (unsigned char)(idx >> 24);

    Sha256_Init(&c);
    Sha256_Update(&c, chain, HASHCHAIN_LEN);
    Sha256_Update(&c, rec, sizeof(rec));
    Sha256_Final(&c, chain);
}

#endif /* FAIRGUARD_HASHCHAIN_H */
