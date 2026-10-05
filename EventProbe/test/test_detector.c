/*
 * test_detector.c —— 判据核心单元测试（不需要游戏、不需要联机）
 *
 * 为什么要有它：
 *   判据是整个项目的命根子。它一旦算错，要么漏报（对手开挂看不见），
 *   要么误报（冤枉正常玩家）。而实机验证要装进游戏、联机打一局，
 *   成本极高、还只能验证"这一次"。
 *
 *   所以把判据拆成不依赖引擎的纯算法（src/detector_core.h），
 *   用【开发文档/03 里那份真实实测数据】构造用例，在这里先跑通：
 *     手动进同一辆载具   Destination 唯一值 = 1
 *     手动 PvP 技巧      Destination 唯一值 = 2
 *     AutoLoad 10 配 10  Destination 唯一值 = 10
 *   凡是"应该不命中"的用例，就是防误报；"应该命中"的用例，就是防漏报。
 *
 * 另外顺带验证：
 *   - 真实样本字节的字段偏移（Whom/Mission/Destination）解析对不对
 *   - 本机事件（Destination 尚未算出 = 0）会不会被误判
 *   - SHA256 实现是否正确（用标准测试向量）
 *
 * 编译运行（32 位 gcc，与插件同一个工具链）:
 *   gcc -O2 -Wall -o test_detector.exe test_detector.c -I ..\src
 *   test_detector.exe            正常输出 failures: 0
 */

#include <stdio.h>
#include <string.h>

#include "../src/detector_core.h"
#include "../src/sha256.h"

static int g_fail = 0;
static int g_pass = 0;

static void check(const char* what, int cond)
{
    if (cond) { g_pass++; printf("[PASS] %s\n", what); }
    else      { g_fail++; printf("[FAIL] %s\n", what); }
}

/* ------------------------------------------------------------------
 * 造一条事件（111 字节），只填判据用得到的那几个字段
 * ------------------------------------------------------------------ */
static void mk_event(unsigned char* e, int house, unsigned frame,
                     unsigned whom, unsigned char mission, unsigned dest)
{
    memset(e, 0, 111);
    e[0] = 0x04;                       /* Type = MegaMission */
    e[1] = 0x00;                       /* IsExecuted */
    e[2] = (unsigned char)house;       /* HouseIndex */
    memcpy(e + 3, &frame, 4);          /* Frame */
    memcpy(e + DET_OFF_WHOM, &whom, 4);/* Whom ID */
    e[DET_OFF_MISSION] = mission;      /* Mission */
    memcpy(e + DET_OFF_DEST, &dest, 4);/* Destination ID */
}

/* 默认阈值：与 EventProbe.ini 的 [Detector] 默认值一致 */
static DetRule DefaultRule(void)
{
    DetRule r;
    r.MinEvents    = 5;
    r.MinDest      = 5;
    r.RatioPercent = 50;
    return r;
}

/* 把 n 条事件喂进一个统计里 */
static void feed_all(DetStat* s, unsigned char (*evs)[111], int n)
{
    int i;
    DetStat_Reset(s);
    for (i = 0; i < n; i++) DetStat_Feed(s, evs[i]);
}

/* ==================================================================
 * 用例
 * ================================================================== */

/* ① 手动：10 个单位进【同一辆】载具 —— 绝不能命中 */
static void case_manual_same_vehicle(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 1, 26004, 1000u + (unsigned)i, DET_MISSION_ENTER, 500u);

    feed_all(&s, evs, 10);

    check("manual/10 units -> 1 vehicle : nWhom = 10", s.nWhom == 10);
    check("manual/10 units -> 1 vehicle : nDest = 1",  s.nDest == 1);
    check("manual/10 units -> 1 vehicle : NOT a hit",  DetStat_Judge(&s, &r) == 0);
}

/* ② 手动 PvP 技巧：进载具A + 路径点进载具B（实测 nWhom=11, nDest=2）—— 不能命中 */
static void case_pvp_two_vehicles(void)
{
    unsigned char evs[11][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 0, 21232, 2000u + (unsigned)i, DET_MISSION_MOVE, 600u);
    /* 第 11 条：Mission = 0x0B (Area_Guard)，实测里偶发出现 */
    mk_event(evs[10], 0, 21232, 2010u, 0x0B, 601u);

    feed_all(&s, evs, 11);

    check("PvP trick (2 vehicles) : nWhom = 11", s.nWhom == 11);
    check("PvP trick (2 vehicles) : nDest = 2",  s.nDest == 2);
    check("PvP trick (2 vehicles) : NOT a hit",  DetStat_Judge(&s, &r) == 0);
}

/* ③ 框选 10 个单位点地面移动（同一个目标格）—— 不能命中
 *    （用户"放出单位后命令它们移动一下"就是这个，曾被误判为作弊特征） */
static void case_group_move(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 0, 14126, 3000u + (unsigned)i, DET_MISSION_MOVE, 700u);

    feed_all(&s, evs, 10);

    check("group move to one cell : nDest = 1", s.nDest == 1);
    check("group move to one cell : NOT a hit", DetStat_Judge(&s, &r) == 0);
}

/* ④ ★ AutoLoad：10 个单位配 10 辆【不同】载具 —— 必须命中 */
static void case_autoload_10_10(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 1, 26004, 4000u + (unsigned)i, DET_MISSION_ENTER, 800u + (unsigned)i);

    feed_all(&s, evs, 10);

    check("AutoLoad 10 units / 10 vehicles : nWhom = 10", s.nWhom == 10);
    check("AutoLoad 10 units / 10 vehicles : nDest = 10", s.nDest == 10);
    check("AutoLoad 10 units / 10 vehicles : IS a hit",   DetStat_Judge(&s, &r) == 1);
    check("AutoLoad : Move/Enter counters",               s.nEnter == 10 && s.nMove == 0);
}

/* ⑤ 本机事件：事件刚生成，Destination 还没算出来（全 0）—— 不能命中，
 *    而且必须被认成"无效"而不是"一个目的地" */
static void case_local_fields_not_ready(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 0, 26004, 0u, DET_MISSION_ENTER, 0u);   /* Whom/Dest 都是 0 */

    feed_all(&s, evs, 10);

    check("local (fields not computed) : nEvt = 0",     s.nEvt == 0);
    check("local (fields not computed) : nInvalid = 10", s.nInvalid == 10);
    check("local (fields not computed) : NOT a hit",    DetStat_Judge(&s, &r) == 0);
}

/* ⑥ 混合：一半有效、一半字段为 0（本机与远程同名房号不该出现，
 *    但真出现时不能因为 0 参与去重而误判） */
static void case_half_invalid(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 5; i++)
        mk_event(evs[i], 1, 100, 5000u + (unsigned)i, DET_MISSION_ENTER, 900u + (unsigned)i);
    for (i = 5; i < 10; i++)
        mk_event(evs[i], 1, 100, 0u, DET_MISSION_ENTER, 0u);

    feed_all(&s, evs, 10);

    check("half invalid : nEvt = 5",  s.nEvt == 5);
    check("half invalid : nDest = 5", s.nDest == 5);
    /* 5 >= MinEvents(5) 且 5 >= MinDest(5) 且 5*2 >= 5 -> 命中
     * 这是刻意的：有效证据达到阈值就该报，无效条目只是被剔除 */
    check("half invalid : IS a hit (5 valid pairs)", DetStat_Judge(&s, &r) == 1);
}

/* ⑦ 比率阈值：10 单位配 5 辆（一半）—— 默认 50% 刚好够；配 4 辆就不够 */
static void case_ratio(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 1, 1, 6000u + (unsigned)i, DET_MISSION_ENTER, 950u + (unsigned)(i % 5));
    feed_all(&s, evs, 10);
    check("ratio 5/10 : nDest = 5, IS a hit (50%)", s.nDest == 5 && DetStat_Judge(&s, &r) == 1);

    for (i = 0; i < 10; i++)
        mk_event(evs[i], 1, 1, 6000u + (unsigned)i, DET_MISSION_ENTER, 950u + (unsigned)(i % 4));
    feed_all(&s, evs, 10);
    check("ratio 4/10 : nDest = 4, NOT a hit (<MinDest)", s.nDest == 4 && DetStat_Judge(&s, &r) == 0);

    /* 把阈值放松成 40%，4/10 就该命中 */
    r.RatioPercent = 40;
    r.MinDest = 4;
    check("ratio 4/10 with MinDest=4/Ratio=40 : IS a hit", DetStat_Judge(&s, &r) == 1);
}

/* ⑧ 规模阈值：只有 3 对（小规模自动装车以外的正常操作）—— 默认不报 */
static void case_min_events(void)
{
    unsigned char evs[3][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 3; i++)
        mk_event(evs[i], 1, 1, 7000u + (unsigned)i, DET_MISSION_ENTER, 980u + (unsigned)i);
    feed_all(&s, evs, 3);

    check("3 units / 3 vehicles : nDest = 3, NOT a hit (below MinEvents)", DetStat_Judge(&s, &r) == 0);

    /* 用户把阈值调到 3 就应当能抓到"小规模自动装车" */
    r.MinEvents = 3; r.MinDest = 3;
    check("3 units / 3 vehicles with MinEvents=3 : IS a hit", DetStat_Judge(&s, &r) == 1);
}

/* ⑨ 真实样本字节（开发文档/01 第三节里那条，来自真实联机日志）
 *
 *    04 00 00 5C 57 00 00 | 6D 3E 10 00 34 | 02 | 06 | 00 00 00 00 00 | 1D DF 00 00 0B | ...
 *    ↑  ↑  ↑  └───┬────┘   └─────┬──────┘   ↑    ↑    └─────┬──────┘   └──────┬──────┘
 *   类型 执行 房号 Frame=22364   Whom(5B)  Mission gap    Target(空)      Destination
 */
static void case_real_bytes(void)
{
    static const unsigned char sample[32] = {
        0x04, 0x00, 0x00, 0x5C, 0x57, 0x00, 0x00,   /* Type/Exec/House/Frame */
        0x6D, 0x3E, 0x10, 0x00, 0x34,               /* Whom  : ID=0x00103E6D RTTI=0x34 */
        0x02,                                       /* Mission = 2 (Move) */
        0x06,                                       /* gap */
        0x00, 0x00, 0x00, 0x00, 0x00,               /* Target (empty) */
        0x1D, 0xDF, 0x00, 0x00, 0x0B,               /* Dest  : ID=0x0000DF1D RTTI=0x0B */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DetStat s;
    unsigned wantWhom = 0x00103E6Du, wantDest = 0x0000DF1Du;

    DetStat_Reset(&s);
    DetStat_Feed(&s, sample);

    check("real sample : nEvt = 1",            s.nEvt == 1);
    check("real sample : Whom ID parsed",      s.nWhom == 1 && s.whom[0] == wantWhom);
    check("real sample : Destination parsed",  s.nDest == 1 && s.dest[0] == wantDest);
    check("real sample : Mission = 2 (Move)",  s.nMove == 1 && s.nEnter == 0);
    check("real sample : head bytes captured", s.nHeads == 1 && s.heads[0] == 0x04
                                               && s.heads[DET_OFF_MISSION] == 0x02);
}

/* ⑩ 去重别把不同 RTTI 的同一个 ID 当成一个 —— 本实现只比 4 字节 ID，
 *    这是刻意的（开发文档/01：RTTI 字节含义未深究，且不影响判据） */
static void case_dedup_by_id(void)
{
    unsigned char evs[10][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 10; i++)
    {
        mk_event(evs[i], 1, 1, 8000u + (unsigned)i, DET_MISSION_ENTER, 1000u + (unsigned)i);
        evs[i][DET_OFF_WHOM + 4] = (unsigned char)(0x30 + i);   /* 各不相同的 RTTI */
        evs[i][DET_OFF_DEST + 4] = (unsigned char)(0x0B);       /* 相同 RTTI */
    }
    feed_all(&s, evs, 10);
    check("dedup ignores RTTI byte : nDest = 10", s.nDest == 10);
    check("dedup ignores RTTI byte : IS a hit",   DetStat_Judge(&s, &r) == 1);
}

/* ⑪ 去重集合溢出保护：超过 DET_MAX_UNIQ 条不同值时不再增长，
 *    判据也不能因此凭空命中或崩溃 */
static void case_overflow(void)
{
    static unsigned char evs[DET_MAX_UNIQ + 20][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < DET_MAX_UNIQ + 20; i++)
        mk_event(evs[i], 1, 1, 9000u + (unsigned)i, DET_MISSION_ENTER, 1100u + (unsigned)i);

    DetStat_Reset(&s);
    for (i = 0; i < DET_MAX_UNIQ + 20; i++) DetStat_Feed(&s, evs[i]);

    check("overflow : nWhom capped at DET_MAX_UNIQ", s.nWhom == DET_MAX_UNIQ);
    check("overflow : nDest capped at DET_MAX_UNIQ", s.nDest == DET_MAX_UNIQ);
    check("overflow : nEvt still counts all",        s.nEvt == DET_MAX_UNIQ + 20);
    check("overflow : still a hit (capped but consistent)", DetStat_Judge(&s, &r) == 1);
}

/* ⑫ SHA256 —— 标准测试向量，确保哈希链是可信的 */
static void case_sha256(void)
{
    static const char* abcHex =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static const char* emptyHex =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    unsigned char d[32];
    char hex[80];
    int i;
    static const char* tbl = "0123456789abcdef";

    Sha256("abc", 3, d);
    for (i = 0; i < 32; i++) { hex[i * 2] = tbl[d[i] >> 4]; hex[i * 2 + 1] = tbl[d[i] & 0xF]; }
    hex[64] = 0;
    check("SHA256(\"abc\") matches test vector", strcmp(hex, abcHex) == 0);

    Sha256("", 0, d);
    for (i = 0; i < 32; i++) { hex[i * 2] = tbl[d[i] >> 4]; hex[i * 2 + 1] = tbl[d[i] & 0xF]; }
    hex[64] = 0;
    check("SHA256(\"\") matches test vector", strcmp(hex, emptyHex) == 0);

    /* 跨块（>64 字节）也要正确：用"增量喂"与"一次喂"比对 */
    {
        unsigned char big[200];
        unsigned char a[32], b[32];
        Sha256Ctx c;

        for (i = 0; i < 200; i++) big[i] = (unsigned char)(i * 7 + 3);

        Sha256(big, 200, a);
        Sha256_Init(&c);
        Sha256_Update(&c, big, 63);
        Sha256_Update(&c, big + 63, 1);
        Sha256_Update(&c, big + 64, 136);
        Sha256_Final(&c, b);

        check("SHA256 incremental == one-shot (200 bytes)", memcmp(a, b, 32) == 0);
    }
}

int main(void)
{
    printf("== detector_core / sha256 unit test ==\n\n");

    printf("-- 1) 不该命中的（防误报）--\n");
    case_manual_same_vehicle();
    case_pvp_two_vehicles();
    case_group_move();
    case_local_fields_not_ready();

    printf("\n-- 2) 应该命中的（防漏报）--\n");
    case_autoload_10_10();
    case_half_invalid();
    case_dedup_by_id();
    case_overflow();

    printf("\n-- 3) 阈值行为 --\n");
    case_ratio();
    case_min_events();

    printf("\n-- 4) 真实样本字节 --\n");
    case_real_bytes();

    printf("\n-- 5) SHA256 --\n");
    case_sha256();

    printf("\n----------------------------------------\n");
    printf("passed: %d   failures: %d\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
