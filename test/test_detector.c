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
 * ============================ 1.2 的两处修正（都有实测依据）============================
 *
 * ① **只对 Mission=7(Enter) 判定**（`MissionFilter`，默认 "7"）
 *
 *   1.1 对所有 MegaMission 一视同仁，把用户的"路径点模式移动"整批报成了自动装车。
 *   用户 2026-10-05 的真实日志里 20 次命中**无一例外** `Enter=0`：
 *       *** DETECT f=10321 h=0 units=20 veh=10 MM=20 (Move=20 Enter=0 Other=0)
 *   原因：Move 的目标是【格子】，路径点模式下引擎会给每个单位展开各自的目标格，
 *   Destination 于是天然分散（20 个单位给出 10 个不同值）；而 Enter 的目标是
 *   【载具本体】，手动=1、自动=单位数 —— 判据只在后者成立。
 *
 *   `case_pathway_move_false_positive()` 就是这个场景的回归用例，
 *   并且把"旧行为确实会误报"也固化下来，免得有人把默认值改回去。
 *
 * ② **阈值 MinDest 5→3、RatioPercent 50→0**
 *
 *   用户实测"20 个单位 + 3 辆 6 容量载具自动装车"漏报：nDest 只有 3，
 *   被 MinDest=5 和比例条件（3/20=15% < 50%）双重挡掉。
 *   只判 Enter 之后比例条件已无必要（人手无法同帧点多个不同载具），
 *   默认关掉；MinDest=3 让"多单位混装"也能抓到，而 2 辆（人力可为）仍不报。
 *   见 `case_autoload_3_vehicles()`。
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

/* 默认阈值：与 FairGuard.ini 的 [Detector] 默认值一致
 * （1.2：MinDest 5->3、RatioPercent 50->0，理由见 case_autoload_3_vehicles） */
static DetRule DefaultRule(void)
{
    DetRule r;
    r.MinEvents    = 5;
    r.MinDest      = 3;
    r.RatioPercent = 0;
    return r;
}

/* Mission 过滤掩码：默认配置 = 只判 Enter(7)（1.2 的修正） */
#define MASK_ENTER  (1u << DET_MISSION_ENTER)
#define MASK_NONE   0u

/* 把 n 条事件喂进一个统计里（mask 见 DetMissionAllowed） */
static void feed_all(DetStat* s, unsigned char (*evs)[111], int n, unsigned mask)
{
    int i;
    DetStat_Reset(s);
    for (i = 0; i < n; i++) DetStat_Feed(s, evs[i], mask);
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

    feed_all(&s, evs, 10, MASK_ENTER);

    check("manual/10 units -> 1 vehicle : nWhom = 10", s.nWhom == 10);
    check("manual/10 units -> 1 vehicle : nDest = 1",  s.nDest == 1);
    check("manual/10 units -> 1 vehicle : NOT a hit",  DetStat_Judge(&s, &r) == 0);
}

/* ② 手动 PvP 技巧：进载具A + 路径点进载具B（实测 nWhom=11, nDest=2）—— 不能命中
 *
 * 数据来自 开发文档/03 的实测表（16:30:41 帧 21232：`02x10 0Bx1`）。
 * 注意它是 **Move**（`02`）+ **Area_Guard**（`0B`），所以 1.2 的默认配置
 * （只判 Enter）连判都不判它 —— 两道防线都验证一遍。 */
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

    /* (a) 先看事件本身的形态（不过滤）：11 个不同单位，只打给 2 个不同目标 */
    feed_all(&s, evs, 11, MASK_NONE);
    check("PvP trick (2 vehicles) : nWhom = 11", s.nWhom == 11);
    check("PvP trick (2 vehicles) : nDest = 2",  s.nDest == 2);
    check("PvP trick : NOT a hit (nDest < MinDest)", DetStat_Judge(&s, &r) == 0);

    /* (b) 默认配置（只判 Enter）：这类命令整批不参与判据 */
    feed_all(&s, evs, 11, MASK_ENTER);
    check("PvP trick : all filtered by MissionFilter", s.nFiltered == 11 && s.nEvt == 0);
    check("PvP trick : NOT a hit (1.2 default)",       DetStat_Judge(&s, &r) == 0);
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

    /* (a) 不过滤时：10 个单位却只有 1 个目的地 -> 靠 MinDest 就挡住了 */
    feed_all(&s, evs, 10, MASK_NONE);
    check("group move to one cell : nDest = 1", s.nDest == 1);
    check("group move : NOT a hit (nDest < MinDest)", DetStat_Judge(&s, &r) == 0);

    /* (b) 默认配置：根本不放行 Move */
    feed_all(&s, evs, 10, MASK_ENTER);
    check("group move : all filtered by MissionFilter", s.nFiltered == 10 && s.nEvt == 0);
    check("group move : NOT a hit (1.2 default)",       DetStat_Judge(&s, &r) == 0);
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

    feed_all(&s, evs, 10, MASK_ENTER);

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

    feed_all(&s, evs, 10, MASK_ENTER);

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

    feed_all(&s, evs, 10, MASK_ENTER);

    check("half invalid : nEvt = 5",  s.nEvt == 5);
    check("half invalid : nDest = 5", s.nDest == 5);
    /* 5 >= MinEvents(5) 且 5 >= MinDest(5) 且 5*2 >= 5 -> 命中
     * 这是刻意的：有效证据达到阈值就该报，无效条目只是被剔除 */
    check("half invalid : IS a hit (5 valid pairs)", DetStat_Judge(&s, &r) == 1);
}

/* ⑦ 比例条件（RatioPercent）：1.2 默认关闭（0），这一段验证"关"和"开"的差别 */
static void case_ratio(void)
{
    unsigned char evs[20][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    /* 20 单位配 3 辆 —— 默认（不检查比例）应当命中 */
    for (i = 0; i < 20; i++)
        mk_event(evs[i], 1, 1, 6000u + (unsigned)i, DET_MISSION_ENTER, 950u + (unsigned)(i % 3));
    feed_all(&s, evs, 20, MASK_ENTER);
    check("ratio off (1.2 default) : 3/20 IS a hit", s.nDest == 3 && DetStat_Judge(&s, &r) == 1);

    /* 把比例条件打开到 50%：3/20 = 15% 就过不了了 —— 这正是 1.1 漏报的原因 */
    r.RatioPercent = 50;
    check("ratio 50% : 3/20 NOT a hit (this is why 1.1 missed it)", DetStat_Judge(&s, &r) == 0);

    /* 10 单位配 5 辆 = 恰好 50%，踩线应当命中 */
    r.MinDest = 5;
    for (i = 0; i < 10; i++)
        mk_event(evs[i], 1, 1, 6000u + (unsigned)i, DET_MISSION_ENTER, 950u + (unsigned)(i % 5));
    feed_all(&s, evs, 10, MASK_ENTER);
    check("ratio 50% : 5/10 IS a hit (exactly on the line)",
          s.nDest == 5 && DetStat_Judge(&s, &r) == 1);
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
    feed_all(&s, evs, 3, MASK_ENTER);

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
    DetStat_Feed(&s, sample, MASK_NONE);   /* 这里测的是字段解析，关掉过滤 */

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
    feed_all(&s, evs, 10, MASK_ENTER);
    check("dedup ignores RTTI byte : nDest = 10", s.nDest == 10);
    check("dedup ignores RTTI byte : IS a hit",   DetStat_Judge(&s, &r) == 1);
}

/*
 * ⑪ 去重集合溢出：超过 DET_MAX_UNIQ 条不同值时集合不再增长，
 *    判据不能凭空命中、也不能崩。
 *    顺带验证 1.2 修好的 dup / overflow 区分（1.1 把"重复"也报成 OVERFLOW）。
 */
static void case_overflow(void)
{
    static unsigned char evs[DET_MAX_UNIQ + 20][111];
    DetStat s;
    DetRule r;
    int i;

    for (i = 0; i < DET_MAX_UNIQ + 20; i++)
        mk_event(evs[i], 1, 1, 9000u + (unsigned)i, DET_MISSION_ENTER, 1100u + (unsigned)i);

    DetStat_Reset(&s);
    for (i = 0; i < DET_MAX_UNIQ + 20; i++) DetStat_Feed(&s, evs[i], MASK_ENTER);

    check("overflow : nWhom capped at DET_MAX_UNIQ", s.nWhom == DET_MAX_UNIQ);
    check("overflow : nDest capped at DET_MAX_UNIQ", s.nDest == DET_MAX_UNIQ);
    check("overflow : nEvt still counts all",        s.nEvt == DET_MAX_UNIQ + 20);
    check("overflow : nOverflow counted",            s.nOverflow > 0);
    check("overflow : no false dup",                 s.nDup == 0);

    /* 默认阈值（MinDest=3, Ratio=0）下仍然命中 —— 集合被截断但依然高度可疑 */
    r = DefaultRule();
    check("overflow : still a hit (capped but consistent)", DetStat_Judge(&s, &r) == 1);
}

/*
 * ⑫ ★ 回归：用户实测的**误报**场景
 *
 * 用户操作："选中 20 个单位，进入路径点模式，移动到某个点" -> 1.1 误报。
 *
 * 数据取自用户 2026-10-05 20:17 的真实日志：
 *     *** DETECT f=10321 h=0 units=20 veh=10 MM=20 (Move=20 Enter=0 Other=0)
 *
 * 20 个单位、同一次操作，Destination 却有 10 个不同值 —— 因为 **Move 的目标是
 * 格子，路径点模式下引擎给每个单位展开各自的目标格**。这跟手速无关。
 *
 * 期望：
 *   - 用默认的 MissionFilter（只判 Enter）-> **不命中** ✓（任务过滤挡掉）
 *   - 用 MissionFilter=0（1.1 的旧行为） -> 会命中（说明旧行为确实误报）
 */
static void case_pathway_move_false_positive(void)
{
    unsigned char evs[20][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    /* 20 个单位，每个单位各自一个"目标格"（复现日志里 veh 分散的样子） */
    for (i = 0; i < 20; i++)
        mk_event(evs[i], 0, 10321, 500u + (unsigned)i, DET_MISSION_MOVE, 700u + (unsigned)(i / 2));

    /* 默认配置：只判 Enter -> 20 条 Move 全被挡掉 */
    feed_all(&s, evs, 20, MASK_ENTER);
    check("pathway move : all filtered by MissionFilter", s.nFiltered == 20);
    check("pathway move : nEvt = 0",                      s.nEvt == 0);
    check("pathway move : NOT a hit (1.2 default)",       DetStat_Judge(&s, &r) == 0);

    /* 旧行为（MissionFilter=0）确实会误报 —— 把这个事实固化成用例，
     * 免得以后有人"顺手"把默认值改回 0 */
    feed_all(&s, evs, 20, MASK_NONE);
    check("pathway move : old behaviour (no filter) DID hit", DetStat_Judge(&s, &r) == 1);
}

/*
 * ⑬ ★ 回归：用户实测的**漏报**场景（改成应该命中）
 *
 * 用户操作："选中 20 个单位和三辆 6 容量的载具，使用自动装车" -> 1.1 没报。
 * 原因：nDest 只有 3（3 辆载具），被 MinDest=5 和 RatioPercent=50（3/20=15%）双重挡掉。
 *
 * 1.2 的默认值（MinDest=3, RatioPercent=0）应当命中：
 * 人手不可能在同一帧里点中 3 辆**不同**的载具。
 */
static void case_autoload_3_vehicles(void)
{
    unsigned char evs[20][111];
    DetStat s;
    DetRule r = DefaultRule();
    int i;

    for (i = 0; i < 20; i++)
        mk_event(evs[i], 0, 26548, 6000u + (unsigned)i, DET_MISSION_ENTER, 300u + (unsigned)(i % 3));

    feed_all(&s, evs, 20, MASK_ENTER);

    check("autoload 20 units / 3 vehicles : nEvt = 20", s.nEvt == 20);
    check("autoload 20 units / 3 vehicles : nWhom = 20", s.nWhom == 20);
    check("autoload 20 units / 3 vehicles : nDest = 3",  s.nDest == 3);
    check("autoload 20 units / 3 vehicles : dup counted", s.nDup > 0);
    check("autoload 20 units / 3 vehicles : IS a hit (1.2 default)", DetStat_Judge(&s, &r) == 1);

    /* 而 2 辆（PvP 技巧那种规模）仍然不报 —— 人力可为，留出容错 */
    for (i = 0; i < 20; i++)
        mk_event(evs[i], 0, 26548, 6000u + (unsigned)i, DET_MISSION_ENTER, 300u + (unsigned)(i % 2));
    feed_all(&s, evs, 20, MASK_ENTER);
    check("20 units / 2 vehicles : nDest = 2, NOT a hit", s.nDest == 2 && DetStat_Judge(&s, &r) == 0);
}

/*
 * ⑭ MissionFilter 的边界：多个 Mission、以及非法/超范围取值
 */
static void case_mission_filter(void)
{
    unsigned char evs[8][111];
    DetStat s;
    int i;

    for (i = 0; i < 4; i++)
        mk_event(evs[i], 1, 1, 100u + (unsigned)i, DET_MISSION_ENTER, 200u + (unsigned)i);
    for (i = 4; i < 8; i++)
        mk_event(evs[i], 1, 1, 100u + (unsigned)i, DET_MISSION_MOVE, 200u + (unsigned)i);

    /* 只放行 Enter -> 4 条有效、4 条被过滤 */
    feed_all(&s, evs, 8, MASK_ENTER);
    check("filter Enter only : nEvt = 4",     s.nEvt == 4);
    check("filter Enter only : nFiltered = 4", s.nFiltered == 4);
    check("filter Enter only : Mission 分布仍记全部", s.nEnter == 4 && s.nMove == 4);

    /* 同时放行 Enter + Move -> 8 条有效 */
    feed_all(&s, evs, 8, (1u << DET_MISSION_ENTER) | (1u << DET_MISSION_MOVE));
    check("filter Enter+Move : nEvt = 8",      s.nEvt == 8);
    check("filter Enter+Move : nFiltered = 0", s.nFiltered == 0);

    /* mask = 0 -> 不过滤 */
    feed_all(&s, evs, 8, MASK_NONE);
    check("filter off : nEvt = 8", s.nEvt == 8);

    /* 判断函数本身：超范围 Mission 一律不放行（宁可少报） */
    check("DetMissionAllowed : Enter allowed with default mask",
          DetMissionAllowed(DET_MISSION_ENTER, MASK_ENTER) == 1);
    check("DetMissionAllowed : Move rejected with default mask",
          DetMissionAllowed(DET_MISSION_MOVE, MASK_ENTER) == 0);
    check("DetMissionAllowed : mask 0 allows everything",
          DetMissionAllowed(0x2B, 0) == 1);
    check("DetMissionAllowed : out-of-range mission rejected",
          DetMissionAllowed(40, MASK_ENTER) == 0);
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
    case_pathway_move_false_positive();
    case_local_fields_not_ready();

    printf("\n-- 2) 应该命中的（防漏报）--\n");
    case_autoload_10_10();
    case_autoload_3_vehicles();
    case_half_invalid();
    case_dedup_by_id();
    case_overflow();

    printf("\n-- 3) 阈值与 Mission 过滤 --\n");
    case_ratio();
    case_min_events();
    case_mission_filter();

    printf("\n-- 4) 真实样本字节 --\n");
    case_real_bytes();

    printf("\n-- 5) SHA256 --\n");
    case_sha256();

    printf("\n----------------------------------------\n");
    printf("passed: %d   failures: %d\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
