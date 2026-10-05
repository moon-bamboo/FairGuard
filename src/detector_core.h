/*
 * FairGuard —— 《尤里的复仇》对手异常操作检测
 *
 * 作者：白月青竹
 *       DeepSeek-V4.1-Flash（AI 协作）
 * 许可：GPL-3.0，见仓库根目录的 LICENSE
 *
 * （以下是本文件自己的说明）
 */
/*
 * detector_core.h —— 「自动装车」判据核心
 *
 * ============================ 它是什么 ============================
 *
 * 把【判据】从探针代码里单独拆出来，做成不依赖任何引擎地址的纯算法：
 * 输入是原始事件字节，输出是"这一帧这个玩家是否可疑"。
 *
 * 这样做有两个好处：
 *   1) 可以直接用【真实样本字节】写单元测试（test/test_detector.c）——
 *      不必装进游戏、不必联机，就能验证判据算得对不对；
 *   2) 判据只有一份实现，检测器和测试不会各写一遍然后慢慢跑偏。
 *
 * ============================ 判据 ============================
 *
 *   同一帧内、同一玩家的一批 MegaMission(0x04) 事件里，
 *   「Destination 的不同取值个数」≈「Whom 的不同取值个数」
 *   ——即"每个单位配一辆不同载具" —— 判定为自动装车。
 *
 * 为什么是"逻辑必然"：要让 10 个单位各进 10 辆【不同】载具，玩家必须逐个
 * 点选（点单位A → 点载具A → 点单位B → 点载具B …）共 20 次点击，
 * 人手不可能把这些压进同一帧（一帧约 1/60 秒）。而插件能一次性下发。
 *
 * 实测对照（见 开发文档/03）：
 *     手动：多单位进【同一辆】载具        Destination 唯一值 = 1
 *     手动：PvP 技巧（进载具A + 进载具B） Destination 唯一值 = 2
 *     自动装车：10 单位配 10 辆           Destination 唯一值 = 10
 *   1 与 10 之间没有模糊地带。
 *
 * ============================ 字段偏移 ============================
 *
 * 来自 开发文档/01 的实地校准（用真实联机日志的原始字节对照得出）：
 *
 *     事件[0]        EventType   （本模块只接收 0x04 = MegaMission）
 *     事件[7..11]    Whom        TargetClass：ID(4) + RTTI(1)
 *     事件[12]       Mission     02=Move，07=Enter
 *     事件[19..23]   Destination TargetClass：ID(4) + RTTI(1)
 *
 * 本模块只取每个字段的前 4 字节 ID（RTTI 字节含义未深究，且不影响判据）。
 *
 * ============================ 两个刻意的保守设计 ============================
 *
 * 1) 【Whom 或 Destination 为 0 的事件被剔除，不计入有效集】
 *    实测：事件在【本机刚生成】的那一瞬间，Destination 等字段还没算出来，
 *    读到的全是 0（见 开发文档/01 第六节）。若把 0 当成一个正常取值，
 *    本机 10 条事件的 Destination 会"去重成 1"，虽然不会误报，
 *    但会掩盖真实情况。直接剔除更干净，也让日志里的 units/veh 数字可信。
 *
 * 2) 【去重集合溢出时不再增长】
 *    容量 64 远大于实测规模（最大 20），真溢出说明数据异常；
 *    此时"宁可不告警"也好过"拿截断后的集合去下结论"。
 */

#ifndef DETECTOR_CORE_H
#define DETECTOR_CORE_H

/* 事件内字段偏移（相对事件起点）—— 见 开发文档/01 第三节 */
#define DET_OFF_WHOM        7
#define DET_OFF_MISSION     12
#define DET_OFF_DEST        19

/* 命中时保留的事件字节数（只用于日志里回放那一批事件，便于人工复核）。
 * 24 字节正好覆盖到 Destination 的 4 字节 ID：
 *   [0]类型 [1]已执行 [2]房号 [3..6]帧号 [7..11]Whom [12]Mission [13]gap
 *   [14..18]Target [19..23]Destination */
#define DET_HEAD_SAVE       24

/* ⚠️ 1.3 起：事件字节**不再参与哈希链**（哈希链只用日志里可见的字段，
 *   这样校验工具才能独立重算 —— 见 FairGuard.c 的 ChainPush 注释）。
 *   heads 现在只供 [Detector] LogRaw=1 时输出 `detraw` 行，用于人工复核。 */

/* 单帧单玩家最多跟踪多少个不同的 Whom / Destination */
#define DET_MAX_UNIQ        64

/* Mission 枚举里我们关心的两个取值 */
#define DET_MISSION_MOVE    2      /* Move  —— ★ 不能用它判定（见文件头说明） */
#define DET_MISSION_ENTER   7      /* Enter —— ★ 判据只认它（默认 MissionFilter=7） */

/* ------------------------------------------------------------------
 * 一个玩家在【一帧内】的 MegaMission 统计
 * ------------------------------------------------------------------ */
typedef struct {
    int      nEvt;        /* 通过 Mission 过滤、且字段有效的条数（判据用这个） */
    int      nInvalid;    /* 字段未算出来（含 0）的条数 —— 本机事件就是这样 */
    int      nFiltered;   /* 被 MissionFilter 挡掉的条数（日志里可核对） */
    int      nWhom;       /* 去重后的 Whom 个数   = "几个单位" */
    int      nDest;       /* 去重后的 Destination 个数 = "几辆不同载具" */
    unsigned whom[DET_MAX_UNIQ];
    unsigned dest[DET_MAX_UNIQ];

    /* Mission 分布（全部事件，不受 MissionFilter 影响，仅用于日志） */
    int      nMove;       /* Mission == 2 的条数 */
    int      nEnter;      /* Mission == 7 的条数 */
    int      nOtherMission;

    int      nDup;        /* 去重时遇到"已有值"的次数 —— 正常现象，不是错误 */
    int      nOverflow;   /* 去重集合真的装不下了（>0 才是异常） */

    /* 命中时保留的事件字节（供 LogRaw=1 的 detraw 行回放，不参与哈希链） */
    unsigned char heads[DET_MAX_UNIQ * DET_HEAD_SAVE];
    int      nHeads;
} DetStat;

/* ------------------------------------------------------------------
 * 判据阈值
 * ------------------------------------------------------------------ */
typedef struct {
    int MinEvents;     /* 单帧该玩家至少要有这么多条有效 MegaMission */
    int MinDest;       /* Destination 至少要有这么多个【不同】取值 */
    int RatioPercent;  /* nDest 至少要达到 nWhom 的百分之几（50 = 宽容一半） */
} DetRule;

/* ------------------------------------------------------------------
 * 实现
 * ------------------------------------------------------------------ */

static inline void DetStat_Reset(DetStat* s)
{
    int i;
    s->nEvt = 0;
    s->nInvalid = 0;
    s->nFiltered = 0;
    s->nWhom = 0;
    s->nDest = 0;
    s->nMove = 0;
    s->nEnter = 0;
    s->nOtherMission = 0;
    s->nDup = 0;
    s->nOverflow = 0;
    s->nHeads = 0;
    for (i = 0; i < DET_MAX_UNIQ; i++) { s->whom[i] = 0; s->dest[i] = 0; }
}

/* 把一个值并进去重集合。
 * 返回  1 = 新增
 *       0 = 集合里已有这个值（Dup，完全正常 —— 多个单位进同一辆车就是这样）
 *      -1 = 集合满了（Overflow，才是真异常）
 *
 * ⚠️ 1.1 把"已存在"和"溢出"混在一起返回 0，日志里于是出现
 *    `OVERFLOW=10` 这种吓人的数字，其实只是在数重复值。
 *    1.2 分开返回，日志里 `dup=` 与 `ovf=` 各归各位。 */
static inline int DetAddUnique(unsigned* arr, int* n, int cap, unsigned v)
{
    int i;
    for (i = 0; i < *n; i++)
        if (arr[i] == v) return 0;
    if (*n < cap) { arr[*n] = v; (*n)++; return 1; }
    return -1;
}

/*
 * MissionFilter 判定：mask 为 0 表示"不过滤"；否则要求 bit[mission] 为 1。
 * （Mission 取值范围 0..47，这里只覆盖低 32 位；超出的一律不放行 ——
 *   宁可少报，也不要拿语义不明的 Mission 去下结论。）
 */
static inline int DetMissionAllowed(unsigned char mission, unsigned mask)
{
    if (mask == 0) return 1;
    if (mission >= 32) return 0;
    return ((mask >> mission) & 1u) ? 1 : 0;
}

/*
 * 吃进一条【原始事件字节】（至少 DET_OFF_DEST + 4 = 23 字节可读）。
 * 调用方负责筛掉：Type != 0x04、已执行、Frame != 当前帧。
 *
 * missionMask 见 DetMissionAllowed：只有通过过滤的事件才计入 nEvt /
 * nWhom / nDest（判据看的那三个数）；Mission 分布始终统计全部，
 * 这样日志里能看出"这一帧有 20 条 Move 被挡掉了"。
 */
static inline void DetStat_Feed(DetStat* s, const unsigned char* ev, unsigned missionMask)
{
    unsigned      whom = *(const unsigned*)(ev + DET_OFF_WHOM);
    unsigned      dest = *(const unsigned*)(ev + DET_OFF_DEST);
    unsigned char mission = ev[DET_OFF_MISSION];
    int           r;

    /* 头部样本（哈希链 + 命中回放用）。份数满了就不再收，不影响判据。 */
    if (s->nHeads < DET_MAX_UNIQ)
    {
        unsigned char* p = s->heads + (s->nHeads * DET_HEAD_SAVE);
        int i;
        for (i = 0; i < DET_HEAD_SAVE; i++) p[i] = ev[i];
        s->nHeads++;
    }

    if      (mission == DET_MISSION_MOVE)  s->nMove++;
    else if (mission == DET_MISSION_ENTER) s->nEnter++;
    else                                   s->nOtherMission++;

    /* ★ 字段还没算出来（本机刚生成的事件）—— 剔除，不参与判据 */
    if (!whom || !dest) { s->nInvalid++; return; }

    /* ★ Mission 过滤：默认只放行 Enter(7)，把 Move 等语义不同的命令挡在外面 */
    if (!DetMissionAllowed(mission, missionMask)) { s->nFiltered++; return; }

    s->nEvt++;

    r = DetAddUnique(s->whom, &s->nWhom, DET_MAX_UNIQ, whom);
    if (r == 0) s->nDup++; else if (r < 0) s->nOverflow++;

    r = DetAddUnique(s->dest, &s->nDest, DET_MAX_UNIQ, dest);
    if (r == 0) s->nDup++; else if (r < 0) s->nOverflow++;
}

/*
 * 判据。返回 1 = 命中（疑似自动装车）。
 *
 * 三个条件同时成立：
 *   nEvt  >= MinEvents        —— 规模够大（小规模不判，避免噪音）
 *   nDest >= MinDest          —— 真的打给了多辆【不同】载具
 *   nDest/nWhom >= Ratio      —— 接近"一单位一载具"（默认允许打对折）
 *
 * 反例验算（默认 MinEvents=5, MinDest=3, RatioPercent=0，且只判 Enter）：
 *   手动 10 单位进 1 辆载具       : nWhom=10 nDest=1  -> nDest<3   不命中 ✓
 *   手动 PvP 技巧两辆             : nWhom=11 nDest=2  -> nDest<3   不命中 ✓
 *   框选 20 单位路径点移动         : 全被 MissionFilter 挡掉，nEvt=0  不命中 ✓
 *   自动装车 20 单位 3 辆         : nWhom=20 nDest=3  -> 3>=3       命中 ✓
 *   自动装车 10 单位 10 辆        : nWhom=10 nDest=10 -> 10>=3      命中 ✓
 *
 * ⚠️ RatioPercent 默认改成 0（不检查）。1.1 用 50% 时，"20 单位进 3 辆载具"
 *    （3/20 = 15%）会被比例条件挡掉，而用户实测认为这该报。
 *    只判 Enter 之后比例条件意义不大（人手无法同帧点多个不同载具），
 *    想开启就设 RatioPercent（50 = 至少要有"半个单位数"那么多的不同载具）。
 */
static inline int DetStat_Judge(const DetStat* s, const DetRule* r)
{
    if (s->nEvt < r->MinEvents) return 0;
    if (s->nDest < r->MinDest)  return 0;
    if (s->nWhom <= 0)          return 0;

    if (r->RatioPercent > 0)
    {
        /* nDest/nWhom >= RatioPercent/100  <=>  nDest*100 >= nWhom*RatioPercent */
        if ((long long)s->nDest * 100 < (long long)s->nWhom * r->RatioPercent) return 0;
    }

    return 1;
}

#endif /* DETECTOR_CORE_H */
