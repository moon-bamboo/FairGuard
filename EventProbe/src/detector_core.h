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

/* 参与哈希链的事件头部长度：+0..+12
 * （为什么不是整条：Destination 之后两台机器不一样——那是本地状态，
 *   只有头部在各客户端上逐字节一致，见 开发文档/06 第 3.4 节） */
#define DET_HEAD_HASH       13

/* 单帧单玩家最多跟踪多少个不同的 Whom / Destination */
#define DET_MAX_UNIQ        64

/* Mission 枚举里我们关心的两个取值 */
#define DET_MISSION_MOVE    2      /* Move  —— 自动装车"先走到载具附近"时用 */
#define DET_MISSION_ENTER   7      /* Enter —— 手动装车用它 */

/* ------------------------------------------------------------------
 * 一个玩家在【一帧内】的 MegaMission 统计
 * ------------------------------------------------------------------ */
typedef struct {
    int      nEvt;        /* 有效条数（Whom、Destination 都非 0） */
    int      nInvalid;    /* 字段未算出来（含 0）的条数 —— 本机事件就是这样 */
    int      nWhom;       /* 去重后的 Whom 个数   = "几个单位" */
    int      nDest;       /* 去重后的 Destination 个数 = "几辆不同载具" */
    unsigned whom[DET_MAX_UNIQ];
    unsigned dest[DET_MAX_UNIQ];

    int      nMove;       /* Mission == 2 的条数（仅用于日志展示） */
    int      nEnter;      /* Mission == 7 的条数 */
    int      nOtherMission;
    int      nOverflow;   /* 去重集合溢出次数（>0 说明数据异常） */

    /* 命中时保留的事件字节（只对前 DET_HEAD_HASH 字节做哈希，见文件头说明） */
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
    s->nWhom = 0;
    s->nDest = 0;
    s->nMove = 0;
    s->nEnter = 0;
    s->nOtherMission = 0;
    s->nOverflow = 0;
    s->nHeads = 0;
    for (i = 0; i < DET_MAX_UNIQ; i++) { s->whom[i] = 0; s->dest[i] = 0; }
}

/* 把一个值并进去重集合；返回 1 = 新增，0 = 已存在或溢出 */
static inline int DetAddUnique(unsigned* arr, int* n, int cap, unsigned v)
{
    int i;
    for (i = 0; i < *n; i++)
        if (arr[i] == v) return 0;
    if (*n < cap) { arr[*n] = v; (*n)++; return 1; }
    return 0;
}

/*
 * 吃进一条【原始事件字节】（至少 DET_OFF_DEST + 4 = 23 字节可读）。
 * 调用方负责筛掉：Type != 0x04、已执行、Frame != 当前帧。
 */
static inline void DetStat_Feed(DetStat* s, const unsigned char* ev)
{
    unsigned      whom = *(const unsigned*)(ev + DET_OFF_WHOM);
    unsigned      dest = *(const unsigned*)(ev + DET_OFF_DEST);
    unsigned char mission = ev[DET_OFF_MISSION];

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

    s->nEvt++;

    if (!DetAddUnique(s->whom, &s->nWhom, DET_MAX_UNIQ, whom)) s->nOverflow++;
    if (!DetAddUnique(s->dest, &s->nDest, DET_MAX_UNIQ, dest)) s->nOverflow++;
}

/*
 * 判据。返回 1 = 命中（疑似自动装车）。
 *
 * 三个条件同时成立：
 *   nEvt  >= MinEvents        —— 规模够大（小规模不判，避免噪音）
 *   nDest >= MinDest          —— 真的打给了多辆【不同】载具
 *   nDest/nWhom >= Ratio      —— 接近"一单位一载具"（默认允许打对折）
 *
 * 反例验算（默认 MinEvents=5, MinDest=5, Ratio=50）：
 *   手动 10 单位进 1 辆载具 : nWhom=10 nDest=1  -> nDest<5        不命中 ✓
 *   手动 PvP 技巧两辆       : nWhom=11 nDest=2  -> nDest<5        不命中 ✓
 *   框选 10 单位点地面移动   : nWhom=10 nDest=1  -> nDest<5        不命中 ✓
 *   自动装车 10 单位 10 辆   : nWhom=10 nDest=10 -> 10>=5 且 2*10>=10 命中 ✓
 */
static inline int DetStat_Judge(const DetStat* s, const DetRule* r)
{
    if (s->nEvt < r->MinEvents) return 0;
    if (s->nDest < r->MinDest)  return 0;
    if (s->nWhom <= 0)          return 0;

    /* nDest/nWhom >= RatioPercent/100  <=>  nDest*100 >= nWhom*RatioPercent */
    if ((long long)s->nDest * 100 < (long long)s->nWhom * r->RatioPercent) return 0;

    return 1;
}

#endif /* DETECTOR_CORE_H */
