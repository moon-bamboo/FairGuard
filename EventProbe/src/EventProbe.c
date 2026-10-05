/*
 * EventProbe.c - 《尤里的复仇》事件队列探针 + 自动装车检测器
 *
 * ============================ 用途 ============================
 *
 * 本 DLL 里有两件东西，共用同一个取样钩子、同一份事件数据：
 *
 *   [探针 Probe]     按【玩家】统计"每个逻辑帧下达了多少条命令"，写日志。
 *                    用于回答"地址对不对 / 正常人的命令量基线是多少"。
 *                    默认开启，可以用 EventProbe.ini 关掉。
 *
 *   [检测器 Detector] 实时判据：同一帧内某玩家的一批 MegaMission 事件里，
 *                    若「Destination 的不同取值个数」≈「Whom 的不同取值个数」
 *                    （= 每个单位配一辆【不同】载具），就判定为自动装车，
 *                    在屏幕上提示 + 写进带哈希链的日志。
 *
 * ★ 为什么两件事合在一个 DLL 里，而不是做成两个插件：
 *   两者都要钩 0x64C38D / 0x55D360。Syringe 对【同一地址】的多次 hook
 *   是后装覆盖先装，两个 DLL 各钩一次必然有一个哑掉甚至崩溃。
 *   合在一个 DLL 里是唯一稳妥的做法。
 *
 * ---------------------------- 判据为什么是"逻辑必然" ----------------------------
 *
 *  要让 10 个单位各自进入 10 辆【不同】的载具，玩家必须逐个操作：
 *     点单位A → 点载具A → 点单位B → 点载具B …… 共 20 次点击
 *  人手无法把这些压进同一帧（约 1/60 秒）。插件能，因为它一次下发一批。
 *
 *  实测对照（开发文档/03）：
 *     手动：多单位进同一辆载具     Destination 唯一值 = 1
 *     手动：PvP 技巧（两辆）       Destination 唯一值 = 2
 *     自动装车：10 单位配 10 辆    Destination 唯一值 = 10
 *
 * ---------------------------- 安全性 ----------------------------
 *
 * 只【读】DoList；不写任何游戏状态、不发送任何事件、不修改任何指令。
 * 屏幕上那条提示走 MessageListClass::AddMessage —— 那是引擎自己的
 * "本地提示消息"通道（快捷键提示、结盟提示都走它），属于纯本地 UI，
 * 不进事件队列，因此【不会造成不同步】。
 *
 * 所以：只要自己装，联机时对手无须安装。
 *
 * ---------------------------- 构建 ----------------------------
 *
 *    build.bat   (32 位 mingw + -nostdlib，无 CRT)
 *
 * 产物: EventProbe.dll + EventProbe.dll.inj  ->  放进游戏根目录
 * 日志: <游戏目录>\MsgLog\EventProbe_YYYY-MM-DD_HH-MM-SS.log
 *
 * 单元测试:
 *    test/test_detector.c  判据算法（用真实样本字节，不需要游戏）
 *    test/test_load.c      DLL 加载 / 导出 / 握手自检
 */

#include <windows.h>

#include "detector_core.h"   /* 判据核心：纯算法，可单测 */
#include "sha256.h"          /* 哈希链用的 SHA-256 */

#define PROBE_VERSION   "1.1"

/* ==================================================================
 * 1. 地址常量
 * ================================================================== */

/* 事件队列 —— 所有玩家（含远程）待执行的事件都在这里。
 * 来源: YRpp/EventClass.h:17  DEFINE_REFERENCE(QueueClass<EventClass, MAX_EVENTS*128>, DoList, 0x008B41F8)
 * RAReplayPlugin 的 src/game_api/GameApi.cpp:65-91 也是这么读的。 */
#define ADDR_DOLIST           0x008B41F8u

/* 本机待发送队列（用来和 DoList 对照，看"我发的"与"大家发的"） */
#define ADDR_OUTLIST          0x00A802C8u

/* Unsorted::CurrentFrame —— 全局逻辑帧号（ChatBox/AutoKit/Rareplay 同址） */
#define ADDR_CURRENT_FRAME    0x00A8ED84u

/* ==================================================================
 * 屏幕提示用的引擎通道
 * ==================================================================
 *
 * 借用 MessageListClass::AddMessage @ 0x005D3BA0 —— 游戏里所有文本消息的
 * 唯一入口 —— 来显示告警。地址、调用约定、为什么不用自己画的理由，
 * 全部写在 engine_abi.h 里（那份 typedef 有 test/test_abi.c 专门验证）。 */
#include "engine_abi.h"

/* ==================================================================
 * 2. 结构布局
 * ================================================================== */

/*  QueueClass<T,size> 的字段顺序（YRpp/QueueClass.h:52-58）：
 *
 *      int Count;          // +0x00
 *      int Head;           // +0x04
 *      int Tail;           // +0x08
 *      T   Array[size];    // +0x0C   <- 步长 sizeof(T)
 *      int Timings[size];  // Array 之后
 *
 *  自校验: 对 DoList(size=16384) 而言
 *      Array    = 0x8B41F8 + 0x0C = 0x8B4204
 *      Timings  = 0x8B4204 + 16384*111 = 0xA70204
 *      结束于   = 0xA70204 + 16384*4   = 0xA80204
 *  而 0xA80208 是已知的 ParticleSystemClass::Array —— 严丝合缝。
 *  这条算术是判断"地址没错"的最有力依据。 */
#define Q_OFF_COUNT           0x00
#define Q_OFF_HEAD            0x04
#define Q_OFF_TAIL            0x08
#define Q_OFF_ARRAY           0x0C

/*  EventClass（YRpp/EventClass.h:154-157，有编译期断言
 *  sizeof==111 / offsetof(Frame)==3 / offsetof(DataBuffer)==7）：
 *
 *      EventType    Type;         // +0   操作类型
 *      bool         IsExecuted;   // +1
 *      char         HouseIndex;   // +2   ★哪个玩家 (-1 = 无效)
 *      unsigned int Frame;        // +3   ★该命令在第几帧执行
 *      union { char DataBuffer[104]; ... };  // +7 具体参数
 *
 *  注意: 只有头部这 4 个字段是有断言保证的。
 *        DataBuffer 里的内容（Mission / Destination 等）【未经校准】，
 *        本探针刻意【不解析】它们 —— 只 dump 原始字节供人工对照。 */
#define EVENT_SIZE            111
#define EVT_OFF_TYPE          0
#define EVT_OFF_EXEC          1
#define EVT_OFF_HOUSE         2
#define EVT_OFF_FRAME         3
#define EVT_OFF_DATA          7

#define DOLIST_CAPACITY       16384

/* 一次最多统计多少条（防越界；DoList 容量就是 16384） */
#define MAX_SCAN              16384
#define MAX_HOUSES            16

/* ==================================================================
 * 3. 配置
 * ================================================================== */

typedef struct {
    int Enable;        /* Enable=1        总开关 */
    int DumpRaw;       /* DumpRaw=0       1 = 每条事件输出原始 hex（校准偏移用） */
    int DumpBytes;     /* DumpBytes=32    每条 dump 前多少字节 */
    int BurstOps;      /* BurstOps=5      单帧"操作类"命令数达到它就告警 */
    int LogEveryFrame; /* LogEveryFrame=0 1 = 连空帧也记一行（看心跳） */
    int LogUtf8;       /* LogUtf8=0       1 = 日志用 UTF-8 带 BOM */
} ProbeConfig;

/* 检测器配置（EventProbe.ini 的 [Detector] 段） */
typedef struct {
    int  Enable;          /* 总开关 */
    int  MinEvents;       /* 单帧最少有效 MegaMission 条数 */
    int  MinDest;         /* 单帧最少 Destination 不同取值数 */
    int  RatioPercent;    /* nDest 至少要达到 nWhom 的百分之几 */
    int  ShowAlert;       /* 是否在屏幕上提示 */
    int  AlertSeconds;    /* 提示停留秒数 */
    int  LogRaw;          /* 命中时是否把该批事件逐条写原始 hex */
    int  WindowFrames;    /* 滑动窗口长度（帧） */
    int  WindowHits;      /* 窗口内命中多少次就升级告警 */
    int  HashChain;       /* 是否启用哈希链 */
    int  SummaryEvery;    /* 每多少帧输出一次汇总（0 = 只在对局结束时输出） */
    int  IgnoreHouseMask; /* 位掩码：要忽略的房号（AI 常在这里） */
    int  IgnoreList;      /* IgnoreHouses= 里是否填过东西（填了就覆盖掩码） */
} DetConfig;

static ProbeConfig g_Cfg;
static DetConfig   g_DetCfg;
static DetRule     g_Rule;

static char g_Dir[MAX_PATH];
static char g_LogPath[MAX_PATH];
static HANDLE g_Log = NULL;
static int   g_Inited = 0;
static int   g_LogFailed = 0;

/* ==================================================================
 * 4. 无 CRT 工具函数
 * ================================================================== */

/* 无符号整数 -> 十进制，返回写入长度 (缓冲区至少 12 字节) */
static unsigned UtoA(unsigned v, char* p)
{
    char tmp[12];
    int  i = 0, n = 0;

    if (v == 0) { p[0] = '0'; return 1; }
    while (v && i < 12) { tmp[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i > 0) p[n++] = tmp[--i];
    return (unsigned)n;
}

/* 无符号整数 -> 十六进制（不定长，至少 digits 位），返回长度。
 *
 * ⚠️ 末尾一定要补 '\0'：
 *    有的调用点直接写进缓冲区中段(d += HtoA(x, d, 2))，多出的终止符会被
 *    下一次写入覆盖，无害；但另有调用点是"先写进临时数组、再当字符串追加"，
 *    那种情况没有终止符就会读到栈上的垃圾。
 *    早期版本漏了这一步，日志里于是出现
 *        DoList=<=1 DumpR008B41F8C:\Users...
 *    这样的乱码 —— 正是读到了 hx[] 后面的栈残留。 */
static unsigned HtoA(unsigned v, char* p, int digits)
{
    static const char* hex = "0123456789ABCDEF";
    char tmp[16];
    int  i = 0, n = 0;

    if (v == 0) tmp[i++] = '0';
    while (v && i < 16) { tmp[i++] = hex[v & 0xF]; v >>= 4; }
    while (i < digits && i < 16) tmp[i++] = '0';
    while (i > 0) p[n++] = tmp[--i];
    p[n] = 0;
    return (unsigned)n;
}

/* 字符串拼接（都带边界检查，返回新的写入位置） */
static char* AppStr(char* d, const char* s, char* end)
{
    while (*s && d < end) *d++ = *s++;
    return d;
}
static char* AppCh(char* d, char c, char* end)
{
    if (d < end) *d++ = c;
    return d;
}

/* 有符号/无符号整数的便捷追加。
 * ⚠️ UtoA 不检查边界（它只负责把自己那几位写出来），所以这里必须先留足余量。
 *    整数最长 11 位（含符号），留 14 字节。 */
static char* AppNum(char* d, int v, char* end)
{
    if (d + 14 > end) return end;
    if (v < 0) { d = AppCh(d, '-', end); v = -v; }
    d += UtoA((unsigned)v, d);
    return d;
}

static int StrLen(const char* s) { int n = 0; while (s[n]) n++; return n; }

/* ---- 宽字符版本（屏幕提示要用 wchar_t）----
 * mingw 的 wchar_t 是 16 位（与 Windows 一致），所以这里可以直接当
 * UTF-16 码元数组处理。中文宽字面量靠编译选项
 *     -finput-charset=UTF-8 -fwide-exec-charset=UTF-16LE
 * 保证编码正确（build.bat 里已加）。 */

static wchar_t* AppWide(wchar_t* d, const wchar_t* s, wchar_t* end)
{
    while (*s && d < end) *d++ = *s++;
    return d;
}

static wchar_t* AppWideNum(wchar_t* d, int v, wchar_t* end)
{
    wchar_t tmp[12];
    int i = 0, n = 0;

    if (d + 14 > end) return end;
    if (v < 0) { *d++ = L'-'; v = -v; }
    if (v == 0) tmp[i++] = L'0';
    while (v && i < 12) { tmp[i++] = (wchar_t)(L'0' + (v % 10)); v /= 10; }
    while (i > 0) d[n++] = tmp[--i];
    return d + n;
}

/* ==================================================================
 * 5. 日志
 * ================================================================== */

/* 日志路径: <游戏目录>\MsgLog\EventProbe_<时间>.log
 * 游戏目录 = gamemd.exe 所在目录（取本 DLL 的路径再往上一层）。 */
static void BuildPaths(void)
{
    char  dll[MAX_PATH];
    DWORD n;
    char* p;
    SYSTEMTIME st;
    char  b[8];
    char* d;
    char* end = g_LogPath + sizeof(g_LogPath) - 2;

    if (g_Dir[0]) return;

    dll[0] = 0;
    n = GetModuleFileNameA(NULL, dll, MAX_PATH);   /* 宿主进程 = gamemd.exe */
    if (n == 0 || n >= MAX_PATH) { g_Dir[0] = '.'; g_Dir[1] = 0; }
    else
    {
        p = dll + StrLen(dll);
        while (p > dll && *p != '\\') p--;        /* 去掉文件名 */
        if (*p == '\\') *p = 0;
        /* 复制目录 */
        {
            int i = 0;
            while (dll[i] && i < MAX_PATH - 1) { g_Dir[i] = dll[i]; i++; }
            g_Dir[i] = 0;
        }
    }

    /* 目录 + "\MsgLog\EventProbe_YYYY-MM-DD_HH-MM-SS.log"
     * 目录不存在时 CreateFileA 会失败 —— 所以先用 CreateDirectoryA 建 MsgLog。 */
    {
        char sub[MAX_PATH];
        int  i = 0;
        const char* tail = "\\MsgLog";
        while (g_Dir[i] && i < MAX_PATH - 16) { sub[i] = g_Dir[i]; i++; }
        while (*tail && i < MAX_PATH - 1) sub[i++] = *tail++;
        sub[i] = 0;
        CreateDirectoryA(sub, NULL);
    }

    GetLocalTime(&st);
    d = g_LogPath;
    d = AppStr(d, g_Dir, end);
    d = AppStr(d, "\\MsgLog\\EventProbe_", end);
    d += UtoA(st.wYear, d);          d = AppCh(d, '-', end);
    b[0] = (char)('0' + st.wMonth / 10); b[1] = (char)('0' + st.wMonth % 10); b[2] = 0;
    d = AppStr(d, b, end);           d = AppCh(d, '-', end);
    b[0] = (char)('0' + st.wDay / 10);   b[1] = (char)('0' + st.wDay % 10);   b[2] = 0;
    d = AppStr(d, b, end);           d = AppCh(d, '_', end);
    b[0] = (char)('0' + st.wHour / 10);  b[1] = (char)('0' + st.wHour % 10);  b[2] = 0;
    d = AppStr(d, b, end);           d = AppCh(d, '-', end);
    b[0] = (char)('0' + st.wMinute / 10); b[1] = (char)('0' + st.wMinute % 10); b[2] = 0;
    d = AppStr(d, b, end);           d = AppCh(d, '-', end);
    b[0] = (char)('0' + st.wSecond / 10); b[1] = (char)('0' + st.wSecond % 10); b[2] = 0;
    d = AppStr(d, b, end);
    d = AppStr(d, ".log", end);
    *d = 0;
}

/* 当前进程是不是 gamemd.exe？
 *
 * 为什么需要判断：Syringe 在【自己进程】里会先调用一次各 DLL 的
 * SyringeHandshake（就是日志里 "Calling xxx.dll ... Answers ..." 那几行），
 * 而握手会走到 EnsureInit 里建日志文件 —— 于是【每次启动都会多出一个
 * 只有启动头的空日志】（实测：一局生成两个 EventProbe_*.log）。
 * 那个日志是 Syringe 进程留下的，不是游戏产生的，留着只会让人困惑。
 *
 * 所以：只有宿主是 gamemd.exe 时才真正建日志；其他进程静默。 */
static int IsGameProcess(void)
{
    char  exe[MAX_PATH];
    DWORD n;
    const char* want = "gamemd.exe";
    int   i, wl = 10;

    n = GetModuleFileNameA(NULL, exe, MAX_PATH);
    if (n == 0 || n < (DWORD)wl) return 0;

    for (i = 0; i < wl; i++)
    {
        char c = exe[n - wl + i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');   /* 无 CRT，自己做 tolower */
        if (c != want[i]) return 0;
    }
    return 1;
}

static void LogOpen(void)
{
    if (g_Log || g_LogFailed) return;

    /* 非游戏进程（Syringe 自己）不建日志 */
    if (!IsGameProcess()) { g_LogFailed = 1; return; }

    BuildPaths();
    g_Log = CreateFileA(g_LogPath, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_Log == INVALID_HANDLE_VALUE) { g_Log = NULL; g_LogFailed = 1; return; }

    if (g_Cfg.LogUtf8)
    {
        const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
        DWORD w = 0;
        WriteFile(g_Log, bom, 3, &w, NULL);
    }
}

/* 写一行（自动加时间戳与换行）。行缓冲上限 1024 字节，足够。 */
static void LogLine(const char* body)
{
    char  out[1200];
    char* d = out;
    char* end = out + sizeof(out) - 4;
    DWORD w = 0;
    char  b[8];
    SYSTEMTIME st;

    LogOpen();
    if (!g_Log) return;

    GetLocalTime(&st);
    d = AppCh(d, '[', end);
    b[0] = (char)('0' + st.wMonth / 10);  b[1] = (char)('0' + st.wMonth % 10);  b[2] = 0;
    d = AppStr(d, b, end); d = AppCh(d, '-', end);
    b[0] = (char)('0' + st.wDay / 10);    b[1] = (char)('0' + st.wDay % 10);    b[2] = 0;
    d = AppStr(d, b, end); d = AppCh(d, ' ', end);
    b[0] = (char)('0' + st.wHour / 10);   b[1] = (char)('0' + st.wHour % 10);   b[2] = 0;
    d = AppStr(d, b, end); d = AppCh(d, ':', end);
    b[0] = (char)('0' + st.wMinute / 10); b[1] = (char)('0' + st.wMinute % 10); b[2] = 0;
    d = AppStr(d, b, end); d = AppCh(d, ':', end);
    b[0] = (char)('0' + st.wSecond / 10); b[1] = (char)('0' + st.wSecond % 10); b[2] = 0;
    d = AppStr(d, b, end);
    d = AppStr(d, "] ", end);
    d = AppStr(d, body, end);
    d = AppCh(d, '\r', end);
    d = AppCh(d, '\n', end);

    WriteFile(g_Log, out, (DWORD)(d - out), &w, NULL);
}

/* ==================================================================
 * 6. 配置读取
 * ================================================================== */

static void LoadConfig(void)
{
    char ini[MAX_PATH];
    char* d = ini;
    char* end = ini + sizeof(ini) - 32;

    d = AppStr(d, g_Dir, end);
    d = AppStr(d, "\\EventProbe.ini", end);
    *d = 0;

    g_Cfg.Enable        = GetPrivateProfileIntA("EventProbe", "Enable",        1,  ini);
    g_Cfg.DumpRaw       = GetPrivateProfileIntA("EventProbe", "DumpRaw",       0,  ini);
    g_Cfg.DumpBytes     = GetPrivateProfileIntA("EventProbe", "DumpBytes",     32, ini);
    g_Cfg.BurstOps      = GetPrivateProfileIntA("EventProbe", "BurstOps",      5,  ini);
    g_Cfg.LogEveryFrame = GetPrivateProfileIntA("EventProbe", "LogEveryFrame", 0,  ini);
    g_Cfg.LogUtf8       = GetPrivateProfileIntA("EventProbe", "LogUtf8",       0,  ini);

    g_Cfg.Enable        = g_Cfg.Enable        ? 1 : 0;
    g_Cfg.DumpRaw       = g_Cfg.DumpRaw       ? 1 : 0;
    g_Cfg.LogEveryFrame = g_Cfg.LogEveryFrame ? 1 : 0;
    g_Cfg.LogUtf8       = g_Cfg.LogUtf8       ? 1 : 0;
    if (g_Cfg.DumpBytes < 8)    g_Cfg.DumpBytes = 8;
    if (g_Cfg.DumpBytes > EVENT_SIZE) g_Cfg.DumpBytes = EVENT_SIZE;
    if (g_Cfg.BurstOps < 1)     g_Cfg.BurstOps = 1;
    if (g_Cfg.BurstOps > 200)   g_Cfg.BurstOps = 200;

    /* ---------------- [Detector] ---------------- */

    g_DetCfg.Enable          = GetPrivateProfileIntA("Detector", "Enable",          1,  ini);
    g_DetCfg.MinEvents       = GetPrivateProfileIntA("Detector", "MinEvents",       5,  ini);
    g_DetCfg.MinDest         = GetPrivateProfileIntA("Detector", "MinDest",         5,  ini);
    g_DetCfg.RatioPercent    = GetPrivateProfileIntA("Detector", "RatioPercent",    50, ini);
    g_DetCfg.ShowAlert       = GetPrivateProfileIntA("Detector", "ShowAlert",       1,  ini);
    g_DetCfg.AlertSeconds    = GetPrivateProfileIntA("Detector", "AlertSeconds",    10, ini);
    g_DetCfg.LogRaw          = GetPrivateProfileIntA("Detector", "LogRaw",          0,  ini);
    g_DetCfg.WindowFrames    = GetPrivateProfileIntA("Detector", "WindowFrames",    600, ini);
    g_DetCfg.WindowHits      = GetPrivateProfileIntA("Detector", "WindowHits",      2,  ini);
    g_DetCfg.HashChain       = GetPrivateProfileIntA("Detector", "HashChain",       1,  ini);
    g_DetCfg.SummaryEvery    = GetPrivateProfileIntA("Detector", "SummaryEvery",    1800, ini);

    g_DetCfg.Enable       = g_DetCfg.Enable       ? 1 : 0;
    g_DetCfg.ShowAlert    = g_DetCfg.ShowAlert    ? 1 : 0;
    g_DetCfg.LogRaw       = g_DetCfg.LogRaw       ? 1 : 0;
    g_DetCfg.HashChain    = g_DetCfg.HashChain    ? 1 : 0;

    if (g_DetCfg.MinEvents < 1)         g_DetCfg.MinEvents = 1;
    if (g_DetCfg.MinEvents > DET_MAX_UNIQ) g_DetCfg.MinEvents = DET_MAX_UNIQ;
    if (g_DetCfg.MinDest < 1)           g_DetCfg.MinDest = 1;
    if (g_DetCfg.MinDest > DET_MAX_UNIQ)   g_DetCfg.MinDest = DET_MAX_UNIQ;
    if (g_DetCfg.RatioPercent < 0)      g_DetCfg.RatioPercent = 0;
    if (g_DetCfg.RatioPercent > 100)    g_DetCfg.RatioPercent = 100;
    if (g_DetCfg.AlertSeconds < 1)      g_DetCfg.AlertSeconds = 1;
    if (g_DetCfg.AlertSeconds > 600)    g_DetCfg.AlertSeconds = 600;
    if (g_DetCfg.WindowFrames < 1)      g_DetCfg.WindowFrames = 1;
    if (g_DetCfg.WindowFrames > 100000) g_DetCfg.WindowFrames = 100000;
    if (g_DetCfg.WindowHits < 1)        g_DetCfg.WindowHits = 1;
    if (g_DetCfg.WindowHits > 1000)     g_DetCfg.WindowHits = 1000;
    if (g_DetCfg.SummaryEvery < 0)      g_DetCfg.SummaryEvery = 0;

    /* 要忽略的房号（逗号分隔，例如 "3,5"）—— 联机遭遇战里电脑玩家的房号
     * 也可能出现批量命令，若它造成噪音就在这里排除。留空 = 不排除任何房号。 */
    {
        char list[128];
        int  i = 0, seen = 0;
        list[0] = 0;
        GetPrivateProfileStringA("Detector", "IgnoreHouses", "", list, sizeof(list), ini);
        while (list[i])
        {
            int v = 0, got = 0;
            while (list[i] >= '0' && list[i] <= '9')
            {
                if (v < 10000) v = v * 10 + (list[i] - '0');
                i++; got = 1;
            }
            if (got)
            {
                if (v >= 0 && v < MAX_HOUSES) { g_DetCfg.IgnoreHouseMask |= (1 << v); seen = 1; }
            }
            else i++;   /* 分隔符（逗号/空格）跳过 */
        }
        g_DetCfg.IgnoreList = seen;
    }

    g_Rule.MinEvents    = g_DetCfg.MinEvents;
    g_Rule.MinDest      = g_DetCfg.MinDest;
    g_Rule.RatioPercent = g_DetCfg.RatioPercent;
}

/* ==================================================================
 * 7. 事件分类
 * ================================================================== */

/* EventType 全表见 YRpp/GeneralDefinitions.h:1409-1458。
 * 这里把 47 种事件分成四类，目的是把"玩家操作"从"协议噪声"里摘出来 ——
 * 尤其是 FrameInfo(0x1C)：它【每个玩家每帧都发一条】，不排除的话
 * 统计会被它彻底淹没。 */

/* 玩家操作类：由玩家主动发起、会影响模拟状态 */
static int IsPlayerOp(unsigned char t)
{
    switch (t)
    {
    case 0x01: case 0x02:              /* PowerOn / PowerOff */
    case 0x03:                         /* Ally（结盟） */
    case 0x04: case 0x05:              /* MegaMission / MegaMissionF ★移动/攻击/进入 */
    case 0x06: case 0x07: case 0x08:   /* Idle / Scatter / Destruct */
    case 0x09: case 0x0A:              /* Deploy / Detonate */
    case 0x0B:                         /* Place（放建筑） */
    case 0x0E: case 0x0F: case 0x10:   /* Produce / Suspend / Abandon（生产相关） */
    case 0x11: case 0x12:              /* Primary / SpecialPlace（超武） */
    case 0x15: case 0x16: case 0x17:   /* Repair / Sell / SellCell */
    case 0x1E:                         /* Archive */
        return 1;
    default:
        return 0;
    }
}

/* 协议类：引擎/网络自身周期性发送，玩家的"操作频率"不该把它们算进去 */
static int IsProtocol(unsigned char t)
{
    switch (t)
    {
    case 0x00:                         /* Empty */
    case 0x19:                         /* FrameSync */
    case 0x1B:                         /* ResponseTime */
    case 0x1C:                         /* ★ FrameInfo —— 每玩家每帧一条 */
    case 0x1D:                         /* SaveGame */
    case 0x1F: case 0x20: case 0x21:   /* AddPlayer / Timing / ProcessTime */
    case 0x22: case 0x23: case 0x24:   /* PageUser / RemovePlayer / LatencyFudge */
    case 0x25: case 0x26:              /* MegaFrameInfo / PacketTiming */
    case 0x27: case 0x28: case 0x29:   /* AboutToExit / FallbackHost / AddressChange */
    case 0x2A: case 0x2B: case 0x2C:   /* PlanConnect / PlanCommit / PlanNodeDelete */
    case 0x2D: case 0x2E:              /* AllCheer / AbandonAll */
        return 1;
    default:
        return 0;
    }
}

/* 聊天（0x1A Message）单列 —— 它不影响模拟，但属于"玩家行为"，值得单独看 */
#define ET_MESSAGE  0x1A

/* ==================================================================
 * 8. 探针主体
 * ================================================================== */

typedef struct {
    int ops;       /* 玩家操作类 */
    int chat;      /* 聊天 */
    int proto;     /* 协议类 */
    int other;     /* 其余 */
    int mm;        /* 其中 MegaMission(0x04/0x05) —— 移动/攻击/进入类，检测重点 */
} HouseStat;

/* 事件字段的便捷读取 */
static unsigned char  EvType (const unsigned char* e) { return e[EVT_OFF_TYPE]; }
static unsigned char  EvExec (const unsigned char* e) { return e[EVT_OFF_EXEC]; }
static signed char    EvHouse(const unsigned char* e) { return (signed char)e[EVT_OFF_HOUSE]; }
static unsigned       EvFrame(const unsigned char* e) { return *(const unsigned*) (e + EVT_OFF_FRAME); }

static int  g_LastProbedFrame = -1;    /* 同一帧只统计一次（钩子可能一帧被调多次） */
static unsigned g_FrameSeen  = 0;      /* 帧钩子心跳计数 */
static unsigned g_HookCalls  = 0;      /* ExecuteEventsHook 累计调用次数 */

/* 队列深度的历史最大值。
 * 为什么需要记最大值：OutList（本机待发）是【每帧发送后清空】的，
 * 每 60 帧才采一次样必然错过。只有每次钩子调用都采、并保留最大值，
 * 才能回答"到底有没有产生过事件"。 */
static int  g_MaxOps      = 0;         /* 单帧单玩家 ops 的历史最大值 */
static int  g_MaxOpsHouse = -1;        /* 上面那个值出现在哪个房号 */
static int  g_MaxIn  = 0;              /* DoList  历史最大 Count */
static int  g_MaxOut = 0;              /* OutList 历史最大 Count */

/* 一行摘要：evt f=12480 q=45 n=12 | h1 ops=9 chat=0 proto=3 | h2 ... */
static void ReportFrame(unsigned frame, int queueDepth, int nThis,
                        const HouseStat* hs, int nHouses)
{
    char  buf[1024];
    char* d = buf;
    char* end = buf + sizeof(buf) - 16;
    int   i, any = 0;

    d = AppStr(d, "evt f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " q=", end);          /* DoList 当前总条数（含未来帧，看积压） */
    d = AppNum(d, queueDepth, end);
    d = AppStr(d, " n=", end);          /* 本帧待执行条数 */
    d = AppNum(d, nThis, end);

    for (i = 0; i < nHouses; i++)
    {
        if (!hs[i].ops && !hs[i].chat && !hs[i].proto && !hs[i].other) continue;
        any = 1;
        d = AppStr(d, " | h", end);
        d = AppNum(d, i, end);
        d = AppStr(d, " ops=", end);    d = AppNum(d, hs[i].ops, end);
        d = AppStr(d, " chat=", end);   d = AppNum(d, hs[i].chat, end);
        d = AppStr(d, " proto=", end);  d = AppNum(d, hs[i].proto, end);
        if (hs[i].mm) { d = AppStr(d, " MM=", end); d = AppNum(d, hs[i].mm, end); }
        if (hs[i].other) { d = AppStr(d, " other=", end); d = AppNum(d, hs[i].other, end); }
    }
    if (!any) d = AppStr(d, " | (no events)", end);

    *d = 0;
    LogLine(buf);
}

/* 一条事件的原始字节（校准偏移用）：
 *   raw f=12480 h=1 t=04 fr=12480 ex=0 | 04 00 01 30 30 00 00 07 ... */
static void ReportRaw(unsigned frame, const unsigned char* e)
{
    char  buf[768];
    char* d = buf;
    char* end = buf + sizeof(buf) - 8;
    int   i, n = g_Cfg.DumpBytes;

    d = AppStr(d, "raw f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " h=", end);
    d = AppNum(d, (int)EvHouse(e), end);
    d = AppStr(d, " t=0x", end);
    d += HtoA(EvType(e), d, 2);
    d = AppStr(d, " fr=", end);
    d = AppNum(d, (int)EvFrame(e), end);
    d = AppStr(d, " ex=", end);
    d = AppNum(d, EvExec(e) & 1, end);
    d = AppStr(d, " |", end);

    for (i = 0; i < n && i < EVENT_SIZE; i++)
    {
        /* HtoA 会写 2 位十六进制 + 1 个 '\0'，先确认放得下 */
        if (d + 4 > end) break;
        d = AppCh(d, ' ', end);
        d += HtoA(e[i], d, 2);
    }
    if (n < EVENT_SIZE) d = AppStr(d, " ...", end);

    *d = 0;
    LogLine(buf);
}

/* 突发告警 */
static void ReportBurst(unsigned frame, int house, int ops, int movers, int enters)
{
    char  buf[256];
    char* d = buf;
    char* end = buf + sizeof(buf) - 8;

    d = AppStr(d, "*** BURST f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " h=", end);
    d = AppNum(d, house, end);
    d = AppStr(d, " ops=", end);
    d = AppNum(d, ops, end);
    d = AppStr(d, "  (MegaMission=", end);
    d = AppNum(d, movers, end);
    d = AppStr(d, ", Mission=7(Enter): ", end);
    d = AppNum(d, enters, end);
    d = AppStr(d, ")", end);

    *d = 0;
    LogLine(buf);
}

/* ==================================================================
 * 9. 检测器 —— 「自动装车」实时判据
 * ==================================================================
 *
 * 判据本身在 detector_core.h（纯算法，可单测）。这一节负责：
 *   把每帧的事件喂给判据 → 命中后写日志（含哈希链）→ 屏幕上提示。
 *
 * 判据（详见 detector_core.h 与 开发文档/00 第四节）：
 *   同一帧内、同一玩家的一批 MegaMission 里，
 *   「Destination 不同取值个数」≈「Whom 不同取值个数」→ 自动装车。
 */

/* 每帧、每房号一份统计。刻意放 static 而不是栈上：
 * DetStat 约 2KB，16 份就是 34KB —— 钩子跑在游戏主线程上，不该在栈上摆这么大。 */
static DetStat g_Det[MAX_HOUSES];

/* ---------------- 哈希链 ----------------
 * chain[n] = SHA256( chain[n-1] || 本次记录 || 命中事件的头部字节 )
 * 每次告警把当前 chain 写进日志，局末再写最终值。
 * 事后改中间任意一行，之后所有 chain 值都要重算，对不上就暴露。 */
static unsigned char g_Chain[32];
static int           g_ChainRecords = 0;

static void PutU32(unsigned char* p, unsigned v)
{
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

/* ---------------- 每个房号的命中状态（滑动窗口 + 累计）---------------- */

typedef struct {
    unsigned winStart;      /* 当前窗口的起点帧 */
    int      hitsInWindow;  /* 窗口内命中次数 */
    int      totalHits;     /* 该房号累计命中次数 */
    unsigned lastHitFrame;
} DetHouseState;

static DetHouseState g_DetState[MAX_HOUSES];
static int           g_DetTotalHits        = 0;
static int           g_DetScans            = 0;   /* 出现过有效 MegaMission 的帧数（活性指标） */
static int           g_DetFrames           = 0;
static unsigned      g_DetFirstHit         = 0;
static unsigned      g_DetLastHit          = 0;
static int           g_DetLastSummaryFrame = -1;   /* 上次输出定期汇总的帧号 */
static int           g_DetHitsAtLastSummary = 0;   /* 上次汇总时的命中数（没变化就不重复输出） */

/* ---------------- 待显示的屏幕提示 ----------------
 *
 * 为什么不在命中的当口直接显示：
 *   命中是在 Execute_DoList 内部（0x64C38D 钩子）算出来的，
 *   那一刻引擎正在消费事件队列。在别人的函数中途去调 UI 函数，
 *   轻则显示异常，重则重入崩溃。
 * 所以这里只【登记】，由帧钩子（0x55D360，主循环帧入口，安全的时机）显示。 */
typedef struct {
    int      pending;
    int      level;        /* 1 = 命中，2 = 窗口内重复命中（升级） */
    int      house;
    unsigned frame;
    int      nEvt, nWhom, nDest, nMove, nEnter;
    int      windowHits;
} PendingAlert;

static PendingAlert g_Alert;

/* 屏幕提示：借用引擎的 AddMessage（调用约定与 typedef 见 engine_abi.h） */
static void ShowScreenAlert(const wchar_t* text)
{
    AddMessageFn fn = (AddMessageFn)ADDR_ADD_MESSAGE;
    fn((void*)(unsigned)ADDR_MESSAGELIST_INSTANCE, NULL,
       NULL, 0, text,
       MSG_COLOR_SCHEME, MSG_STYLE,
       g_DetCfg.AlertSeconds * 60,   /* 超时按帧算，实测约 60 帧/秒 */
       1);                           /* silent=1：不播提示音，别吓人 */
}

/* 哈希链推进 + 取当前值前 8 字节的 hex */
static void ChainPush(int house, unsigned frame, const DetStat* s)
{
    unsigned char rec[32];
    Sha256Ctx     c;

    PutU32(rec + 0,  (unsigned)house);
    PutU32(rec + 4,  frame);
    PutU32(rec + 8,  (unsigned)s->nEvt);
    PutU32(rec + 12, (unsigned)s->nWhom);
    PutU32(rec + 16, (unsigned)s->nDest);
    PutU32(rec + 20, (unsigned)GetTickCount());
    PutU32(rec + 24, (unsigned)s->nHeads);
    PutU32(rec + 28, (unsigned)g_DetTotalHits);

    Sha256_Init(&c);
    Sha256_Update(&c, g_Chain, 32);
    Sha256_Update(&c, rec, 32);

    /* 把命中事件的头部位节也绑进链里（只取各条前 DET_HEAD_HASH 字节，
     * 因为只有这一段在各客户端上逐字节一致） */
    {
        int i;
        for (i = 0; i < s->nHeads; i++)
            Sha256_Update(&c, s->heads + (i * DET_HEAD_SAVE), DET_HEAD_HASH);
    }

    Sha256_Final(&c, g_Chain);
    g_ChainRecords++;
}

static void ChainHex(char* d, int full)
{
    static const char* hex = "0123456789ABCDEF";
    int n = full ? 32 : 8;
    int i;
    for (i = 0; i < n; i++)
    {
        d[i * 2]     = hex[(g_Chain[i] >> 4) & 0xF];
        d[i * 2 + 1] = hex[g_Chain[i] & 0xF];
    }
    d[n * 2] = 0;
}

/* ---------------- 告警日志 ---------------- */

static void ReportDetectHit(unsigned frame, int house, const DetStat* s, int ratio, int repeated)
{
    char  buf[640];
    char* d = buf;
    char* end = buf + sizeof(buf) - 16;
    char  ch[80];

    d = AppStr(d, "*** DETECT f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " h=", end);
    d = AppNum(d, house, end);
    d = AppStr(d, " units=", end);   d = AppNum(d, s->nWhom, end);
    d = AppStr(d, " veh=", end);     d = AppNum(d, s->nDest, end);
    d = AppStr(d, " MM=", end);      d = AppNum(d, s->nEvt, end);
    d = AppStr(d, " (Move=", end);   d = AppNum(d, s->nMove, end);
    d = AppStr(d, " Enter=", end);   d = AppNum(d, s->nEnter, end);
    d = AppStr(d, " Other=", end);   d = AppNum(d, s->nOtherMission, end);
    d = AppStr(d, ") ratio=", end);  d = AppNum(d, ratio, end);
    d = AppStr(d, "%", end);
    if (s->nInvalid) { d = AppStr(d, " invalid=", end); d = AppNum(d, s->nInvalid, end); }
    if (s->nOverflow) { d = AppStr(d, " OVERFLOW=", end); d = AppNum(d, s->nOverflow, end); }
    if (repeated) d = AppStr(d, " [repeated]", end);

    if (g_DetCfg.HashChain)
    {
        ChainHex(ch, 0);
        d = AppStr(d, " chain=", end);
        d = AppStr(d, ch, end);
    }

    *d = 0;
    LogLine(buf);
}

static void ReportDetectRepeat(unsigned frame, int house, const DetHouseState* st)
{
    char  buf[320];
    char* d = buf;
    char* end = buf + sizeof(buf) - 8;

    d = AppStr(d, "*** DETECT-REPEAT f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " h=", end);
    d = AppNum(d, house, end);
    d = AppStr(d, " hitsInWindow=", end);
    d = AppNum(d, st->hitsInWindow, end);
    d = AppStr(d, "/", end);
    d = AppNum(d, g_DetCfg.WindowFrames, end);
    d = AppStr(d, " frames, totalHits=", end);
    d = AppNum(d, st->totalHits, end);

    *d = 0;
    LogLine(buf);
}

/* 命中那一批事件的原始字节（LogRaw=1 时）—— 便于人工复核判据 */
static void ReportDetectRaw(unsigned frame, int house, const DetStat* s)
{
    int i, k;

    for (i = 0; i < s->nHeads; i++)
    {
        char  buf[256];
        char* d = buf;
        char* end = buf + sizeof(buf) - 8;
        const unsigned char* p = s->heads + (i * DET_HEAD_SAVE);

        d = AppStr(d, "detraw f=", end);
        d = AppNum(d, (int)frame, end);
        d = AppStr(d, " h=", end);
        d = AppNum(d, house, end);
        d = AppStr(d, " i=", end);
        d = AppNum(d, i, end);
        d = AppStr(d, " |", end);

        for (k = 0; k < DET_HEAD_SAVE; k++)
        {
            if (d + 4 > end) break;
            d = AppCh(d, ' ', end);
            d += HtoA(p[k], d, 2);
        }

        *d = 0;
        LogLine(buf);
    }
}

/* ---------------- 汇总 ---------------- */

static void ReportDetectSummary(int final)
{
    char  buf[640];
    char* d;
    char* end = buf + sizeof(buf) - 16;
    char  ch[80];
    int   i, any = 0;

    if (!g_Inited || !g_DetCfg.Enable) return;
    if (!g_Log && !g_LogFailed) LogOpen();

    d = buf;
    if (final)
    {
        d = AppStr(d, "[DETECT-SUMMARY] ver=" PROBE_VERSION " f=", end);
        d = AppNum(d, (int)*(const unsigned*)ADDR_CURRENT_FRAME, end);
    }
    else
    {
        /* 定期的心跳型汇总：只报活性和累计命中，方便判断"检测器还在跑吗" */
        d = AppStr(d, "[DETECT] alive f=", end);
        d = AppNum(d, (int)*(const unsigned*)ADDR_CURRENT_FRAME, end);
    }

    d = AppStr(d, " hits=", end);   d = AppNum(d, g_DetTotalHits, end);
    d = AppStr(d, " scans=", end);  d = AppNum(d, g_DetScans, end);
    if (!final)
    {
        d = AppStr(d, " frames=", end);
        d = AppNum(d, g_DetFrames, end);
    }

    if (g_DetTotalHits)
    {
        d = AppStr(d, " firstHit=", end); d = AppNum(d, (int)g_DetFirstHit, end);
        d = AppStr(d, " lastHit=", end);  d = AppNum(d, (int)g_DetLastHit, end);
        d = AppStr(d, " byHouse=", end);
        for (i = 0; i < MAX_HOUSES; i++)
        {
            if (g_DetState[i].totalHits <= 0) continue;
            if (any) d = AppCh(d, ',', end);
            d = AppCh(d, 'h', end);
            d = AppNum(d, i, end);
            d = AppCh(d, ':', end);
            d = AppNum(d, g_DetState[i].totalHits, end);
            any = 1;
        }
    }

    if (g_DetCfg.HashChain)
    {
        ChainHex(ch, final ? 1 : 0);
        d = AppStr(d, " chain=", end);
        d = AppStr(d, ch, end);
        d = AppStr(d, " recs=", end);
        d = AppNum(d, g_ChainRecords, end);
    }

    *d = 0;
    LogLine(buf);
}

/* ---------------- 命中处理 ---------------- */

static void OnDetectHit(unsigned frame, int house, const DetStat* s)
{
    DetHouseState* st = &g_DetState[house];
    int  ratio = (s->nWhom > 0) ? (s->nDest * 100 / s->nWhom) : 0;
    int  repeated = 0;

    /* 滑动窗口：这一批命中落在同一个窗口里就累计，跨窗口则重开 */
    if (st->winStart == 0 || (int)(frame - st->winStart) > g_DetCfg.WindowFrames)
    {
        st->winStart = frame;
        st->hitsInWindow = 0;
    }
    st->hitsInWindow++;
    st->totalHits++;
    st->lastHitFrame = frame;

    g_DetTotalHits++;
    if (!g_DetFirstHit) g_DetFirstHit = frame;
    g_DetLastHit = frame;

    if (st->hitsInWindow >= g_DetCfg.WindowHits) repeated = 1;

    if (g_DetCfg.HashChain) ChainPush(house, frame, s);

    ReportDetectHit(frame, house, s, ratio, repeated);
    if (repeated) ReportDetectRepeat(frame, house, st);
    if (g_DetCfg.LogRaw) ReportDetectRaw(frame, house, s);

    /* 登记屏幕提示（真正的显示在帧钩子里做，理由见 PendingAlert 的注释） */
    if (g_DetCfg.ShowAlert)
    {
        g_Alert.pending    = 1;
        g_Alert.level      = repeated ? 2 : 1;
        g_Alert.house      = house;
        g_Alert.frame      = frame;
        g_Alert.nEvt       = s->nEvt;
        g_Alert.nWhom      = s->nWhom;
        g_Alert.nDest      = s->nDest;
        g_Alert.nMove      = s->nMove;
        g_Alert.nEnter     = s->nEnter;
        g_Alert.windowHits = st->hitsInWindow;
    }
}

/* 每帧检查一次：把本帧各房号的统计过一遍判据 */
static void DetectCheckFrame(unsigned frame)
{
    int h;

    if (!g_DetCfg.Enable) return;

    g_DetFrames++;

    for (h = 0; h < MAX_HOUSES; h++)
    {
        const DetStat* s = &g_Det[h];

        if (s->nEvt <= 0) continue;
        g_DetScans++;

        if (g_DetCfg.IgnoreHouseMask & (1 << h)) continue;

        if (!DetStat_Judge(s, &g_Rule)) continue;

        OnDetectHit(frame, h, s);
    }

    /* 定期汇总（只在对局有进展时输出，避免刷屏） */
    if (g_DetCfg.SummaryEvery > 0)
    {
        if (g_DetLastSummaryFrame < 0)
        {
            g_DetLastSummaryFrame = (int)frame;
        }
        else if ((int)frame - g_DetLastSummaryFrame >= g_DetCfg.SummaryEvery)
        {
            g_DetLastSummaryFrame = (int)frame;
            if (g_DetTotalHits != g_DetHitsAtLastSummary)
            {
                g_DetHitsAtLastSummary = g_DetTotalHits;
                ReportDetectSummary(0);
            }
        }
    }
}

/* 显示登记的屏幕提示。只在帧钩子（0x55D360）里调用 —— 那是安全时机。 */
static void ShowPendingAlert(void)
{
    wchar_t  wbuf[256];
    wchar_t* d = wbuf;
    wchar_t* end = wbuf + (sizeof(wbuf) / sizeof(wbuf[0])) - 2;

    if (!g_Alert.pending) return;
    g_Alert.pending = 0;

    if (!g_DetCfg.Enable || !g_DetCfg.ShowAlert) return;
    if (!IsGameProcess()) return;   /* 不在 Syringe 自己进程里折腾 UI */

    if (g_Alert.level >= 2)
        d = AppWide(d, L"【可疑·重复】自动装车特征：", end);
    else
        d = AppWide(d, L"【可疑】检测到自动装车特征：", end);

    d = AppWide(d, L"房号", end);
    d = AppWideNum(d, g_Alert.house, end);
    d = AppWide(d, L" 第", end);
    d = AppWideNum(d, (int)g_Alert.frame, end);
    d = AppWide(d, L"帧 ", end);
    d = AppWideNum(d, g_Alert.nWhom, end);
    d = AppWide(d, L" 个单位配 ", end);
    d = AppWideNum(d, g_Alert.nDest, end);
    d = AppWide(d, L" 辆不同载具", end);

    if (g_Alert.level >= 2)
    {
        d = AppWide(d, L"（", end);
        d = AppWideNum(d, g_Alert.windowHits, end);
        d = AppWide(d, L" 次重复）", end);
    }

    *d = 0;
    ShowScreenAlert(wbuf);
}

/* 队列状态汇报（每 60 帧一次，不管有没有数据）。
 *
 * 一行里同时给出三个数，是为了回答"到底哪一步没东西"：
 *   in    = DoList.Count   待执行（含远程玩家）—— 我们真正想要的那个
 *   out   = OutList.Count  本机待发送
 *   calls = ExecuteEventsHook 被调用的累计次数（即 Execute_DoList 跑了多少次）
 *
 *   in 长期为 0 而 out 有值  -> 事件只停在"本机待发"，没进待执行队列
 *   两者长期都为 0          -> 这个环境下事件根本不走这条路
 *   calls 不增长            -> 钩子所在函数压根没被调用
 */
static void ReportListStat(unsigned frame)
{
    int   in  = *(const int*)(ADDR_DOLIST  + Q_OFF_COUNT);
    int   out = *(const int*)(ADDR_OUTLIST + Q_OFF_COUNT);
    int   head= *(const int*)(ADDR_DOLIST  + Q_OFF_HEAD);
    char  buf[320];
    char* d   = buf;
    char* end = buf + sizeof(buf) - 8;

    d = AppStr(d, "list: f=", end);
    d = AppNum(d, (int)frame, end);
    d = AppStr(d, " in=", end);
    d = AppNum(d, in, end);
    d = AppStr(d, "/", end);
    d = AppNum(d, g_MaxIn, end);              /* 历史最大: 判断"有没有过内容" */
    d = AppStr(d, " out=", end);
    d = AppNum(d, out, end);
    d = AppStr(d, "/", end);
    d = AppNum(d, g_MaxOut, end);
    d = AppStr(d, " calls=", end);
    d = AppNum(d, (int)g_HookCalls, end);
    d = AppStr(d, " maxOps=", end);
    d = AppNum(d, g_MaxOps, end);
    if (g_MaxOpsHouse >= 0) { d = AppStr(d, "@h", end); d = AppNum(d, g_MaxOpsHouse, end); }

    /* 队列非空时附上第一条事件的头部 —— 一次就能确认"位置读对了"以及
     * "事件帧号与当前帧差多少"。t=类型 h=房号 fr=目标帧 ex=已执行 */
    if (in > 0)
    {
        unsigned slot = ((unsigned)head) & (unsigned)(DOLIST_CAPACITY - 1);
        const unsigned char* e =
            (const unsigned char*)(ADDR_DOLIST + Q_OFF_ARRAY + slot * EVENT_SIZE);
        d = AppStr(d, " | e0 t=", end);
        d += HtoA(EvType(e), d, 2);
        d = AppStr(d, " h=", end);  d = AppNum(d, (int)EvHouse(e), end);
        d = AppStr(d, " fr=", end); d = AppNum(d, (int)EvFrame(e), end);
        d = AppStr(d, " ex=", end); d = AppNum(d, EvExec(e) & 1, end);
    }

    *d = 0;
    LogLine(buf);
}

/*
 * 统计本帧事件。
 *
 * ★ 刻意【不解析】DataBuffer（Mission / Destination 等）——
 *   那些偏移没有校准过，解析出来的东西不可信，反而会误导判断。
 *   这里只按头部四个字段（有编译期断言保证）分桶。
 */
static void ProbeFrame(void)
{
    unsigned  cur;
    int       depth, i, nThis = 0, head = 0;
    int       nUnexec = 0;                          /* 未执行事件总数（不过滤帧号） */
    unsigned  fmin = 0xFFFFFFFFu, fmax = 0;         /* 未执行事件的帧号范围 */
    HouseStat hs[MAX_HOUSES];

    cur = *(const unsigned*)ADDR_CURRENT_FRAME;

    /* ★ 每次钩子调用都采样队列深度（刻意放在帧号去重【之前】）。
     *   OutList 是"发完就清"的，只有每次都采并保留最大值，
     *   才能回答"这个环境到底有没有产生过事件"。 */
    {
        int dIn  = *(const int*)(ADDR_DOLIST  + Q_OFF_COUNT);
        int dOut = *(const int*)(ADDR_OUTLIST + Q_OFF_COUNT);
        if (dIn  > g_MaxIn  && dIn  <= DOLIST_CAPACITY) g_MaxIn  = dIn;
        if (dOut > g_MaxOut && dOut <= DOLIST_CAPACITY) g_MaxOut = dOut;
    }

    /* 同一帧只统计一次：钩子可能一帧被调用多次 */
    if ((int)cur == g_LastProbedFrame) return;
    g_LastProbedFrame = (int)cur;

    depth = *(const int*)(ADDR_DOLIST + Q_OFF_COUNT);

    /* 队列深度异常时不做统计，只记一行 —— 说明地址或状态不对，
     * 这时候继续按数组遍历可能读到非法内存。 */
    if (depth < 0 || depth > DOLIST_CAPACITY)
    {
        char  buf[192];
        char* d = buf;
        char* end = buf + sizeof(buf) - 8;
        d = AppStr(d, "!!! DoList.Count invalid = ", end);
        d = AppNum(d, depth, end);
        d = AppStr(d, " (0..", end);
        d = AppNum(d, DOLIST_CAPACITY, end);
        d = AppStr(d, ") -- address may be wrong", end);
        *d = 0;
        LogLine(buf);
        return;
    }

    for (i = 0; i < MAX_HOUSES; i++)
    {
        hs[i].ops = hs[i].chat = hs[i].proto = hs[i].other = hs[i].mm = 0;
        DetStat_Reset(&g_Det[i]);          /* 检测器：本帧重新收集 */
    }

    /* ★ 这是【环形队列】—— 元素下标不是 i，而是 (Head + i) 对容量取模。
     *
     * 不是猜的，是从 Execute_DoList 自己的代码里读出来的：
     *     64c3ae:  03 c6                 add  %esi,%eax          ; Head + i
     *     64c3b0:  25 ff 3f 00 00        and  $0x3fff,%eax       ; % 16384
     *     64c3b8:  8d 04 90              lea  (%eax,%edx,4),%eax
     *     64c3bb:  cmpb $0x1c,0x8b4204(%eax,%eax,2)            ; 0x8b4204 + eax*111
     *
     * 早期版本直接算 ADDR + i*111，漏了 Head 偏移与取模，读到的全是错位条目 ——
     * 表现为"Count 明明大于 0，却一条未执行事件都找不到"。 */
    head = *(const int*)(ADDR_DOLIST + Q_OFF_HEAD);

    for (i = 0; i < depth && i < MAX_SCAN; i++)
    {
        unsigned slot = ((unsigned)head + (unsigned)i) & (unsigned)(DOLIST_CAPACITY - 1);
        const unsigned char* e =
            (const unsigned char*)(ADDR_DOLIST + Q_OFF_ARRAY + slot * EVENT_SIZE);
        unsigned char t;
        signed char   h;
        unsigned      fr;

        if (EvExec(e) & 1) continue;      /* 已经执行过的不要 */

        fr = EvFrame(e);
        nUnexec++;
        if (fr < fmin) fmin = fr;
        if (fr > fmax) fmax = fr;

        if (fr != cur) continue;          /* 只统计"本帧要执行"的（队列里有未来帧的） */

        t = EvType(e);
        h = EvHouse(e);

        nThis++;

        if (h >= 0 && h < MAX_HOUSES)
        {
            if (t == ET_MESSAGE)                       hs[h].chat++;
            else if (IsPlayerOp(t))                    hs[h].ops++;
            else if (IsProtocol(t))                    hs[h].proto++;
            else                                       hs[h].other++;

            /* MegaMission 单列 —— 装车/移动/攻击都属于它，是检测的重点 */
            if (t == 0x04 || t == 0x05) hs[h].mm++;

            /* ★ 检测器：把这条事件喂给判据。
             *   刻意【只喂 MegaMission(0x04)】——
             *   DataBuffer 里的字段偏移（Whom/Mission/Destination）只在 0x04 上
             *   实地校准过（开发文档/01 第三节）。MegaMissionF(0x05) 的布局
             *   未必相同，拿错位的字节去下结论比不做还糟。
             *
             *   这里【不判 Enable】：收集本身开销极小，而且 BURST 告警行
             *   要用到 Mission 分布。检测器开关只决定"要不要判定/告警"。 */
            if (t == 0x04) DetStat_Feed(&g_Det[h], e);
        }

        if (g_Cfg.Enable && g_Cfg.DumpRaw) ReportRaw(cur, e);
    }

    /* 下面这些【探针专用】的输出都由 [EventProbe] Enable 控制；
     * 检测器的判定与告警是独立的（由 [Detector] Enable 控制），
     * 所以即使探针关掉、只要检测器开着，取样和判据照样跑。 */
    if (g_Cfg.Enable && (nThis > 0 || g_Cfg.LogEveryFrame))
    {
        ReportFrame(cur, depth, nThis, hs, MAX_HOUSES);
    }
    else if (g_Cfg.Enable && nUnexec > 0)
    {
        /* ★ 诊断 1: 队列里确实有事件，但没有一条属于当前帧 —— 帧号基准差了一格。
         *    这种时候数据的"时间轴"是错的，必须先修，否则统计没有意义。 */
        static int s_lastDiag = -999;
        if ((int)cur - s_lastDiag > 60)
        {
            char  buf[256];
            char* d = buf;
            char* end = buf + sizeof(buf) - 8;
            s_lastDiag = (int)cur;
            d = AppStr(d, "list: events exist but none for this frame -- cur=", end);
            d = AppNum(d, (int)cur, end);
            d = AppStr(d, " count=", end);
            d = AppNum(d, nUnexec, end);
            d = AppStr(d, " frames=[", end);
            d = AppNum(d, (int)fmin, end);
            d = AppStr(d, "..", end);
            d = AppNum(d, (int)fmax, end);
            d = AppStr(d, "]", end);
            *d = 0;
            LogLine(buf);
        }
    }
    else
    {
        /* 队列里连一条未执行事件都没有。这里刻意【不再只在"状态变化"时记】——
         * 早期版本那样写，一局下来只有初始化那一行，完全看不出后面到底是
         * 一直为空、还是某个时刻有过内容。改成在下面每 60 帧无条件汇报一次。 */
    }

    /* 每 60 帧汇报一次队列状态（不管有没有数据）。
     * 一行里给出 in / out / calls 三个数，用来判断"到底哪一步没东西"：
     *   in    = DoList.Count   待执行（含远程玩家）—— 我们真正想要的那个
     *   out   = OutList.Count  本机待发送
     *   calls = ExecuteEventsHook 被调用的累计次数
     *
     *   in 长期 0 而 out 有值 -> 事件只停在"本机待发", 没进待执行队列
     *   两者长期都是 0        -> 这个环境下事件根本不走这条路
     *   calls 不增长          -> 钩子所在函数压根没被调用 */
    {
        static int s_lastStat = -999;
        if (g_Cfg.Enable && (int)cur - s_lastStat >= 60)
        {
            s_lastStat = (int)cur;
            ReportListStat(cur);
        }
    }

    /* ★ 检测器：本帧判据 + 滑动窗口 + 定期汇总 */
    DetectCheckFrame(cur);

    /* 记录历史最高峰（采样可能漏帧，但高峰只要被采到一次就能发现） */
    for (i = 0; i < MAX_HOUSES; i++)
    {
        if (hs[i].ops > g_MaxOps) { g_MaxOps = hs[i].ops; g_MaxOpsHouse = i; }
    }

    /* 突发检查（探针层的粗略告警）。
     * 早期版本这里传的是【全房号】的 megaTotal 和一个恒为 -1 的占位
     * （见 开发文档/06 第五节"未完成事项"）—— 现在改成该房号自己的
     * MegaMission 数和 Enter 数，那一行才有意义。 */
    for (i = 0; i < MAX_HOUSES; i++)
    {
        if (g_Cfg.Enable && hs[i].ops >= g_Cfg.BurstOps)
            ReportBurst(cur, i, hs[i].ops, hs[i].mm, g_Det[i].nEnter);
    }
}

/* ==================================================================
 * 9. Syringe 接口
 * ================================================================== */

typedef struct {
    int  cbSize;
    int  num_hooks;
    unsigned int checksum;
    DWORD exeFilesize;
    DWORD exeTimestamp;
    unsigned int exeCRC;
    int  cchMessage;
    char* Message;
} SyringeHandshakeInfo;

static void EnsureInit(void)
{
    if (g_Inited) return;
    g_Inited = 1;

    BuildPaths();
    LoadConfig();

    if (g_Cfg.Enable || g_DetCfg.Enable)
    {
        char  buf[640];
        char* d = buf;
        char* end = buf + sizeof(buf) - 8;
        char  hx[16];

        d = AppStr(d, "EventProbe " PROBE_VERSION " start", end);
        *d = 0; LogLine(buf);

        d = buf;
        d = AppStr(d, "config: Enable=", end);        d = AppNum(d, g_Cfg.Enable, end);
        d = AppStr(d, " DumpRaw=", end);              d = AppNum(d, g_Cfg.DumpRaw, end);
        d = AppStr(d, " DumpBytes=", end);            d = AppNum(d, g_Cfg.DumpBytes, end);
        d = AppStr(d, " BurstOps=", end);             d = AppNum(d, g_Cfg.BurstOps, end);
        d = AppStr(d, " LogEveryFrame=", end);        d = AppNum(d, g_Cfg.LogEveryFrame, end);
        *d = 0; LogLine(buf);

        d = buf;
        d = AppStr(d, "detector: Enable=", end);      d = AppNum(d, g_DetCfg.Enable, end);
        d = AppStr(d, " MinEvents=", end);            d = AppNum(d, g_DetCfg.MinEvents, end);
        d = AppStr(d, " MinDest=", end);              d = AppNum(d, g_DetCfg.MinDest, end);
        d = AppStr(d, " RatioPercent=", end);         d = AppNum(d, g_DetCfg.RatioPercent, end);
        d = AppStr(d, " ShowAlert=", end);            d = AppNum(d, g_DetCfg.ShowAlert, end);
        d = AppStr(d, " AlertSeconds=", end);         d = AppNum(d, g_DetCfg.AlertSeconds, end);
        d = AppStr(d, " WindowFrames=", end);         d = AppNum(d, g_DetCfg.WindowFrames, end);
        d = AppStr(d, " WindowHits=", end);           d = AppNum(d, g_DetCfg.WindowHits, end);
        d = AppStr(d, " HashChain=", end);            d = AppNum(d, g_DetCfg.HashChain, end);
        d = AppStr(d, " SummaryEvery=", end);         d = AppNum(d, g_DetCfg.SummaryEvery, end);
        *d = 0; LogLine(buf);

        if (g_DetCfg.IgnoreList)
        {
            int i, first = 1;
            d = buf;
            d = AppStr(d, "detector: ignore houses =", end);
            for (i = 0; i < MAX_HOUSES; i++)
            {
                if (!(g_DetCfg.IgnoreHouseMask & (1 << i))) continue;
                d = AppCh(d, first ? ' ' : ',', end);
                d = AppNum(d, i, end);
                first = 0;
            }
            *d = 0; LogLine(buf);
        }

        d = buf;
        d = AppStr(d, "addr: DoList=<", end);
        HtoA(ADDR_DOLIST, hx, 8);         d = AppStr(d, hx, end);
        d = AppStr(d, "> OutList=<", end);
        HtoA(ADDR_OUTLIST, hx, 8);        d = AppStr(d, hx, end);
        d = AppStr(d, "> CurrentFrame=<", end);
        HtoA(ADDR_CURRENT_FRAME, hx, 8);  d = AppStr(d, hx, end);
        d = AppStr(d, "> AddMessage=<", end);
        HtoA(ADDR_ADD_MESSAGE, hx, 8);    d = AppStr(d, hx, end);
        d = AppStr(d, ">", end);
        *d = 0; LogLine(buf);

        LogLine("read-only probe: does not modify any game state");

        if (g_DetCfg.HashChain)
        {
            /* 链的起点写进日志：后面每一行 chain= 都能和这一行连起来核对 */
            char ch[80];
            ChainHex(ch, 1);
            d = buf;
            d = AppStr(d, "hash-chain: sha256, initial=", end);
            d = AppStr(d, ch, end);
            d = AppStr(d, " (each DETECT line carries chain=; tampering breaks the chain)", end);
            *d = 0; LogLine(buf);
        }

        LogLine("--------------------------------------------------");
    }
}

/* 钩子 1: 0x64C38D —— Execute_DoList 内部读 DoList.Count 的那条指令。
 *
 * ⚠️ 不要改回函数入口 0x64C380：那里要覆盖 10 字节，含 sub esp / push
 *    两条改栈指令，实测必崩（纯原版 + MO 都一样）。详见 开发文档/04 第 1 条。
 *    .inj 里声明的覆盖长度是 6 —— 正好是 `mov 0x8b41f8,%edi` 一条指令。 */
extern "C" __declspec(dllexport) DWORD __cdecl EventProbe_ExecuteEventsHook(void* regs)
{
    (void)regs;
    EnsureInit();

    g_HookCalls++;

    /* 入口探针（只记前 3 次）:
     * 用来分辨崩溃到底发生在「钩子函数内部」还是「钩子返回之后」——
     * 日志里有这行  => 我们的函数跑到了这里, 崩在之后(Syringe trampoline 侧)
     * 日志里没这行  => 崩在进入函数之前, 或 EnsureInit 里
     * 用 WriteFile 直写无缓冲, 所以崩溃前写下的内容一定会留在文件里。 */
    {
        static int s_calls = 0;
        if (s_calls < 3)
        {
            char  buf[160];
            char* d = buf;
            char* end = buf + sizeof(buf) - 8;
            s_calls++;
            d = AppStr(d, "hook: ExecuteEventsHook #", end);
            d = AppNum(d, s_calls, end);
            d = AppStr(d, " entered, frame=", end);
            d = AppNum(d, (int)*(const unsigned*)ADDR_CURRENT_FRAME, end);
            *d = 0;
            LogLine(buf);
        }
    }

    /* 探针与检测器共用这一次采样；两个都关才真的什么都不做 */
    if (g_Cfg.Enable || g_DetCfg.Enable) ProbeFrame();
    return 0;   /* 返回 0 -> Syringe 执行被覆盖的原指令，游戏照常 */
}

/* 钩子 2: 0x55D360 —— 主循环每逻辑帧入口（ChatBox/AutoKit/Phobos/RAReplay 同址）。
 *
 * 这个地址是【多方共用且已验证】的安全钩点（5 字节，绝对寻址），
 * 所以这里也驱动一次统计 —— 万一 0x64C38D 那个钩点在某个环境下有问题，
 * 把 .inj 里的那一行删掉，本插件仍然能工作（取样时机变成"帧开始"）。
 *
 * ProbeFrame() 内部有帧号去重，两个钩子同时存在也不会重复统计。
 *
 * ★ 屏幕提示只在这里显示：命中是在 Execute_DoList 内部算出来的，
 *   那一刻引擎正在消费事件队列，不适合调 UI 函数。这里是帧入口，安全。 */
extern "C" __declspec(dllexport) DWORD __cdecl EventProbe_FrameHook(void* regs)
{
    (void)regs;
    EnsureInit();

    g_FrameSeen++;

    /* 心跳行（只记一次）—— 排查"探针是否活着"就看它 */
    {
        static unsigned char s_alive = 0;
        if (!s_alive)
        {
            char  buf[192];
            char* d = buf;
            char* end = buf + sizeof(buf) - 8;
            d = AppStr(d, "hook: frame alive (0x55D360), CurrentFrame=", end);
            d = AppNum(d, (int)*(const unsigned*)ADDR_CURRENT_FRAME, end);
            *d = 0;
            LogLine(buf);
            s_alive = 1;
        }
    }

    if (g_Cfg.Enable || g_DetCfg.Enable) ProbeFrame();

    ShowPendingAlert();

    return 0;
}

extern "C" __declspec(dllexport) HRESULT __cdecl SyringeHandshake(SyringeHandshakeInfo* pInfo)
{
    if (!pInfo || pInfo->cbSize < (int)sizeof(SyringeHandshakeInfo))
        return E_FAIL;

    EnsureInit();

    if (pInfo->Message && pInfo->cchMessage > 0)
    {
        const char* msg = "EventProbe " PROBE_VERSION
                          ": read-only event-queue probe + AutoLoad detector "
                          "(detection only, no game state touched).";
        int i = 0;
        while (msg[i] && i < pInfo->cchMessage - 1) { pInfo->Message[i] = msg[i]; i++; }
        pInfo->Message[i] = 0;
    }
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInst);
    else if (reason == DLL_PROCESS_DETACH)
    {
        /* 退出游戏（或卸载 DLL）时补一条局末汇总。
         * 只依赖 kernel32 的 WriteFile，进程退出阶段仍然可用。
         * 对局中途返回主菜单【不会】走到这里，所以另有定期汇总兜底。 */
        if (g_Inited) ReportDetectSummary(1);
    }
    return TRUE;
}
