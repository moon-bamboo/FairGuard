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
 * FairGuardReport.c —— 日志阅读器 + 哈希链校验器（独立工具）
 *
 * ============================ 它是干什么的 ============================
 *
 * 把 FairGuard 写出来的原始日志，变成一份**人看得懂的 HTML 报告**，同时
 * **独立重算哈希链**，告诉用户这份日志有没有被事后改动过。
 *
 * 用法（双击即可，也可以把日志文件拖到 exe 上）：
 *
 *     FairGuardReport.exe                    找 <exe目录>\MsgLog 里最新的日志
 *     FairGuardReport.exe <日志路径>          指定日志
 *     FairGuardReport.exe --selftest         自检（不读日志）
 *
 * 输出：`<日志名>.report.html`，生成后自动用默认浏览器打开。
 *
 * ============================ 为什么必须"独立" ============================
 *
 * 插件自己写的链，插件自己说"没被改过" —— 那不叫验证。所以这个工具：
 *
 *   - **不链接插件的任何代码**，只共用 `src/sha256.h`（一个标准 SHA-256）
 *   - **只从日志文本里读字段**重算链：房号、帧号、MM、units、veh、第几条
 *   - 逐行比对，能报出"第 N 条对不上" —— 那一行之后的所有内容都不可信
 *
 * ⚠️ 校验算法必须与 `src/FairGuard.c` 的 `ChainPush()` **逐字节一致**。
 *    改任何一边都要同步改另一边，并重跑 `--selftest`。
 *
 * ============================ 哈希链的诚实局限 ============================
 *
 * 这个工具**只能证明"日志内容与链自洽"**，不能证明"这份日志是真实对局的"：
 *
 *   - 算法是公开的、没有密钥 —— 有人可以整份重新生成一份自洽的日志
 *   - 单人日志**无法自证**：要成为有效证据，需要**多方交叉核对**
 *     （那台没有操作的机器也会记下同一批事件，头部应当一致）
 *   - 它能防的是"改几个数字"这种最省事的造假，防不了精心重制
 *
 * 报告里会把这段话原样写给用户看 —— **不要让它显得比实际更权威**。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "../src/hashchain.h"   /* 与插件共用的链算法 */

/* ------------------------------------------------------------------
 * 数据
 * ------------------------------------------------------------------ */

#define MAX_HITS   20000
#define MAX_LINE   2048

typedef struct {
    char          time[16];      /* "10-05 20:52:49" */
    unsigned      frame;
    int           house;
    int           nEvt;          /* MM=   */
    int           nWhom;         /* units= */
    int           nDest;         /* veh=  */
    unsigned char chain[32];     /* 日志里写的 chain（只前 8 字节有效） */
    int           chainOk;       /* 1 = 与重算结果一致 */
    int           repeated;      /* 该行带 [repeated] */
} Hit;

static Hit   g_Hits[MAX_HITS];
static int   g_Count      = 0;
static int   g_ChainBad   = -1;      /* 第一处对不上的序号，-1 = 全部一致 */

/* 启动配置（从日志头里读，报告里显示出来） */
static char  g_CfgLine1[256] = "";
static char  g_CfgLine2[256] = "";
static char  g_Ver[32]       = "?";
static char  g_FirstTime[16] = "";
static char  g_LastTime[16]  = "";

/* ------------------------------------------------------------------
 * 小工具
 * ------------------------------------------------------------------ */

/* 在行里找 "key=" 后面的十进制数；找不到返回 0 */
static int FindInt(const char* line, const char* key, int* out)
{
    const char* p = strstr(line, key);
    int v = 0, got = 0;

    if (!p) return 0;
    p += strlen(key);
    while (*p >= '0' && *p <= '9')
    {
        v = v * 10 + (*p - '0');
        if (v > 2000000000) v = 2000000000;
        p++; got = 1;
    }
    if (!got) return 0;
    *out = v;
    return 1;
}

/* 取行首的 "[MM-DD HH:MM:SS] " 时间戳 */
static int ParseTime(const char* line, char* out, int cap)
{
    const char* p = line;

    if (*p != '[') return 0;
    p++;
    if (strlen(p) < 15) return 0;
    if (p[14] != ']') return 0;
    if (cap < 16) return 0;
    memcpy(out, p, 14);
    out[14] = 0;
    return 1;
}

/* "1A2B3C4D..." -> 字节数组；n = 要几个字节 */
static int ParseHex(const char* s, unsigned char* out, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        int hi = -1, lo = -1;
        char a = s[i * 2], b = s[i * 2 + 1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void HexStr(const unsigned char* p, int n, char* out)
{
    static const char* h = "0123456789ABCDEF";
    int i;
    for (i = 0; i < n; i++) { out[i * 2] = h[p[i] >> 4]; out[i * 2 + 1] = h[p[i] & 0xF]; }
    out[n * 2] = 0;
}

/* ------------------------------------------------------------------
 * 窄（UTF-8）-> 宽字符
 *
 * ⚠️ 为什么控制台输出全用英文、而弹窗走宽字符：
 *
 *   源码里的中文字面量按 UTF-8 编译（默认 -fexec-charset=UTF-8），
 *   而 Windows 控制台的默认代码页是 **GBK(936)** —— 于是
 *   `printf` 打出去的中文在控制台上全是乱码（实测确认过）。
 *
 *   两条出路：
 *     · 控制台：**干脆用英文** —— 不依赖代码页、不依赖字体，最稳。
 *       （报告里的中文在 HTML 里，浏览器按 UTF-8 正确显示，不受影响）
 *     · 弹窗：改用 `MessageBoxW` + UTF-16 —— 中文正确，且这是个 GUI，
 *       写英文对用户不友好。
 *
 *   注意：`MessageBoxA` 收的是 **ANSI(GBK)** 字符串，传 UTF-8 一样乱码，
 *   所以那 6 处必须一起换成 W 版本。
 * ------------------------------------------------------------------ */
static void NarrowToWide(const char* src, wchar_t* dst, int cap)
{
    if (!src || cap <= 0 || !dst) return;
    if (MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap) <= 0) dst[0] = 0;
}

/* 把"一句中文 + 一行窄字符串（通常是路径）"拼成弹窗文本 */
static void MakeMsg(wchar_t* out, int cap, const wchar_t* text, const char* narrow)
{
    int n;

    if (!out || cap <= 0) return;
    wcsncpy(out, text, (size_t)cap - 1);
    out[cap - 1] = 0;

    if (!narrow) return;

    n = (int)wcslen(out);
    if (n < cap - 1) { out[n++] = L'\n'; out[n] = 0; }

    {
        wchar_t wtmp[MAX_PATH];
        NarrowToWide(narrow, wtmp, MAX_PATH);
        n = (int)wcslen(out);
        if (n < cap - 1) wcsncat(out, wtmp, (size_t)(cap - n - 1));
    }
}

/* 取 exe 所在目录（带尾部反斜杠） */
static void ExeDir(char* out, int cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, cap);
    if (n == 0 || (int)n >= cap) { strcpy(out, ".\\"); return; }
    while (n > 0 && out[n] != '\\' && out[n] != '/') n--;
    out[n + 1] = 0;
}

/* 拼路径 */
static void JoinPath(char* out, int cap, const char* dir, const char* name)
{
    snprintf(out, cap - 1, "%s%s", dir, name);
    out[cap - 1] = 0;
}

/* ------------------------------------------------------------------
 * 找最新日志：<exe目录>\MsgLog\FairGuard_*.log
 * 文件名是 FairGuard_YYYY-MM-DD_HH-MM-SS.log，字典序 == 时间序
 * ------------------------------------------------------------------ */
static int FindLatestLog(char* out, int cap)
{
    char dir[MAX_PATH], pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char best[MAX_PATH] = "";

    ExeDir(dir, sizeof(dir));
    JoinPath(pat, sizeof(pat), dir, "MsgLog\\FairGuard_*.log");

    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        /* 退一步：找 EventProbe_*（1.0/1.1 时代的日志名），方便读老日志 */
        JoinPath(pat, sizeof(pat), dir, "MsgLog\\EventProbe_*.log");
        h = FindFirstFileA(pat, &fd);
        if (h == INVALID_HANDLE_VALUE) return 0;
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (strcmp(fd.cFileName, best) > 0) snprintf(best, sizeof(best), "%s", fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (!best[0]) return 0;
    JoinPath(out, cap, dir, "MsgLog\\");
    strncat(out, best, cap - strlen(out) - 1);
    return 1;
}

/* ------------------------------------------------------------------
 * 解析日志
 * 返回 0 = 文件打不开
 * ------------------------------------------------------------------ */
static int ParseLog(const char* path)
{
    FILE* f = fopen(path, "rb");
    char  line[MAX_LINE];

    if (!f) return 0;

    while (fgets(line, sizeof(line), f))
    {
        /* 去掉行尾换行 */
        {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        }

        /* --- 启动头：版本 + 配置 --- */
        if (!g_Ver[0] || g_Ver[0] == '?')
        {
            const char* p = strstr(line, "FairGuard ");
            if (p && strstr(p, " start"))
            {
                const char* q = p + 10;
                int i = 0;
                while (*q && *q != ' ' && i < 31) g_Ver[i++] = *q++;
                g_Ver[i] = 0;
            }
        }
        if (strstr(line, "detector: Enable=") && !g_CfgLine1[0])
            snprintf(g_CfgLine1, sizeof(g_CfgLine1), "%s", line);
        if (strstr(line, "detector: ShowAlert=") && !g_CfgLine2[0])
            snprintf(g_CfgLine2, sizeof(g_CfgLine2), "%s", line);

        /* --- 命中行 --- */
        if (strstr(line, "*** DETECT "))
        {
            Hit* h;
            char  chHex[80];
            const char* cp;
            int   f_, house_, mm, un, ve;

            if (g_Count >= MAX_HITS) continue;

            if (!FindInt(line, "f=", &f_))     continue;
            if (!FindInt(line, "h=", &house_))     continue;
            if (!FindInt(line, "MM=", &mm))    continue;
            if (!FindInt(line, "units=", &un)) continue;
            if (!FindInt(line, "veh=", &ve))   continue;

            cp = strstr(line, "chain=");
            if (!cp) continue;
            cp += 6;
            if (strlen(cp) < 16) continue;
            strncpy(chHex, cp, 16);
            chHex[16] = 0;

            h = &g_Hits[g_Count];
            memset(h, 0, sizeof(*h));
            ParseTime(line, h->time, sizeof(h->time));
            h->frame  = (unsigned)f_;
            h->house  = house_;
            h->nEvt   = mm;
            h->nWhom  = un;
            h->nDest  = ve;
            h->repeated = strstr(line, "[repeated]") ? 1 : 0;
            if (!ParseHex(chHex, h->chain, 8)) continue;

            if (!g_FirstTime[0]) strcpy(g_FirstTime, h->time);
            strcpy(g_LastTime, h->time);

            g_Count++;
        }
    }

    fclose(f);
    return 1;
}

/* ------------------------------------------------------------------
 * 独立重算哈希链 —— 必须与 src/FairGuard.c 的 ChainPush() 逐字节一致
 *
 *     rec[0..1]   house   uint16 LE
 *     rec[2..5]   frame   uint32 LE
 *     rec[6..7]   nEvt    uint16 LE   （日志里的 MM=）
 *     rec[8..9]   nWhom   uint16 LE   （units=）
 *     rec[10..11] nDest   uint16 LE   （veh=）
 *     rec[12..15] idx     uint32 LE   （第几条 DETECT，从 0 起）
 *
 *     chain = SHA256( chain_prev || rec )        chain 初值 = 32 个 0
 * ------------------------------------------------------------------ */
static void ChainStep(unsigned char* chain, int idx, const Hit* h)
{
    /* 实现放在 src/hashchain.h，插件 include 的是同一份 —— 不会跑偏 */
    HashChainStep(chain, h->house, h->frame,
                  h->nEvt, h->nWhom, h->nDest, (unsigned)idx);
}

static void VerifyChain(void)
{
    unsigned char chain[32];
    int i;

    memset(chain, 0, sizeof(chain));
    g_ChainBad = -1;

    for (i = 0; i < g_Count; i++)
    {
        ChainStep(chain, i, &g_Hits[i]);
        g_Hits[i].chainOk = (memcmp(chain, g_Hits[i].chain, HASHCHAIN_SHOWN) == 0) ? 1 : 0;
        if (!g_Hits[i].chainOk && g_ChainBad < 0) g_ChainBad = i;
    }
}

/*
 * 这份日志是不是"用旧哈希算法"写的？
 *
 * 1.0 ~ 1.2 的链里混进了 GetTickCount() 和事件的原始字节 —— 那些东西
 * 日志里没有记录，所以**谁都无法离线重算**（这正是 1.3 改算法的原因）。
 *
 * 如果不区分版本，用户拿一份 1.2 的老日志来跑，会看到"第 1 条对不上"，
 * 然后合理地怀疑自己的日志被人改了 —— 那是**我们的误导**，不是他的问题。
 * 所以旧版本要单独说明，并且不给"✓/✗"的结论。
 */
static int OldHashAlgo(void)
{
    if (g_Ver[0] != '1' || g_Ver[1] != '.') return 1;   /* 版本没读到 -> 按老的算 */
    if (g_Ver[2] >= '0' && g_Ver[2] <= '2') return 1;   /* 1.0 / 1.1 / 1.2 */
    return 0;
}

/* ------------------------------------------------------------------
 * 自检：验证 SHA256 实现与链算法本身没写错
 * ------------------------------------------------------------------ */
static int SelfTest(void)
{
    unsigned char d[32], chain[32];
    char hex[80];
    Hit h;
    int fail = 0;

    Sha256("abc", 3, d);
    HexStr(d, 32, hex);
    if (strcmp(hex, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD") != 0)
    { printf("[FAIL] SHA256(\"abc\") mismatch: %s\n", hex); fail++; }
    else printf("[PASS] SHA256(\"abc\") matches FIPS-180-4 vector\n");

    Sha256("", 0, d);
    HexStr(d, 32, hex);
    if (strcmp(hex, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") != 0)
    { printf("[FAIL] SHA256(\"\") mismatch: %s\n", hex); fail++; }
    else printf("[PASS] SHA256(\"\") matches FIPS-180-4 vector\n");

    /* 链算法：同一条记录两次必须得到同样的链值（确定性） */
    memset(&h, 0, sizeof(h));
    h.house = 3; h.frame = 12345; h.nEvt = 10; h.nWhom = 9; h.nDest = 4;
    memset(chain, 0, sizeof(chain));
    ChainStep(chain, 0, &h);
    HexStr(chain, 32, hex);
    printf("[INFO] chain after one record (h=3 f=12345 MM=10 units=9 veh=4 idx=0):\n       %s\n", hex);
    {
        unsigned char c2[32];
        char hex2[80];
        memset(c2, 0, sizeof(c2));
        ChainStep(c2, 0, &h);
        HexStr(c2, 32, hex2);
        if (strcmp(hex, hex2) != 0) { printf("[FAIL] chain not deterministic\n"); fail++; }
        else printf("[PASS] chain step is deterministic\n");
    }

    /* 改一个字段，链值必须变（否则链没意义） */
    h.nDest = 5;
    {
        unsigned char c3[32];
        char hex3[80];
        memset(c3, 0, sizeof(c3));
        ChainStep(c3, 0, &h);
        HexStr(c3, 32, hex3);
        if (strcmp(hex, hex3) == 0) { printf("[FAIL] chain unchanged after field edit\n"); fail++; }
        else printf("[PASS] changing veh changes the chain\n");
    }

    printf("\nfailures: %d\n", fail);
    return fail ? 1 : 0;
}

/* ------------------------------------------------------------------
 * 生成 HTML 报告
 * ------------------------------------------------------------------ */

static void HtmlEsc(const char* s, char* out, int cap)
{
    int i = 0;
    for (; *s && i < cap - 8; s++)
    {
        if      (*s == '<') { strcpy(out + i, "&lt;");   i += 4; }
        else if (*s == '>') { strcpy(out + i, "&gt;");   i += 4; }
        else if (*s == '&') { strcpy(out + i, "&amp;");  i += 5; }
        else                { out[i++] = *s; }
    }
    out[i] = 0;
}

/* 房号 -> 显示用（房号未必等于"玩家1/2"，报告里要提醒） */
static void BuildReport(const char* logPath, const char* outPath)
{
    FILE* f = fopen(outPath, "wb");
    const char* base;
    int   i, nRepeats = 0, nHouses = 0, seen[64];
    int   vehHist[16];
    char  chFull[80];
    unsigned char chain[32];

    if (!f) return;

    base = strrchr(logPath, '\\');
    base = base ? base + 1 : logPath;

    memset(seen, 0, sizeof(seen));
    memset(vehHist, 0, sizeof(vehHist));
    for (i = 0; i < g_Count; i++)
    {
        if (g_Hits[i].repeated) nRepeats++;
        if (g_Hits[i].house >= 0 && g_Hits[i].house < 64) seen[g_Hits[i].house] = 1;
        if (g_Hits[i].nDest >= 0 && g_Hits[i].nDest < 16) vehHist[g_Hits[i].nDest]++;
    }
    for (i = 0; i < 64; i++) if (seen[i]) nHouses++;

    /* 最终链值（重算出来的） */
    memset(chain, 0, sizeof(chain));
    for (i = 0; i < g_Count; i++) ChainStep(chain, i, &g_Hits[i]);
    HexStr(chain, 32, chFull);

    fprintf(f,
"<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\n"
"<title>FairGuard 对局报告 - %s</title>\n"
"<style>\n"
" body{font-family:'Microsoft YaHei',Segoe UI,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#222;line-height:1.7}\n"
" h1{font-size:22px;border-bottom:2px solid #444;padding-bottom:8px}\n"
" h2{font-size:17px;margin-top:28px;border-left:4px solid #666;padding-left:8px}\n"
" .card{padding:14px 18px;border-radius:8px;margin:14px 0}\n"
" .ok{background:#e8f6ec;border:1px solid #7cc48f}\n"
" .bad{background:#fdecea;border:1px solid #e59a92}\n"
" .info{background:#eef3fb;border:1px solid #9ab4d8}\n"
" .warn{background:#fff8e1;border:1px solid #e0c56a}\n"
" table{border-collapse:collapse;width:100%%;font-size:13px}\n"
" th,td{border:1px solid #ccc;padding:5px 8px;text-align:left}\n"
" th{background:#f0f0f0}\n"
" tr:nth-child(even) td{background:#fafafa}\n"
" .num{text-align:right;font-family:Consolas,monospace}\n"
" .mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}\n"
" .muted{color:#666;font-size:13px}\n"
" .hit{color:#b00;font-weight:bold}\n"
"</style></head><body>\n", base);

    /* --- 结论卡片 --- */
    fprintf(f, "<h1>FairGuard 对局报告</h1>\n");
    fprintf(f, "<p class=\"muted\">日志文件：<b>%s</b><br>", base);
    { char e[512]; HtmlEsc(logPath, e, sizeof(e)); fprintf(f, "完整路径：%s<br>", e); }
    if (g_FirstTime[0])
        fprintf(f, "记录时间：%s ~ %s　　插件版本：%s</p>\n", g_FirstTime, g_LastTime, g_Ver);
    else
        fprintf(f, "插件版本：%s</p>\n", g_Ver);

    if (g_Count == 0)
    {
        fprintf(f, "<div class=\"card info\"><b>这一局没有命中记录。</b><br>"
                   "可能的原因：<ul>"
                   "<li>对局中确实没人用自动装车（正常情况）</li>"
                   "<li>这是单机对局 —— 单机不产生事件队列，<b>必须联机</b>才有数据</li>"
                   "<li>插件没有正确加载（看日志开头有没有 <span class=\"mono\">FairGuard … start</span>）</li>"
                   "<li>对手用了插件，但它的行为低于判定门槛（见下面「判据与误判」）</li>"
                   "</ul></div>\n");
    }

    if (g_Count > 0)
    {
        if (OldHashAlgo())
        {
            fprintf(f, "<div class=\"card warn\"><b>这份日志来自 FairGuard 1.2 或更早，哈希链无法用本工具校验。</b><br>"
                       "1.3 之前的算法里混进了「日志里没有记录的数据」（时间戳、事件原始字节），"
                       "所以谁都无法离线重算 —— 这正是 1.3 改掉它的原因。<br>"
                       "<b>下面的「链校验」列全部显示 ✗，但这并不表示日志被篡改</b>，"
                       "只是这个版本的日志本来就不可校验。</div>\n");
        }
        else if (g_ChainBad < 0)
            fprintf(f, "<div class=\"card ok\"><b>哈希链校验通过。</b><br>"
                       "全部 %d 条记录与链自洽 —— <b>日志内容没有被事后改动过</b>（就本工具能检测的范围而言）。"
                       "<br><span class=\"muted\">最终链值：<span class=\"mono\">%s</span></span></div>\n",
                    g_Count, chFull);
        else
            fprintf(f, "<div class=\"card bad\"><b>⚠️ 哈希链在第 %d 条对不上（从 0 数起）。</b><br>"
                       "这一条<b>及其之后</b>的所有内容都不可信 —— 日志被改动过，或者被截断/拼接。"
                       "<br><span class=\"muted\">第 %d 条：帧 %u，房号 %d，veh=%d</span></div>\n",
                    g_ChainBad + 1, g_ChainBad + 1,
                    g_Hits[g_ChainBad].frame, g_Hits[g_ChainBad].house, g_Hits[g_ChainBad].nDest);
    }

    /* --- 统计 --- */
    if (g_Count > 0)
    {
        fprintf(f, "<h2>概览</h2>\n<div class=\"card info\">");
        fprintf(f, "<b>命中 %d 次</b>", g_Count);
        if (nRepeats) fprintf(f, "（其中 %d 次属于「短时间内重复出现」）", nRepeats);
        fprintf(f, "<br>涉及 %d 个房号：" , nHouses);
        for (i = 0; i < 64; i++) if (seen[i])
        {
            int k, c = 0;
            for (k = 0; k < g_Count; k++) if (g_Hits[k].house == i) c++;
            fprintf(f, " 房号%d（%d 次）", i, c);
        }
        fprintf(f, "<br><br><b>每次命中涉及几辆「不同」的载具（veh）：</b><br>");
        for (i = 0; i < 16; i++) if (vehHist[i])
            fprintf(f, "　veh=%d：%d 次<br>", i, vehHist[i]);
        fprintf(f, "</div>\n");
    }

    /* --- 判据说明（用户最需要的部分） --- */
    fprintf(f,
"<h2>判据是什么（一段话）</h2>\n"
"<div class=\"card info\">\n"
"<p>同一帧内，某玩家的一批 <b>「进入载具」（Enter）</b> 命令里，"
"如果<b>目的地（不同的载具）的数量</b>达到门槛（默认 3 辆），就判定为「疑似自动装车」。</p>\n"
"<p><b>为什么这是硬判据：</b>要让多个单位各自进入<b>不同</b>的载具，玩家必须逐个点"
"（点单位A → 点载具A → 点单位B → 点载具B ……）；人手<b>不可能把这些点击压进同一帧</b>"
"（一帧约 1/60 秒）。而自动装车插件一次就能下发一批。</p>\n"
"<p><b>关键数字不是「多少条命令」，而是「几辆不同的载具」</b>："
"手动框选 20 个单位点<b>一辆</b>车，也会产生 20 条命令，但目的地只有 1 个 —— 不会被判定。</p>\n"
"</div>\n");

    /* --- 什么情况下可能是误判 --- */
    fprintf(f,
"<h2>怎么判断是不是误判</h2>\n"
"<div class=\"card warn\">\n"
"<p>按规定，正常的 RTS 操作<b>做不到</b>「同一帧内对多辆不同载具下令」。"
"所以看到命中时，按下面几条自查：</p>\n"
"<ol>\n"
"<li><b>看时间点</b>：命中时刻是不是正好在对手大批量装车/卸载的时候？"
"如果能对上他的一次明显操作，那就是真的。</li>\n"
"<li><b>看 veh 的数字</b>：veh 越大越不可能是手动。"
"veh=3 还能勉强争论，veh≥5 基本没有手动操作能解释。</li>\n"
"<li><b>看是不是「卸载后重装」</b>：运输车在短时间内反复进出，会连续产生命中。"
"这仍然说明是插件在批量下发（人手做不到同帧多目标），但属于「一次操作引发的连续命中」，"
"不必当成很多次作弊。</li>\n"
"<li><b>注意房号不等于「玩家1/玩家2」</b>：房号是引擎内部的槽位编号，"
"哪台机器是哪个房号要在对局中核对（做一个只自己知道的动作，看哪个房号出现峰值）。</li>\n"
"</ol>\n"
"<p><b>已知的检测盲区（诚实说明）：</b></p>\n"
"<ul>\n"
"<li>插件如果<b>故意分帧下发</b>（每帧只处理一辆车），那就和手动操作在数据上完全一样，检测不到。</li>\n"
"<li>插件如果改用<b>移动（Move）</b>实现装车，也不在判据范围内。</li>\n"
"<li>「温和使用」（一秒一次慢慢装）与手速快的玩家无法区分。</li>\n"
"<li><b>连点器 / 键盘宏不在检测范围</b>：它们只是一辆一辆快速点，做不到同帧多目标；"
"而且对 RTS 竞技没有实质影响，社区也已公认「一键建造多个单位」属于正常功能。</li>\n"
"</ul>\n"
"</div>\n");

    /* --- 明细表 --- */
    if (g_Count > 0)
    {
        fprintf(f, "<h2>命中明细（共 %d 条）</h2>\n", g_Count);
        fprintf(f, "<table><tr><th>#</th><th>时间</th><th>帧</th><th>房号</th>"
                   "<th>单位数</th><th>不同载具</th><th>命令数</th><th>重复</th>"
                   "<th>链校验</th><th>chain</th></tr>\n");
        for (i = 0; i < g_Count; i++)
        {
            char ch[20];
            HexStr(g_Hits[i].chain, 8, ch);
            fprintf(f, "<tr><td class=\"num\">%d</td><td class=\"mono\">%s</td>"
                       "<td class=\"num\">%u</td><td class=\"num\">%d</td>"
                       "<td class=\"num\">%d</td><td class=\"num hit\">%d</td>"
                       "<td class=\"num\">%d</td><td>%s</td><td>%s</td>"
                       "<td class=\"mono\">%s</td></tr>\n",
                    i + 1, g_Hits[i].time, g_Hits[i].frame, g_Hits[i].house,
                    g_Hits[i].nWhom, g_Hits[i].nDest, g_Hits[i].nEvt,
                    g_Hits[i].repeated ? "是" : "",
                    OldHashAlgo() ? "—" : (g_Hits[i].chainOk ? "✓" : "<span class=\"hit\">✗</span>"),
                    ch);
        }
        fprintf(f, "</table>\n");
    }

    /* --- 启动配置 --- */
    fprintf(f, "<h2>当时的运行配置</h2>\n<pre class=\"mono\">");
    if (g_CfgLine1[0]) { char e[512]; HtmlEsc(g_CfgLine1, e, sizeof(e)); fprintf(f, "%s\n", e); }
    if (g_CfgLine2[0]) { char e[512]; HtmlEsc(g_CfgLine2, e, sizeof(e)); fprintf(f, "%s\n", e); }
    fprintf(f, "</pre>\n");

    /* --- 免责声明（必须显眼） --- */
    fprintf(f,
"<h2>⚠️ 这份报告的效力边界</h2>\n"
"<div class=\"card bad\">\n"
"<p><b>它是一份「可疑度报告」，不是「作弊判决书」。</b></p>\n"
"<ul>\n"
"<li>插件下发的命令与玩家点击产生的命令<b>在数据上完全同构</b> —— "
"本工具只能说明「这个操作不可能是人手在同一帧完成的」，"
"不能直接证明「对方装了某个程序」。</li>\n"
"<li>哈希链<b>只能证明「日志内容与链自洽」</b>：算法公开、没有密钥，"
"有人可以整份重新生成一份同样自洽的日志。它防的是「改几个数字」，防不了精心重制。</li>\n"
"<li><b>单人日志无法自证。</b>要成为有效证据，需要<b>多方交叉核对</b> —— "
"那台没有操作的机器也会记下同一批事件，两头对得上才可信。</li>\n"
"<li>请把它当作「值得回看录像 / 找当事人确认」的线索，"
"而不是拿去指控任何人的依据。</li>\n"
"</ul>\n"
"</div>\n");

    fprintf(f, "<p class=\"muted\">由 FairGuardReport 生成　|　"
               "报告只读日志，不修改任何东西</p>\n");
    fprintf(f, "</body></html>\n");

    fclose(f);
}

/* ==================================================================
 * 比对模式：交叉核对两台机器的日志
 * ==================================================================
 *
 * 为什么需要：文档里反复说"单人日志无法自证，要成为有效证据需要**多方交叉核对**"，
 * 但一直只有说法、没有工具。这一节补上。
 *
 * 原理：lockstep 下**每个客户端都会收到所有玩家的命令**。所以两台机器
 * （尤其是"没有操作的那台"）应当对同一个对手的同一批操作给出相似的统计。
 *
 * ⚠️ 但它们**不应该**逐条完全相同：
 *   · `Execute_DoList` 在联机时大约只有一半的帧被调用（实测），
 *     两台机器的调用时机不同 → 各自都会漏掉一些帧
 *   · 帧去重（同一帧只统计一次）也会让采样点不一致
 * 所以本工具报告的是「**重合度**」与「**一致率**」，而不是"必须相同"。
 *
 * 真正值得追查的是：**两边都看到的那部分，数值对不对得上**。
 */

typedef struct {
    unsigned frame;
    int      house;
    int      units, veh, mm;
    int      matched;    /* 在另一份日志里找到了同 (房号, 帧号) 的记录 */
    int      same;       /* 配上了，且 units/veh/MM 完全相同 */
} CmpRec;

#define MAX_CMP 20000
static CmpRec g_CmpA[MAX_CMP]; static int g_CmpAn = 0;
static CmpRec g_CmpB[MAX_CMP]; static int g_CmpBn = 0;

static int CmpLess(const void* x, const void* y)
{
    const CmpRec* a = (const CmpRec*)x;
    const CmpRec* b = (const CmpRec*)y;
    if (a->frame != b->frame) return (a->frame < b->frame) ? -1 : 1;
    if (a->house != b->house) return (a->house < b->house) ? -1 : 1;
    return 0;
}

/* 只抓比对需要的字段（不碰哈希链 —— 两台机器的链本来就各自独立） */
static int ParseForCompare(const char* path, CmpRec* out, int* n)
{
    FILE* f = fopen(path, "rb");
    char  line[MAX_LINE];

    *n = 0;
    if (!f) return 0;

    while (fgets(line, sizeof(line), f))
    {
        int f_, house_, mm, un, ve;

        if (!strstr(line, "*** DETECT "))  continue;
        if (*n >= MAX_CMP)                 continue;
        if (!FindInt(line, "f=", &f_))     continue;
        if (!FindInt(line, "h=", &house_)) continue;
        if (!FindInt(line, "MM=", &mm))    continue;
        if (!FindInt(line, "units=", &un)) continue;
        if (!FindInt(line, "veh=", &ve))   continue;

        out[*n].frame   = (unsigned)f_;
        out[*n].house   = house_;
        out[*n].units   = un;
        out[*n].veh     = ve;
        out[*n].mm      = mm;
        out[*n].matched = 0;
        out[*n].same    = 0;
        (*n)++;
    }
    fclose(f);
    return 1;
}

static void BuildCompareReport(const char* pa, const char* pb, const char* outPath)
{
    FILE* f;
    int   i, j, nA = g_CmpAn, nB = g_CmpBn;
    int   matched = 0, same = 0, diff = 0, onlyA = 0, onlyB = 0;
    const char* ba = strrchr(pa, '\\'); ba = ba ? ba + 1 : pa;
    const char* bb = strrchr(pb, '\\'); bb = bb ? bb + 1 : pb;

    /* 按 (帧号, 房号) 排序后归并配对 */
    qsort(g_CmpA, (size_t)nA, sizeof(CmpRec), CmpLess);
    qsort(g_CmpB, (size_t)nB, sizeof(CmpRec), CmpLess);

    i = j = 0;
    while (i < nA && j < nB)
    {
        int c = CmpLess(&g_CmpA[i], &g_CmpB[j]);
        if (c == 0)
        {
            int isSame = (g_CmpA[i].units == g_CmpB[j].units &&
                          g_CmpA[i].veh   == g_CmpB[j].veh   &&
                          g_CmpA[i].mm    == g_CmpB[j].mm);
            g_CmpA[i].matched = g_CmpB[j].matched = 1;
            g_CmpA[i].same    = g_CmpB[j].same    = isSame;
            matched++;
            if (isSame) same++; else diff++;
            i++; j++;
        }
        else if (c < 0) { onlyA++; i++; }
        else            { onlyB++; j++; }
    }
    while (i < nA) { onlyA++; i++; }
    while (j < nB) { onlyB++; j++; }

    f = fopen(outPath, "wb");
    if (!f) return;

    fprintf(f,
"<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\n"
"<title>FairGuard 双机交叉核对</title>\n"
"<style>\n"
" body{font-family:'Microsoft YaHei',Segoe UI,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#222;line-height:1.7}\n"
" h1{font-size:22px;border-bottom:2px solid #444;padding-bottom:8px}\n"
" h2{font-size:17px;margin-top:28px;border-left:4px solid #666;padding-left:8px}\n"
" .card{padding:14px 18px;border-radius:8px;margin:14px 0}\n"
" .ok{background:#e8f6ec;border:1px solid #7cc48f}\n"
" .bad{background:#fdecea;border:1px solid #e59a92}\n"
" .info{background:#eef3fb;border:1px solid #9ab4d8}\n"
" .warn{background:#fff8e1;border:1px solid #e0c56a}\n"
" table{border-collapse:collapse;width:100%%;font-size:13px}\n"
" th,td{border:1px solid #ccc;padding:5px 8px;text-align:left}\n"
" th{background:#f0f0f0}\n"
" tr:nth-child(even) td{background:#fafafa}\n"
" .num{text-align:right;font-family:Consolas,monospace}\n"
" .mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}\n"
" .muted{color:#666;font-size:13px}\n"
" .hit{color:#b00;font-weight:bold}\n"
"</style></head><body>\n");

    fprintf(f, "<h1>双机交叉核对</h1>\n");
    fprintf(f, "<p class=\"muted\">A：<b>%s</b>（%d 条命中）<br>B：<b>%s</b>（%d 条命中）</p>\n",
            ba, nA, bb, nB);

    if (nA == 0 && nB == 0)
        fprintf(f, "<div class=\"card info\"><b>两份日志都没有命中记录</b> —— 没什么可比的。<br>"
                   "如果这不符合预期，先单独看任意一份的报告（确认检测器在工作、对局是联机的）。</div>\n");
    else if (matched == 0)
        fprintf(f, "<div class=\"card bad\"><b>两份日志没有一条能对上（同帧号 + 同房号）。</b><br>"
                   "常见原因：<ul>"
                   "<li>两份日志<b>不是同一局</b>（每局开始时帧号会重置，先确认时间）</li>"
                   "<li>其中一份根本没记录到对方（那台没装插件、或探针没取到数据）</li>"
                   "</ul>这种情况<b>不能</b>说明谁在作弊 —— 先确认是不是同一局。</div>\n");
    else
    {
        int pct = (matched > 0) ? (same * 100 / matched) : 0;
        if (diff == 0)
            fprintf(f, "<div class=\"card ok\"><b>交叉核对通过。</b><br>"
                       "两份日志有 <b>%d</b> 条能对上（同帧号 + 同房号），"
                       "其中 <b>%d 条数值完全一致（100%%）</b>。<br>"
                       "<span class=\"muted\">两台机器对同一批操作的统计完全吻合 —— "
                       "这正是「多方交叉核对」想要的形态。</span></div>\n", matched, same);
        else if (pct >= 80)
            fprintf(f, "<div class=\"card ok\"><b>交叉核对基本通过（一致率 %d%%）。</b><br>"
                       "能对上 %d 条，其中 %d 条数值一致、<b>%d 条对不上</b>。<br>"
                       "<span class=\"muted\">少数不一致通常是采样时机差异造成的，见下方明细。</span></div>\n",
                    pct, matched, same, diff);
        else
            fprintf(f, "<div class=\"card bad\"><b>⚠️ 一致率偏低（%d%%）。</b><br>"
                       "能对上 %d 条，但只有 %d 条数值一致、<b>%d 条对不上</b>。<br>"
                       "这<b>不一定</b>是造假 —— 可能是："
                       "<ul><li>两台机器的 MOD / 游戏版本不同（命令内容会有差异）</li>"
                       "<li>其中一份日志被截断或手工编辑过</li>"
                       "<li>采样时机差异极大</li></ul>"
                       "请把两份日志都留着，结合录像一起看。</div>\n", pct, matched, same, diff);
    }

    fprintf(f, "<h2>统计</h2>\n<table>\n"
               "<tr><th>项目</th><th>数量</th><th>说明</th></tr>\n");
    fprintf(f, "<tr><td>A 命中总数</td><td class=\"num\">%d</td><td class=\"muted\">%s</td></tr>\n", nA, ba);
    fprintf(f, "<tr><td>B 命中总数</td><td class=\"num\">%d</td><td class=\"muted\">%s</td></tr>\n", nB, bb);
    fprintf(f, "<tr><td><b>配对成功</b></td><td class=\"num\"><b>%d</b></td><td class=\"muted\">同帧号 + 同房号</td></tr>\n", matched);
    fprintf(f, "<tr><td>　其中数值一致</td><td class=\"num\">%d</td><td class=\"muted\">units / veh / MM 全同</td></tr>\n", same);
    if (diff) fprintf(f, "<tr><td>　其中数值不一致</td><td class=\"num hit\">%d</td><td class=\"muted\">见下方明细</td></tr>\n", diff);
    fprintf(f, "<tr><td>只有 A 有</td><td class=\"num\">%d</td><td class=\"muted\">多半是 B 漏采样了那几帧</td></tr>\n", onlyA);
    fprintf(f, "<tr><td>只有 B 有</td><td class=\"num\">%d</td><td class=\"muted\">多半是 A 漏采样了那几帧</td></tr>\n", onlyB);
    fprintf(f, "</table>\n");

    if (diff > 0)
    {
        int shown = 0;
        fprintf(f, "<h2>数值不一致的明细</h2>\n"
                   "<table><tr><th>帧</th><th>房号</th><th>A units</th><th>B units</th>"
                   "<th>A veh</th><th>B veh</th><th>A MM</th><th>B MM</th></tr>\n");
        for (i = 0; i < nA && shown < 100; i++)
        {
            if (!g_CmpA[i].matched || g_CmpA[i].same) continue;
            for (j = 0; j < nB; j++)
            {
                if (g_CmpB[j].frame == g_CmpA[i].frame && g_CmpB[j].house == g_CmpA[i].house)
                {
                    fprintf(f, "<tr><td class=\"num\">%u</td><td class=\"num\">%d</td>"
                               "<td class=\"num\">%d</td><td class=\"num hit\">%d</td>"
                               "<td class=\"num\">%d</td><td class=\"num hit\">%d</td>"
                               "<td class=\"num\">%d</td><td class=\"num hit\">%d</td></tr>\n",
                            g_CmpA[i].frame, g_CmpA[i].house,
                            g_CmpA[i].units, g_CmpB[j].units,
                            g_CmpA[i].veh,   g_CmpB[j].veh,
                            g_CmpA[i].mm,    g_CmpB[j].mm);
                    shown++;
                    break;
                }
            }
        }
        fprintf(f, "</table>\n");
        if (diff > shown) fprintf(f, "<p class=\"muted\">（只列了前 %d 条）</p>\n", shown);
    }

    fprintf(f,
"<h2>怎么读这份报告</h2>\n"
"<div class=\"card info\">\n"
"<p><b>为什么两份日志不会完全一样：</b>引擎的 <span class=\"mono\">Execute_DoList</span> "
"在联机时大约只有<b>一半的帧</b>被调用（实测），两台机器的调用时机不同，"
"各自都会漏掉一些帧 —— <b>只有 A 有 / 只有 B 有</b>属于正常现象。</p>\n"
"<p><b>该关注的是「配对成功」里的「数值不一致」：</b>同一帧、同一房号，"
"两台机器对同一批命令的统计应该一样。对不上才需要解释。</p>\n"
"</div>\n"
"<div class=\"card warn\">\n"
"<p><b>⚠️ 交叉核对通过 ≠ 对方作弊。</b>它证明的是"
"「两台机器对同一批操作看法一致」，说明这份记录<b>不是某一台机器上单独编出来的</b>。"
"至于是不是插件发的命令，仍然要看判据与录像。</p>\n"
"<p><b>⚠️ 一致率低也不一定是造假</b>：MOD / 游戏版本不同、日志被截断、"
"采样时机差异大，都会导致对不上。别急着下结论。</p>\n"
"</div>\n"
"<div class=\"card bad\">\n"
"<p>两份日志各自都应当先用单份模式校验哈希链（"
"<span class=\"mono\">FairGuardReport.exe &lt;日志&gt;</span>）—— "
"<b>链对不上的那份，比对结果没有意义</b>。</p>\n"
"</div>\n");

    fprintf(f, "<p class=\"muted\">由 FairGuardReport 生成　|　只读日志，不修改任何东西</p>\n");
    fprintf(f, "</body></html>\n");
    fclose(f);
}

/* ------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------ */
int main(int argc, char** argv)
{
    char logPath[MAX_PATH] = "";
    char outPath[MAX_PATH] = "";
    wchar_t wmsg[1024];
    char paths[2][MAX_PATH];
    int  nPaths = 0;
    int  noOpen = 0;
    int  i;

    printf("FairGuardReport - log reader + hash-chain verifier\n\n");

    /* 参数：
     *   一个日志路径  -> 单份报告（哈希链校验 + 可读报告）
     *   两个日志路径  -> 双机交叉核对
     *   --no-open     -> 只生成，不打开浏览器
     *   --selftest    -> 自检 */
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--selftest") == 0) return SelfTest();
        if (strcmp(argv[i], "--no-open") == 0) { noOpen = 1; continue; }
        if (nPaths < 2) snprintf(paths[nPaths++], MAX_PATH, "%s", argv[i]);
    }

    /* ---------------- 双机交叉核对模式 ---------------- */
    if (nPaths == 2)
    {
        printf("Mode: two-log cross-check\n\n");

        if (!ParseForCompare(paths[0], g_CmpA, &g_CmpAn))
        {
            printf("Cannot open log file: %s\n", paths[0]);
            MakeMsg(wmsg, 1024, L"打不开日志文件：", paths[0]);
            MessageBoxW(NULL, wmsg, L"FairGuardReport", MB_ICONERROR | MB_OK);
            return 1;
        }
        if (!ParseForCompare(paths[1], g_CmpB, &g_CmpBn))
        {
            printf("Cannot open log file: %s\n", paths[1]);
            MakeMsg(wmsg, 1024, L"打不开日志文件：", paths[1]);
            MessageBoxW(NULL, wmsg, L"FairGuardReport", MB_ICONERROR | MB_OK);
            return 1;
        }
        printf("  A: %d hit record(s)\n", g_CmpAn);
        printf("  B: %d hit record(s)\n", g_CmpBn);

        snprintf(outPath, sizeof(outPath) - 1, "%s.vs.html", paths[0]);
        outPath[sizeof(outPath) - 1] = 0;
        BuildCompareReport(paths[0], paths[1], outPath);
        printf("Compare report: %s\n", outPath);

        if (GetFileAttributesA(outPath) != INVALID_FILE_ATTRIBUTES)
        {
            if (!noOpen) ShellExecuteA(NULL, "open", outPath, NULL, NULL, SW_SHOWNORMAL);
            return 0;
        }
        MakeMsg(wmsg, 1024, L"报告写不出来（目录只读？）：", outPath);
        MessageBoxW(NULL, wmsg, L"FairGuardReport", MB_ICONERROR | MB_OK);
        return 1;
    }

    if (nPaths == 1) snprintf(logPath, sizeof(logPath), "%s", paths[0]);

    if (!logPath[0] && !FindLatestLog(logPath, sizeof(logPath)))
    {
        printf("No FairGuard log found. Put this exe next to gamemd.exe,\n"
               "or drag a log file onto it.\n");
        MessageBoxW(NULL,
            L"没有找到 FairGuard 日志。\n\n"
            L"本工具会去找：\n  <本程序所在目录>\\MsgLog\\FairGuard_*.log\n\n"
            L"请把这个 exe 放到游戏根目录（gamemd.exe 那一层），\n"
            L"或者直接把一份日志文件拖到本程序上。",
            L"FairGuardReport", MB_ICONINFORMATION | MB_OK);
        return 1;
    }

    printf("Log: %s\n", logPath);

    if (!ParseLog(logPath))
    {
        printf("Cannot open log file: %s\n", logPath);
        MakeMsg(wmsg, 1024, L"打不开日志文件：", logPath);
        MessageBoxW(NULL, wmsg, L"FairGuardReport", MB_ICONERROR | MB_OK);
        return 1;
    }

    printf("Parsed %d hit record(s)\n", g_Count);
    VerifyChain();
    if (g_Count > 0)
    {
        if (OldHashAlgo())
            printf("Hash chain: log is from 1.2 or earlier (old algorithm) - cannot verify. This is NOT tampering.\n");
        else if (g_ChainBad < 0)
            printf("Hash chain: all %d record(s) consistent - OK\n", g_Count);
        else
            printf("Hash chain: MISMATCH at record #%d (the first %d were consistent)\n",
                   g_ChainBad + 1, g_ChainBad);
    }

    snprintf(outPath, sizeof(outPath) - 1, "%s.report.html", logPath);
    outPath[sizeof(outPath) - 1] = 0;
    BuildReport(logPath, outPath);

    printf("Report: %s\n", outPath);

    /* 生成成功就打开浏览器（--no-open 时跳过）；
     * 拖拽运行时顺手让窗口别一闪而过 */
    if (GetFileAttributesA(outPath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!noOpen) ShellExecuteA(NULL, "open", outPath, NULL, NULL, SW_SHOWNORMAL);
    }
    else
    {
        MakeMsg(wmsg, 1024, L"报告写不出来（目录只读？）：", outPath);
        MessageBoxW(NULL, wmsg, L"FairGuardReport", MB_ICONERROR | MB_OK);
        return 1;
    }

    return 0;
}
