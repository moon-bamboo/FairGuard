/*
 * test_abi.c —— 验证「借用引擎 AddMessage 显示屏幕提示」的调用约定
 *
 * ============================ 为什么必须单独测这个 ============================
 *
 * 检测器要在屏幕上弹一句警告，走的是引擎自己的消息通道
 * MessageListClass::AddMessage（地址 0x005D3BA0）。那是个 __thiscall 函数：
 *
 *     ECX = this，7 个参数全部走栈，函数结尾 ret $0x1C（被调方清栈）
 *
 * GCC 没有可靠的 __thiscall 关键字，我们改用 __fastcall 来表达
 * （见 src/engine_abi.h）。这一步【只要错一点点】的后果是：
 *
 *   - 参数错位      -> 引擎拿垃圾指针去打印 -> 当场崩
 *   - 栈清错字节数  -> 每调一次栈就歪一点 -> 过一会儿崩
 *
 * 而这两种错误在"只编译不运行"的阶段完全看不出来，等实机联机崩了就
 * 白白浪费用户一整轮测试。所以在这里用一个【按 __thiscall 定义的模拟函数】
 * 接收调用，逐个核对 this 与 7 个参数落在哪里。
 *
 * 这个测试不碰游戏、不碰引擎内存，就是一次纯 ABI 演练。
 *
 * 编译运行:
 *   gcc -O2 -Wall -o test_abi.exe test_abi.c
 *   test_abi.exe          正常输出 failures: 0
 */

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "../src/engine_abi.h"

static int g_fail = 0;
static int g_pass = 0;
static int g_calls = 0;

/* 模拟函数实际收到的参数（诊断用） */
static unsigned g_seenThis, g_seenName, g_seenId, g_seenMessage;
static unsigned g_seenCs, g_seenStyle, g_seenTimeout, g_seenSilent;

static void check(const char* what, int cond)
{
    if (cond) { g_pass++; printf("[PASS] %s\n", what); }
    else      { g_fail++; printf("[FAIL] %s\n", what); }
}

/* 期望值 */
#define WANT_THIS    ((void*)(unsigned)ADDR_MESSAGELIST_INSTANCE)
#define WANT_ID      12345
#define WANT_CS      MSG_COLOR_SCHEME
#define WANT_STYLE   MSG_STYLE
#define WANT_TIMEOUT 600
#define WANT_SILENT  1

static const wchar_t* g_wantMessage = L"engine-side message pointer";

/*
 * 模拟引擎那一侧的 AddMessage。
 *
 * 刻意用 GCC 的 thiscall 属性声明，让编译器【自己】按 __thiscall 生成
 * 取参与清栈代码 —— 这样测的就是真实的调用约定，而不是我手写的假设。
 *
 * 第 1 个形参 this_ 走 ECX，其余 7 个走栈；函数由被调方清 0x1C 字节。
 * 返回 0 表示"所有参数都落在正确的位置"。
 *
 * ⚠️ noinline 是必须的：O2 下 GCC 若把调用点直接内联，"调用约定"就被
 *    编译器顺手抹平了，测试会变成恒真（或者得出莫名其妙的结论）。
 *    真实插件里目标是引擎的固定地址，编译器不可能内联，所以这里也不该内联。
 */
static int __attribute__((thiscall, noinline)) FakeAddMessage(
    void*          this_,
    const wchar_t* name,
    int            id,
    const wchar_t* message,
    int            colorSchemeIdx,
    int            style,
    int            timeout,
    int            silent)
{
    g_calls++;

    /* 记下实际收到的值，失败时打印出来 —— 错位的方式能直接指出是
     * "压栈顺序反了"还是"寄存器没传对" */
    g_seenThis    = (unsigned)(size_t)this_;
    g_seenName    = (unsigned)(size_t)name;
    g_seenId      = (unsigned)id;
    g_seenMessage = (unsigned)(size_t)message;
    g_seenCs      = (unsigned)colorSchemeIdx;
    g_seenStyle   = (unsigned)style;
    g_seenTimeout = (unsigned)timeout;
    g_seenSilent  = (unsigned)silent;

    if (this_ != WANT_THIS)                  return 10;
    if (name != NULL)                        return 11;   /* 我们传 nullptr */
    if (id != WANT_ID)                       return 12;
    if (message != g_wantMessage)            return 13;
    if (colorSchemeIdx != WANT_CS)           return 14;
    if (style != WANT_STYLE)                 return 15;
    if (timeout != WANT_TIMEOUT)             return 16;
    if (silent != WANT_SILENT)               return 17;
    return 0;
}

/* 用与 FairGuard.c 完全相同的方式发起调用。
 *
 * 函数指针经 volatile 全局变量取出，避免 GCC 把"已知目标"的间接调用
 * 去虚拟化/内联掉（真实插件里目标是一个引擎地址常量，同样不可内联）。 */
static AddMessageFn volatile g_fnPtr = (AddMessageFn)(void*)FakeAddMessage;

static int CallLikeProbe(int idOverride)
{
    AddMessageFn fn = g_fnPtr;
    void* ret;

    ret = fn(WANT_THIS, NULL,               /* ECX = this, EDX = 占位 */
             NULL, idOverride, g_wantMessage,
             WANT_CS, WANT_STYLE, WANT_TIMEOUT, WANT_SILENT);

    return (int)(long)(size_t)ret;
}

static void DumpSeen(void)
{
    printf("       engine side received:\n");
    printf("         this_    = %08X   (want %08X)\n", g_seenThis,    (unsigned)(size_t)WANT_THIS);
    printf("         name     = %08X   (want 00000000)\n", g_seenName);
    printf("         id       = %08X   (want %08X)\n", g_seenId,      WANT_ID);
    printf("         message  = %08X   (want %08X)\n", g_seenMessage, (unsigned)(size_t)g_wantMessage);
    printf("         cs       = %08X   (want %08X)\n", g_seenCs,      WANT_CS);
    printf("         style    = %08X   (want %08X)\n", g_seenStyle,   WANT_STYLE);
    printf("         timeout  = %08X   (want %08X)\n", g_seenTimeout, WANT_TIMEOUT);
    printf("         silent   = %08X   (want %08X)\n", g_seenSilent,  WANT_SILENT);
}

int main(void)
{
    int i, r;

    printf("== AddMessage ABI test (__thiscall vs __fastcall) ==\n\n");

    /* 1) 参数位置全部正确 */
    r = CallLikeProbe(WANT_ID);
    if (r != 0)
    {
        printf("       FakeAddMessage returned %d (10=this, 11=name, 12=id, 13=message,\n"
               "       14=colorscheme, 15=style, 16=timeout, 17=silent)\n", r);
        DumpSeen();
    }
    check("this/7 stack args all land correctly", r == 0);
    check("mock function was actually called",    g_calls == 1);

    /* 2) 负向测试：故意传错 id，必须被检出
     *    （否则说明这个测试恒真，等于没测） */
    g_calls = 0;
    r = CallLikeProbe(WANT_ID + 1);
    check("negative check: wrong id is detected", r == 12 && g_calls == 1);

    /* 3) 栈平衡：连续调用 20000 次。
     *    如果 __fastcall(调用侧) 与 __thiscall(被调侧) 对"谁清栈、清多少"
     *    的理解不一致，每调一次栈指针就偏 4~8 字节，很快就会崩或者返回乱码。 */
    g_calls = 0;
    for (i = 0; i < 20000; i++)
    {
        r = CallLikeProbe(WANT_ID);
        if (r != 0) break;
    }
    check("20000 consecutive calls stay stack-balanced", i == 20000 && r == 0);
    check("20000 calls all reached the mock",            g_calls == 20000);

    printf("\n----------------------------------------\n");
    printf("passed: %d   failures: %d\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
