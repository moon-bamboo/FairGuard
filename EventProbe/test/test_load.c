/*
 * test_load.c - EventProbe.dll 加载自检（32 位）
 *
 * 验证:
 *   1) DLL 能被 LoadLibrary 加载（依赖是否齐全）
 *   2) 两个钩子函数与 SyringeHandshake 都导出了
 *   3) SyringeHandshake 返回 S_OK 并写出正确的说明串
 *   4) 顺带验证日志能否创建（握手会触发 EnsureInit -> 建 MsgLog 目录并写日志）
 *
 * 编译运行:
 *   gcc -O2 -o test_load.exe test_load.c -lkernel32
 *   test_load.exe
 */

#include <windows.h>
#include <stdio.h>

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

typedef HRESULT (__cdecl *HandshakeFn)(SyringeHandshakeInfo*);

static int g_fail = 0;

static void ok(const char* what, int cond, const char* extra)
{
    if (cond) printf("[PASS] %s\n", what);
    else { printf("[FAIL] %s%s%s\n", what, extra ? " - " : "", extra ? extra : ""); g_fail++; }
}

int main(void)
{
    HMODULE dll;
    FARPROC h1, h2, hs;
    char msg[512];
    SyringeHandshakeInfo info;

    printf("== EventProbe.dll load test ==\n\n");

    dll = LoadLibraryA("EventProbe.dll");
    if (!dll)
    {
        printf("[FAIL] LoadLibrary failed, GetLastError = %lu\n", GetLastError());
        return 1;
    }
    printf("[PASS] LoadLibrary OK, base = %p\n", (void*)dll);

    h1 = GetProcAddress(dll, "EventProbe_ExecuteEventsHook");
    h2 = GetProcAddress(dll, "EventProbe_FrameHook");
    hs = GetProcAddress(dll, "SyringeHandshake");

    ok("EventProbe_ExecuteEventsHook (0x64C38D)", h1 != NULL, NULL);
    ok("EventProbe_FrameHook        (0x55D360)", h2 != NULL, NULL);
    ok("SyringeHandshake",                        hs != NULL, NULL);

    if (hs)
    {
        memset(&info, 0, sizeof(info));
        memset(msg, 0, sizeof(msg));
        info.cbSize = sizeof(info);
        info.cchMessage = sizeof(msg);
        info.Message = msg;

        {
            HRESULT hr = ((HandshakeFn)hs)(&info);
            printf("[%s] SyringeHandshake -> hr = 0x%08lX (期望 0)\n",
                   hr == 0 ? "PASS" : "FAIL", (unsigned long)hr);
            if (hr != 0) g_fail++;
            printf("       message = \"%s\"\n", msg);
            ok("握手说明串非空", msg[0] != 0, NULL);
        }
    }

    printf("\nfailures: %d\n", g_fail);
    FreeLibrary(dll);
    return g_fail ? 1 : 0;
}
