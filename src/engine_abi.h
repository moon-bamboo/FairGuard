/*
 * engine_abi.h —— 借用引擎的 MessageListClass::AddMessage 做屏幕提示
 *
 * ============================ 为什么走这条路 ============================
 *
 * 检测到可疑操作时要让玩家【当场】看见，否则等打完一局翻日志就没意义了。
 *
 * MessageListClass::AddMessage @ 0x005D3BA0 是游戏里【所有】文本消息的唯一
 * 入口（玩家聊天、结盟提示、快捷键提示、超武提示全走它）。往它里面塞一条
 * 我们自己的消息，就等于让引擎替我们显示 —— 不用自己画。
 *
 * 对比 ChatBox 的做法（接管绘制）为什么更稳：
 *   1) 不占绘制钩点。ChatBox 已经钩了 0x4F4558 / 0x5D4A94，我们再钩必冲突；
 *      而调用 AddMessage 与 ChatBox 天然共存 —— 装了 ChatBox 时它会捕获
 *      我们这条消息并显示在它自己的消息窗里。
 *   2) 颜色、字体、折行全由引擎处理，不会画歪。
 *   3) 这是纯本地 UI 消息，不进事件队列，不影响 lockstep 同步。
 *
 * ============================ 调用约定（关键） ============================
 *
 * YRpp/MessageListClass.h:30 + objdump 实测：
 *
 *     TextLabelClass* __thiscall AddMessage(
 *         const wchar_t* Name, int ID, const wchar_t* Message,
 *         int ColorSchemeIdx, TextPrintType Style, int Timeout, bool SinglePlayer)
 *
 *   - ECX = this = MessageListClass::Instance = 0x00A8BC60
 *     （YRpp: DEFINE_REFERENCE(MessageListClass, Instance, 0xA8BC60u)，
 *       反汇编 0x5D4A94 / 0x4F4558 处都是 `mov $0xa8bc60,%ecx`）
 *   - 7 个参数全部走栈
 *   - 函数结尾 `ret $0x1C`（= 7*4）=> 被调方清栈
 *   - 首指令 81 EC 4C 01 00 00 = sub $0x14c,%esp（6 字节）
 *
 * GCC 没有 __thiscall 关键字可用（对普通函数的支持不可靠），
 * 所以用 __fastcall 表达：前两个形参走 ECX/EDX，其余走栈、被调方清栈。
 * 于是把签名写成
 *
 *     (this_  [ECX], edxUnused  [EDX 占位], 再 7 个栈参数)
 *
 * 栈上正好 7 个参数 —— 与引擎的 `ret $0x1C` 严丝合缝。
 * （ChatBox 用同一手法表达 FillRectTrans / Fancy_Text_Print_Wide，已实测。）
 *
 * ⚠️ 这个 typedef 由 test/test_abi.c 用"模拟引擎函数"验证过：
 *    它用一个真正的 __thiscall 函数接收，逐个核对 this/7 个参数的位置。
 *    改动这里必须重跑那个测试 —— 约定错了游戏会当场崩。
 */

#ifndef FAIRGUARD_ENGINE_ABI_H
#define FAIRGUARD_ENGINE_ABI_H

/* MessageListClass::AddMessage */
#define ADDR_ADD_MESSAGE          0x005D3BA0u

/* MessageListClass::Instance（就是 AddMessage 的 this） */
#define ADDR_MESSAGELIST_INSTANCE 0x00A8BC60u

/* 原版所有消息用的 style（实测值，与 ChatBox 的 TEXT_FLAGS 一致） */
#define MSG_STYLE                 0x4046

/* 颜色方案索引：7 = 实测日志里"快捷键提示"那一类用的浅色方案
 * （见 ChatBox/开发记录.md 的消息分类表），够显眼又不刺眼 */
#define MSG_COLOR_SCHEME          7

typedef void* (__fastcall *AddMessageFn)(
    void* this_, void* edxUnused,
    const wchar_t* name, int id, const wchar_t* message,
    int colorSchemeIdx, int style, int timeout, int silent);

#endif /* FAIRGUARD_ENGINE_ABI_H */
